import { z } from 'zod';
import type { Config } from '../config/env.js';
import type { TenantContext } from '../config/types.js';
import type { Database } from '../db/pool.js';
import { transaction } from '../db/pool.js';
import { executeReservedOperation, identifyRefund, withProviderReference } from '../operations/execute.js';
import { completeOperation, getResourceOwner, reserveOperation } from '../operations/repository.js';
import type { Operation } from '../operations/types.js';
import { AppError } from '../security/errors.js';
import type { JsonObject } from '../security/json.js';
import type { XenditClient } from '../xendit/client.js';

export const refundSchema = z.strictObject({
  payment_request_id: z.string().min(1).max(255),
  payment_id: z.string().min(1).max(255),
  amount: z.number().finite().positive()
    .max(999_999_999_999_999_999, 'amount exceeds numeric(24,6) range')
    .refine((value) => /^\d+(?:\.\d{1,6})?$/.test(value.toString()),
      'amount supports at most 6 decimal places'),
  currency: z.string().length(3),
  reason: z.enum(['FRAUDULENT', 'DUPLICATE', 'REQUESTED_BY_CUSTOMER', 'CANCELLATION', 'OTHERS']),
  metadata: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).optional(),
});

export async function createRefund(
  db: Database,
  config: Config,
  xendit: XenditClient,
  context: TenantContext,
  idempotencyKey: string,
  body: JsonObject,
): Promise<Operation> {
  const paymentRequestId = body['payment_request_id'] as string;
  const paymentId = body['payment_id'] as string;
  const reserved = await reserveOperation(db, {
    tenantId: context.tenantId,
    tenantCode: context.tenantCode,
    environment: config.APP_ENV,
    kind: 'REFUND_CREATE',
    idempotencyKey,
    requestBody: body,
    clientReference: paymentRequestId,
  });
  if (!reserved.created) return reserved.operation;
  if (!reserved.operation.providerReference) return reserved.operation;

  try {
    if (await getResourceOwner(db, config.APP_ENV, 'payment_request', paymentRequestId) !== context.tenantId) {
      throw new AppError(404, 'NOT_FOUND', 'Payment request not found');
    }
    if (await getResourceOwner(db, config.APP_ENV, 'payment', paymentId) !== context.tenantId) {
      throw new AppError(404, 'NOT_FOUND', 'Payment not found');
    }
    await reserveRefundAmount(db, {
      operationId: reserved.operation.id,
      tenantId: context.tenantId,
      environment: config.APP_ENV,
      paymentRequestId,
      paymentId,
      amount: body['amount'] as number,
      currency: body['currency'] as string,
      reason: body['reason'] as string,
    });
  } catch (error) {
    await completeOperation(db, {
      operationId: reserved.operation.id,
      environment: config.APP_ENV,
      tenantId: context.tenantId,
      status: 'FAILED',
      errorCode: error instanceof AppError ? error.code : 'REFUND_VALIDATION_FAILED',
      errorDetail: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }

  const refundRequest = { ...body };
  delete refundRequest['payment_id'];
  const providerBody = withProviderReference(refundRequest, reserved.operation.providerReference);
  return executeReservedOperation(
    db,
    reserved.operation,
    () => xendit.createRefund(providerBody),
    identifyRefund,
    (response) => response.body['payment_id'] === paymentId &&
      response.body['payment_request_id'] === paymentRequestId
      ? undefined
      : {
        code: 'REFUND_TARGET_MISMATCH',
        detail: 'Provider refund response omitted or mismatched payment identity',
      },
    async (client, operation) => {
      const providerTargetMatches = operation.errorCode !== 'REFUND_TARGET_MISMATCH';
      await client.query(
        `UPDATE refunds SET status = CASE
           WHEN status IN ('SUCCEEDED', 'FAILED') THEN status
           WHEN $2 = false THEN 'UNKNOWN'
           WHEN $3 = 'SUCCEEDED' THEN 'PENDING'
           WHEN $3 = 'FAILED' THEN 'FAILED'
           WHEN $3 = 'UNKNOWN' THEN 'UNKNOWN'
           ELSE status END,
           provider_refund_id = COALESCE(provider_refund_id, $4), updated_at = now()
         WHERE operation_id = $1`,
        [operation.id, providerTargetMatches, operation.status, operation.providerResourceId],
      );
    },
  );
}

async function reserveRefundAmount(
  db: Database,
  input: {
    operationId: string;
    tenantId: string;
    environment: 'test' | 'live';
    paymentRequestId: string;
    paymentId: string;
    amount: number;
    currency: string;
    reason: string;
  },
): Promise<void> {
  await transaction(db, async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
      `${input.environment}:refund-payment:${input.paymentId}`,
    ]);
    const canonicalPaymentId = input.paymentId;
    const request = await client.query<{ type: string | null }>(
      `SELECT o.request_body->>'type' AS type
         FROM resource_mappings m JOIN operations o ON o.id = m.operation_id
        WHERE m.environment = $1 AND m.resource_type = 'payment_request'
          AND m.resource_id = $2 AND m.tenant_id = $3
          AND o.kind = 'PAYMENT_REQUEST_CREATE' AND o.status = 'SUCCEEDED'`,
      [input.environment, input.paymentRequestId, input.tenantId],
    );
    if (request.rows[0]?.type !== 'PAY') {
      throw new AppError(409, 'REFUND_TARGET_UNVERIFIED', 'Refund requires a gateway-created one-off PAY request');
    }
    const payments = await client.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM resource_mappings
        WHERE environment = $1 AND resource_type = 'payment'
          AND parent_resource_type = 'payment_request' AND parent_resource_id = $2`,
      [input.environment, input.paymentRequestId],
    );
    if (payments.rows[0]?.count !== '1') {
      throw new AppError(409, 'REFUND_TARGET_AMBIGUOUS', 'Payment request has multiple captured payments');
    }
    const payment = await client.query<{ amount: string; currency: string; payment_request_id: string | null }>(
      `SELECT amount, currency, payment_request_id FROM payment_amounts
        WHERE environment = $1 AND payment_id = $2 AND tenant_id = $3`,
      [input.environment, input.paymentId, input.tenantId],
    );
    const row = payment.rows[0];
    if (!row || row.payment_request_id !== input.paymentRequestId) {
      throw new AppError(409, 'PAYMENT_DATA_UNAVAILABLE', 'Captured payment amount is unavailable or mismatched');
    }
    const currency = row.currency;
    const amount = input.amount;
    const requestedCurrency = input.currency;
    if (!Number.isFinite(amount) || amount <= 0 || requestedCurrency !== currency) {
      throw new AppError(409, 'INVALID_REFUND_AMOUNT', 'Refund amount or currency exceeds captured payment');
    }

    const tenantLimit = await client.query<{ exceeds: boolean }>(
      `SELECT max_refund_amount IS NOT NULL AND $2::numeric > max_refund_amount AS exceeds
         FROM tenants WHERE id = $1 FOR UPDATE`,
      [input.tenantId, amount.toString()],
    );
    if (tenantLimit.rows[0]?.exceeds) {
      throw new AppError(403, 'REFUND_LIMIT_EXCEEDED', 'Refund exceeds tenant limit');
    }

    const ceiling = await client.query<{ exceeds: boolean }>(
      `SELECT COALESCE(sum(r.amount), 0) + $3::numeric > $4::numeric AS exceeds
         FROM refunds r
        WHERE r.environment = $1 AND r.payment_id = $2
          AND r.status IN ('RESERVED', 'PENDING', 'SUCCEEDED', 'UNKNOWN')`,
      [input.environment, canonicalPaymentId, amount.toString(), row.amount],
    );
    if (ceiling.rows[0]?.exceeds) {
      throw new AppError(409, 'REFUND_CEILING_EXCEEDED', 'Cumulative refunds exceed captured payment');
    }

    await client.query(
      `INSERT INTO refunds (
         operation_id, tenant_id, environment, payment_id, payment_request_id,
         amount, currency, status, reason
       ) VALUES ($1,$2,$3,$4,$5,$6::numeric,$7,'RESERVED',$8)`,
      [
        input.operationId,
        input.tenantId,
        input.environment,
        canonicalPaymentId,
        input.paymentRequestId,
        amount.toString(),
        currency,
        input.reason,
      ],
    );
  });
}
