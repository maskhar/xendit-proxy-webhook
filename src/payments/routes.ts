import type { FastifyInstance } from 'fastify';
import type { Config } from '../config/env.js';
import { authenticateTenant, requireScope } from '../security/api-keys.js';
import { AppError } from '../security/errors.js';
import { asJsonObject, getString, type JsonObject } from '../security/json.js';
import { parseJsonBody, requireIdempotencyKey, requirePathId } from '../http.js';
import type { Database } from '../db/pool.js';
import { executeReservedOperation, identifyPaymentRequest, identifyPaymentSession, operationHttpStatus, publicOperation, withProviderReference } from '../operations/execute.js';
import { getOperation, getResourceOwner, reserveOperation } from '../operations/repository.js';
import { assertProviderSuccess, type XenditClient } from '../xendit/client.js';
import { enforceTenantPolicy, loadTenantPolicy, paymentRequestSchema, paymentSessionSchema } from './policy.js';

export function registerPaymentRoutes(
  app: FastifyInstance,
  db: Database,
  config: Config,
  xendit: XenditClient,
): void {
  app.post('/v1/payment-requests', async (request, reply) => {
    const context = await authenticateTenant(db, config.APP_ENV, request);
    requireScope(context, 'payment:create');
    const input = paymentRequestSchema.parse(parseJsonBody(request)) as JsonObject;
    enforceTenantPolicy(input, await loadTenantPolicy(db, context.tenantId));
    const key = requireIdempotencyKey(request);
    const clientReference = getString(input, 'reference_id');
    const reserved = await reserveOperation(db, {
      tenantId: context.tenantId,
      tenantCode: context.tenantCode,
      environment: config.APP_ENV,
      kind: 'PAYMENT_REQUEST_CREATE',
      idempotencyKey: key,
      requestBody: input,
      ...(clientReference ? { clientReference } : {}),
    });
    const operation = reserved.operation.status === 'RESERVED' && reserved.operation.providerReference
      ? await executeReservedOperation(
        db,
        reserved.operation,
        () => xendit.createPaymentRequest(withProviderReference(input, reserved.operation.providerReference as string)),
        identifyPaymentRequest,
      )
      : reserved.operation;
    return reply.code(operationHttpStatus(operation)).send(publicOperation(operation));
  });

  app.post('/v1/payment-sessions', async (request, reply) => {
    const context = await authenticateTenant(db, config.APP_ENV, request);
    requireScope(context, 'session:create');
    const input = paymentSessionSchema.parse(parseJsonBody(request)) as JsonObject;
    enforceTenantPolicy(input, await loadTenantPolicy(db, context.tenantId));
    const key = requireIdempotencyKey(request);
    const clientReference = getString(input, 'reference_id');
    const reserved = await reserveOperation(db, {
      tenantId: context.tenantId,
      tenantCode: context.tenantCode,
      environment: config.APP_ENV,
      kind: 'PAYMENT_SESSION_CREATE',
      idempotencyKey: key,
      requestBody: input,
      ...(clientReference ? { clientReference } : {}),
    });
    const operation = reserved.operation.status === 'RESERVED' && reserved.operation.providerReference
      ? await executeReservedOperation(
        db,
        reserved.operation,
        () => xendit.createPaymentSession(withProviderReference(input, reserved.operation.providerReference as string)),
        identifyPaymentSession,
      )
      : reserved.operation;
    return reply.code(operationHttpStatus(operation)).send(publicOperation(operation));
  });

  app.get<{ Params: { id: string } }>('/v1/payment-requests/:id', async (request) => {
    const context = await authenticateTenant(db, config.APP_ENV, request);
    requireScope(context, 'payment:read');
    const id = requirePathId(request.params.id, 'payment request ID');
    if (await getResourceOwner(db, config.APP_ENV, 'payment_request', id) !== context.tenantId) {
      throw new AppError(404, 'NOT_FOUND', 'Payment request not found');
    }
    const response = await xendit.getPaymentRequest(id);
    assertProviderSuccess(response);
    assertBusiness(response.body, config.XENDIT_BUSINESS_ID);
    return response.body;
  });

  app.get<{ Params: { id: string } }>('/v1/payment-sessions/:id', async (request) => {
    const context = await authenticateTenant(db, config.APP_ENV, request);
    requireScope(context, 'session:read');
    const id = requirePathId(request.params.id, 'payment session ID');
    if (await getResourceOwner(db, config.APP_ENV, 'payment_session', id) !== context.tenantId) {
      throw new AppError(404, 'NOT_FOUND', 'Payment session not found');
    }
    const response = await xendit.getPaymentSession(id);
    assertProviderSuccess(response);
    assertBusiness(response.body, config.XENDIT_BUSINESS_ID);
    return response.body;
  });

  app.post<{ Params: { id: string } }>('/v1/payment-requests/:id/cancel', async (request, reply) => {
    const context = await authenticateTenant(db, config.APP_ENV, request);
    requireScope(context, 'payment:cancel');
    const id = requirePathId(request.params.id, 'payment request ID');
    if (await getResourceOwner(db, config.APP_ENV, 'payment_request', id) !== context.tenantId) {
      throw new AppError(404, 'NOT_FOUND', 'Payment request not found');
    }
    const key = requireIdempotencyKey(request);
    const input = { payment_request_id: id };
    const reserved = await reserveOperation(db, {
      tenantId: context.tenantId,
      tenantCode: context.tenantCode,
      environment: config.APP_ENV,
      kind: 'PAYMENT_REQUEST_CANCEL',
      idempotencyKey: key,
      requestBody: input,
      reserveReference: false,
    });
    const operation = reserved.operation.status === 'RESERVED'
      ? await executeReservedOperation(db, reserved.operation, () => xendit.cancelPaymentRequest(id), () => ({}))
      : reserved.operation;
    return reply.code(operationHttpStatus(operation)).send(publicOperation(operation));
  });

  app.get<{ Params: { id: string } }>('/v1/operations/:id', async (request) => {
    const context = await authenticateTenant(db, config.APP_ENV, request);
    const id = requirePathId(request.params.id, 'operation ID');
    const operation = await getOperation(db, context.tenantId, config.APP_ENV, id);
    if (!operation) throw new AppError(404, 'NOT_FOUND', 'Operation not found');
    const scope = operation.kind === 'REFUND_CREATE' ? 'refund:read'
      : operation.kind === 'PAYMENT_SESSION_CREATE' ? 'session:read'
      : 'payment:read';
    requireScope(context, scope);
    return publicOperation(operation);
  });
}

function assertBusiness(body: unknown, expectedBusinessId: string): void {
  const data = asJsonObject(body);
  const businessId = getString(data, 'business_id');
  if (businessId && businessId !== expectedBusinessId) {
    throw new AppError(502, 'BUSINESS_MISMATCH', 'Provider response business ID mismatch');
  }
}
