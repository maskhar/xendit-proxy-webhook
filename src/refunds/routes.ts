import type { FastifyInstance } from 'fastify';
import type { Config } from '../config/env.js';
import type { Database } from '../db/pool.js';
import { parseJsonBody, requireIdempotencyKey, requirePathId } from '../http.js';
import { operationHttpStatus, publicOperation } from '../operations/execute.js';
import { authenticateTenant, requireScope } from '../security/api-keys.js';
import { AppError } from '../security/errors.js';
import type { JsonObject } from '../security/json.js';
import type { XenditClient } from '../xendit/client.js';
import { createRefund, refundSchema } from './service.js';

export function registerRefundRoutes(
  app: FastifyInstance,
  db: Database,
  config: Config,
  xendit: XenditClient,
): void {
  app.post('/v1/refunds', async (request, reply) => {
    const context = await authenticateTenant(db, config.APP_ENV, request);
    requireScope(context, 'refund:create');
    const body = refundSchema.parse(parseJsonBody(request)) as JsonObject;
    const operation = await createRefund(
      db,
      config,
      xendit,
      context,
      requireIdempotencyKey(request),
      body,
    );
    return reply.code(operationHttpStatus(operation)).send(publicOperation(operation));
  });

  app.get<{ Params: { id: string } }>('/v1/refunds/:id', async (request) => {
    const context = await authenticateTenant(db, config.APP_ENV, request);
    requireScope(context, 'refund:read');
    const id = requirePathId(request.params.id, 'refund ID');
    const result = await db.query<{
      operation_id: string;
      payment_id: string;
      payment_request_id: string | null;
      provider_refund_id: string | null;
      amount: string;
      currency: string;
      status: string;
      reason: string | null;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT operation_id, payment_id, payment_request_id, provider_refund_id,
              amount::text, currency, status, reason, created_at, updated_at
         FROM refunds
        WHERE tenant_id = $1 AND environment = $2
          AND (id::text = $3 OR provider_refund_id = $3)`,
      [context.tenantId, config.APP_ENV, id],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(404, 'NOT_FOUND', 'Refund not found');
    return row;
  });
}
