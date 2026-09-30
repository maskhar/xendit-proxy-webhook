import type { FastifyInstance } from 'fastify';
import type { Config } from '../config/env.js';
import type { Database } from '../db/pool.js';
import { AppError } from '../security/errors.js';
import { ingestWebhook, verifyWebhookToken } from './ingest.js';

const ingressPaths = ['payments', 'sessions', 'invoices', 'refunds', 'legacy'] as const;

export function registerWebhookRoutes(app: FastifyInstance, db: Database, config: Config): void {
  for (const ingressPath of ingressPaths) {
    app.post(`/webhooks/${ingressPath}`, async (request, reply) => {
      verifyWebhookToken(
        config,
        typeof request.headers['x-callback-token'] === 'string'
          ? request.headers['x-callback-token']
          : undefined,
      );
      if (!Buffer.isBuffer(request.body)) {
        throw new AppError(400, 'RAW_BODY_REQUIRED', 'Webhook raw body is unavailable');
      }
      const result = await ingestWebhook(db, config, request.body, ingressPath);
      return reply.code(202).send({
        accepted: true,
        event_id: result.eventId,
        duplicate: result.duplicate,
        route_status: result.status,
      });
    });
  }
}
