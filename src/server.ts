import Fastify, { type FastifyInstance } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { ZodError } from 'zod';
import { loadConfig, type Config } from './config/env.js';
import { createDatabase, type Database } from './db/pool.js';
import { registerPaymentRoutes } from './payments/routes.js';
import { registerRefundRoutes } from './refunds/routes.js';
import { AppError } from './security/errors.js';
import { loggerOptions } from './security/logger.js';
import { registerWebhookRoutes } from './webhooks/routes.js';
import { XenditClient } from './xendit/client.js';

export async function buildServer(config: Config, db: Database): Promise<FastifyInstance> {
  const app = Fastify({
    logger: loggerOptions(config.LOG_LEVEL),
    bodyLimit: Math.max(config.WEBHOOK_BODY_LIMIT_BYTES, config.API_BODY_LIMIT_BYTES),
    trustProxy: false,
  });
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_request, body, done) => {
    done(null, body);
  });
  await app.register(rateLimit, { max: 120, timeWindow: '1 minute' });

  app.get('/healthz', () => ({ status: 'ok' }));
  app.get('/readyz', async (_request, reply) => {
    try {
      await db.query('SELECT 1');
      const migration = await db.query<{ count: string }>('SELECT count(*)::text AS count FROM schema_migrations');
      if (Number(migration.rows[0]?.count ?? 0) < 1) throw new Error('Database migrations missing');
      const heartbeat = await db.query<{ ready: boolean }>(
        `SELECT EXISTS (
           SELECT 1 FROM worker_heartbeats
            WHERE environment = $1 AND last_seen_at > now() - interval '2 minutes'
         ) AS ready`,
        [config.APP_ENV],
      );
      if (!heartbeat.rows[0]?.ready) throw new Error('Delivery worker heartbeat missing');
      return { status: 'ready', environment: config.APP_ENV };
    } catch {
      return reply.code(503).send({ status: 'not_ready' });
    }
  });

  const xendit = new XenditClient(config);
  registerPaymentRoutes(app, db, config, xendit);
  registerRefundRoutes(app, db, config, xendit);
  registerWebhookRoutes(app, db, config);

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof ZodError) {
      return reply.code(400).send({ error: { code: 'VALIDATION_ERROR', message: 'Request validation failed', issues: error.issues } });
    }
    if (error instanceof AppError) {
      return reply.code(error.statusCode).send({ error: { code: error.code, message: error.message, detail: error.detail } });
    }
    app.log.error({ err: error }, 'Unhandled request error');
    return reply.code(500).send({ error: { code: 'INTERNAL_ERROR', message: 'Internal server error' } });
  });
  return app;
}

async function main(): Promise<void> {
  const config = loadConfig();
  const db = createDatabase(config);
  const publicServer = await buildServer(config, db);
  const { buildAdminServer } = await import('./admin/server.js');
  const adminServer = await buildAdminServer(config, db);
  let stopping = false;
  const stop = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    publicServer.log.info({ signal }, 'Stopping servers');
    await Promise.allSettled([publicServer.close(), adminServer.close()]);
    await db.end();
  };
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => void stop(signal));
  }
  await Promise.all([
    publicServer.listen({ host: config.HOST, port: config.PORT }),
    adminServer.listen({ host: config.ADMIN_HOST, port: config.ADMIN_PORT }),
  ]);
}

if (process.argv[1]?.endsWith('/server.js') || process.argv[1]?.endsWith('\\server.js') || process.argv[1]?.endsWith('/server.ts') || process.argv[1]?.endsWith('\\server.ts')) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  });
}
