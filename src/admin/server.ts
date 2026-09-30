import Fastify, { type FastifyInstance } from 'fastify';
import type { Config } from '../config/env.js';
import type { Database } from '../db/pool.js';
import { loggerOptions } from '../security/logger.js';
import { registerAdminRoutes } from './routes.js';

export async function buildAdminServer(config: Config, db: Database): Promise<FastifyInstance> {
  const app = Fastify({
    logger: loggerOptions(config.LOG_LEVEL),
    bodyLimit: config.API_BODY_LIMIT_BYTES,
    trustProxy: false,
  });
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_request, body, done) => {
    done(null, body);
  });
  registerAdminRoutes(app, db, config);
  return app;
}
