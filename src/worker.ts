import { loadConfig } from './config/env.js';
import { createDatabase } from './db/pool.js';
import { DeliveryWorker } from './deliveries/worker.js';
import { loggerOptions } from './security/logger.js';
import pino from 'pino';

const config = loadConfig();
const logger = pino(loggerOptions(config.LOG_LEVEL));
const db = createDatabase(config);
const controller = new AbortController();
const worker = new DeliveryWorker(db, config);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    logger.info({ signal }, 'Stopping worker');
    controller.abort();
  });
}

worker.run(controller.signal)
  .then(async () => {
    await db.end();
    logger.info('Worker stopped');
  })
  .catch(async (error: unknown) => {
    logger.fatal({ err: error }, 'Worker failed');
    await db.end().catch(() => undefined);
    process.exitCode = 1;
  });
