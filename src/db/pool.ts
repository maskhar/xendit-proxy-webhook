import pg from 'pg';
import type { Config } from '../config/env.js';

const { Pool } = pg;

export type Database = pg.Pool;
export type DbClient = pg.PoolClient;

export function createDatabase(config: Config): Database {
  return new Pool({
    connectionString: config.DATABASE_URL,
    max: config.DATABASE_MAX_CONNECTIONS,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    application_name: `xendit-proxy-${config.APP_ENV}`,
  });
}

export async function transaction<T>(db: Database, work: (client: DbClient) => Promise<T>): Promise<T> {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL statement_timeout = '15s'");
    await client.query("SET LOCAL lock_timeout = '3s'");
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
