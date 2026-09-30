import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../config/env.js';
import { createDatabase } from './pool.js';

const migrationsDirectory = resolve(fileURLToPath(new URL('../../migrations', import.meta.url)));

export async function migrate(): Promise<void> {
  const config = loadConfig();
  const db = createDatabase(config);
  const client = await db.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [2_026_093_001]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);
    const files = (await readdir(migrationsDirectory))
      .filter((file) => /^\d+.*\.sql$/.test(file))
      .sort();

    for (const file of files) {
      const applied = await client.query<{ exists: boolean }>(
        'SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1) AS exists',
        [file],
      );
      if (applied.rows[0]?.exists) continue;

      const sql = await readFile(resolve(migrationsDirectory, file), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [file]);
        await client.query('COMMIT');
        process.stdout.write(`Applied ${file}\n`);
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [2_026_093_001]).catch(() => undefined);
    client.release();
    await db.end();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  migrate().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  });
}
