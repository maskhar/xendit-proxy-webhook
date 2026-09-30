import { randomUUID } from 'node:crypto';
import type { Config } from '../config/env.js';
import type { Database } from '../db/pool.js';
import { decrypt, type EncryptedValue } from '../security/crypto.js';
import { errorMessage } from '../security/errors.js';
import { sendWebhook } from './http.js';

type DeliveryRow = {
  id: string;
  webhook_event_id: string;
  destination_id: string;
  tenant_id: string;
  raw_body: Buffer;
  event_type: string;
  url: string;
  callback_token_ciphertext: Buffer;
  callback_token_nonce: Buffer;
  callback_token_tag: Buffer;
  extra_headers_ciphertext: Buffer | null;
  extra_headers_nonce: Buffer | null;
  extra_headers_tag: Buffer | null;
  max_attempts: number;
  attempt_count: number;
  replay_start_attempt: number;
};

export class DeliveryWorker {
  readonly #db: Database;
  readonly #config: Config;
  readonly #workerId = randomUUID();
  #running = false;

  constructor(db: Database, config: Config) {
    this.#db = db;
    this.#config = config;
  }

  async run(signal: AbortSignal): Promise<void> {
    this.#running = true;
    try {
      while (!signal.aborted) {
        await this.#heartbeat();
        const jobs = await this.claim();
        if (jobs.length === 0) {
          await new Promise<void>((resolve) => {
            const timer = setTimeout(resolve, this.#config.DELIVERY_POLL_MS);
            signal.addEventListener('abort', () => {
              clearTimeout(timer);
              resolve();
            }, { once: true });
          });
          continue;
        }
        for (const job of jobs) {
          if (signal.aborted) break;
          await this.deliver(job);
        }
      }
    } finally {
      this.#running = false;
    }
  }

  get running(): boolean {
    return this.#running;
  }

  async claim(): Promise<DeliveryRow[]> {
    const client = await this.#db.connect();
    try {
      await client.query('BEGIN');
      const rows = await client.query<DeliveryRow>(
        `WITH eligible AS (
           SELECT d.id FROM deliveries d
             JOIN webhook_events e ON e.id = d.webhook_event_id
             JOIN destinations dest ON dest.id = d.destination_id
            WHERE e.environment = $1
              AND d.attempt_count - d.replay_start_attempt < dest.max_attempts
              AND ((d.status IN ('PENDING', 'RETRY') AND d.next_attempt_at <= now())
                OR (d.status = 'LEASED' AND d.lease_expires_at < now()))
            ORDER BY d.next_attempt_at ASC, d.created_at ASC
            FOR UPDATE OF d SKIP LOCKED LIMIT $2
         ), claimed AS (
           UPDATE deliveries d
              SET status = 'LEASED', lease_owner = $3,
                  lease_expires_at = now() + ($4::int * interval '1 millisecond'),
                  attempt_count = attempt_count + 1,
                  updated_at = now()
             FROM eligible q WHERE d.id = q.id RETURNING d.*
         )
         SELECT c.id, c.webhook_event_id, c.destination_id, c.tenant_id,
                e.raw_body, e.event_type, dest.url, dest.callback_token_ciphertext,
                dest.callback_token_nonce, dest.callback_token_tag,
                dest.extra_headers_ciphertext, dest.extra_headers_nonce,
                dest.extra_headers_tag, dest.max_attempts, c.attempt_count,
                c.replay_start_attempt
           FROM claimed c
           JOIN webhook_events e ON e.id = c.webhook_event_id
           JOIN destinations dest ON dest.id = c.destination_id`,
        [this.#config.APP_ENV, this.#config.DELIVERY_BATCH_SIZE, this.#workerId, this.#config.DELIVERY_LEASE_MS],
      );
      await client.query('COMMIT');
      return rows.rows;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async deliver(job: DeliveryRow): Promise<void> {
    const started = Date.now();
    let httpStatus: number | undefined;
    let responseExcerpt: string | undefined;
    let error: string | undefined;
    try {
      const callbackToken = decrypt(
        {
          ciphertext: job.callback_token_ciphertext,
          nonce: job.callback_token_nonce,
          authTag: job.callback_token_tag,
        },
        this.#config.encryptionKey,
        `destination:${job.tenant_id}:${this.#config.APP_ENV}:callback`,
      ).toString('utf8');
      const headers: Record<string, string> = {
        'x-callback-token': callbackToken,
        'x-proxy-event-id': job.webhook_event_id,
        'x-proxy-delivery-id': job.id,
        'x-proxy-event-type': job.event_type,
      };
      if (job.extra_headers_ciphertext && job.extra_headers_nonce && job.extra_headers_tag) {
        const extra: EncryptedValue = {
          ciphertext: job.extra_headers_ciphertext,
          nonce: job.extra_headers_nonce,
          authTag: job.extra_headers_tag,
        };
        const parsed = JSON.parse(decrypt(
          extra,
          this.#config.encryptionKey,
          `destination:${job.tenant_id}:${this.#config.APP_ENV}:headers`,
        ).toString('utf8')) as unknown;
        if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
          throw new Error('Invalid destination headers');
        }
        for (const [key, value] of Object.entries(parsed)) {
          if (typeof value === 'string' && /^[a-z0-9-]+$/.test(key) &&
              !['authorization', 'host', 'content-type', 'content-length', 'x-callback-token', 'x-proxy-event-id', 'x-proxy-delivery-id'].includes(key)) {
            headers[key] = value;
          } else if (key === 'authorization' && typeof value === 'string') {
            headers['authorization'] = value;
          } else {
            throw new Error('Unsafe destination header');
          }
        }
      }
      const response = await sendWebhook(job.url, job.raw_body, headers, this.#config.DELIVERY_TIMEOUT_MS);
      httpStatus = response.statusCode;
      responseExcerpt = response.responseExcerpt;
    } catch (caught) {
      error = errorMessage(caught).slice(0, 1_000);
    }

    const success = httpStatus !== undefined && httpStatus >= 200 && httpStatus < 300;
    const retryable = httpStatus === undefined || httpStatus >= 500 || httpStatus === 408 || httpStatus === 429;
    const replayAttempt = job.attempt_count - job.replay_start_attempt;
    const exhausted = replayAttempt >= job.max_attempts;
    const status = success ? 'SUCCEEDED' : retryable && !exhausted ? 'RETRY' : 'DEAD';
    const delayMs = Math.min(3_600_000, 2_000 * 2 ** Math.min(replayAttempt - 1, 10));
    const client = await this.#db.connect();
    try {
      await client.query('BEGIN');
      const updated = await client.query(
        `UPDATE deliveries SET status = $3, last_http_status = $4, last_error = $5,
           lease_owner = NULL, lease_expires_at = NULL,
           next_attempt_at = CASE WHEN $3 = 'RETRY' THEN now() + ($6::int * interval '1 millisecond')
                                  ELSE next_attempt_at END,
           completed_at = CASE WHEN $3 IN ('SUCCEEDED', 'DEAD') THEN now() ELSE NULL END,
           updated_at = now()
         WHERE id = $1 AND lease_owner = $2 AND attempt_count = $7`,
        [job.id, this.#workerId, status, httpStatus ?? null, error ?? null, delayMs, job.attempt_count],
      );
      if (updated.rowCount !== 1) throw new Error('Delivery lease was lost before completion');
      await client.query(
        `INSERT INTO delivery_attempts (
          delivery_id, attempt_number, completed_at, http_status, duration_ms, error, response_excerpt
         ) VALUES ($1,$2,now(),$3,$4,$5,$6)`,
        [job.id, job.attempt_count, httpStatus ?? null, Date.now() - started, error ?? null, responseExcerpt ?? null],
      );
      await client.query('COMMIT');
    } catch (caught) {
      await client.query('ROLLBACK');
      throw caught;
    } finally {
      client.release();
    }
  }

  async #heartbeat(): Promise<void> {
    await this.#db.query(
      `INSERT INTO worker_heartbeats (worker_id, environment, last_seen_at)
       VALUES ($1,$2,now()) ON CONFLICT (worker_id)
       DO UPDATE SET last_seen_at = now()`,
      [this.#workerId, this.#config.APP_ENV],
    );
  }
}
