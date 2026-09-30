import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { Config } from '../../src/config/env.js';
import { encrypt } from '../../src/security/crypto.js';
import { generateApiKey } from '../../src/security/api-keys.js';
import { XenditClient } from '../../src/xendit/client.js';
import { buildServer } from '../../src/server.js';
import { buildAdminServer } from '../../src/admin/server.js';

const databaseUrl = process.env['TEST_DATABASE_URL'];
const integration = databaseUrl ? describe : describe.skip;

async function createRefundFixture(
  db: pg.Pool,
  tenantId: string,
  paymentRequestId: string,
  paymentId: string,
  amount: string,
): Promise<void> {
  const operation = await db.query<{ id: string }>(
    `INSERT INTO operations (
       tenant_id, environment, kind, idempotency_key, request_hash, request_body, status
     ) VALUES ($1,'test','PAYMENT_REQUEST_CREATE',$2,digest($2,'sha256'),
       '{"type":"PAY"}'::jsonb,'SUCCEEDED') RETURNING id`,
    [tenantId, `fixture-${randomUUID()}`],
  );
  await db.query(
    `INSERT INTO resource_mappings (
       environment, resource_type, resource_id, tenant_id, operation_id, source
     ) VALUES ('test','payment_request',$1,$2,$3,'API_RESPONSE')`,
    [paymentRequestId, tenantId, operation.rows[0]?.id],
  );
  await db.query(
    `INSERT INTO resource_mappings (
       environment, resource_type, resource_id, tenant_id,
       parent_resource_type, parent_resource_id, source
     ) VALUES ('test','payment',$1,$2,'payment_request',$3,'WEBHOOK')`,
    [paymentId, tenantId, paymentRequestId],
  );
  await db.query(
    `INSERT INTO payment_amounts (
       environment, payment_id, tenant_id, payment_request_id, amount, currency, captured_at
     ) VALUES ('test',$1,$2,$3,$4::numeric,'IDR',now())`,
    [paymentId, tenantId, paymentRequestId, amount],
  );
}

integration('gateway integration', () => {
  let db: pg.Pool;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let adminApp: Awaited<ReturnType<typeof buildAdminServer>>;
  let tenantId: string;
  let secondTenantId: string;
  let apiKey: string;
  let secondApiKey: string;
  let config: Config;

  beforeAll(async () => {
    db = new pg.Pool({ connectionString: databaseUrl });
    const tenants = await db.query<{ id: string; slug: string }>(
      `SELECT id, slug FROM tenants WHERE slug IN ('placers','epochstream') ORDER BY slug`,
    );
    const first = tenants.rows.find((row) => row.slug === 'placers');
    const second = tenants.rows.find((row) => row.slug === 'epochstream');
    if (!first || !second) throw new Error('Test tenants missing');
    tenantId = first.id;
    secondTenantId = second.id;
    const generated = generateApiKey('test');
    const generatedSecond = generateApiKey('test');
    apiKey = generated.token;
    secondApiKey = generatedSecond.token;
    await db.query(
      `INSERT INTO tenant_api_keys (tenant_id, environment, label, key_prefix, key_hash, scopes)
       VALUES ($1,'test',$2,$3,$4,$5), ($6,'test',$7,$8,$9,$5)`,
      [tenantId, `test-${randomUUID()}`, generated.prefix, generated.hash,
        ['payment:create', 'payment:read', 'refund:create', 'refund:read', 'session:create', 'session:read'],
        secondTenantId, `test-${randomUUID()}`, generatedSecond.prefix, generatedSecond.hash],
    );
    await db.query(
      `UPDATE tenants SET allowed_channels = ARRAY['DANA']::text[] WHERE id IN ($1,$2)`,
      [tenantId, secondTenantId],
    );
    await db.query(
      `INSERT INTO worker_heartbeats (worker_id, environment, last_seen_at)
       VALUES ($1, 'test', now()) ON CONFLICT (worker_id) DO UPDATE SET last_seen_at = now()`,
      [`test-${randomUUID()}`],
    );
    config = {
      NODE_ENV: 'test', APP_ENV: 'test', HOST: '127.0.0.1', PORT: 0, ADMIN_HOST: '127.0.0.1', ADMIN_PORT: 0,
      DATABASE_URL: databaseUrl as string, DATABASE_MAX_CONNECTIONS: 5,
      XENDIT_API_BASE_URL: 'https://api.xendit.co', ALLOW_INSECURE_XENDIT_BASE_URL: 'false',
      XENDIT_API_VERSION: '2024-11-11',
      XENDIT_BUSINESS_ID: 'business-test', XENDIT_API_KEY_FILE: '/dev/null',
      XENDIT_CALLBACK_TOKEN_FILE: '/dev/null', ENCRYPTION_KEY_FILE: '/dev/null',
      ADMIN_TOKEN_FILE: '/dev/null', PROVIDER_TIMEOUT_MS: 10_000, WEBHOOK_BODY_LIMIT_BYTES: 1_048_576,
      API_BODY_LIMIT_BYTES: 262_144, DELIVERY_BATCH_SIZE: 20, DELIVERY_POLL_MS: 100,
      DELIVERY_LEASE_MS: 60_000, DELIVERY_TIMEOUT_MS: 1_000, LOG_LEVEL: 'silent',
      xenditApiKey: 'test-key', xenditCallbackTokens: ['provider-callback-secret'],
      encryptionKey: Buffer.alloc(32, 4), adminToken: 'admin-secret',
    };
    app = await buildServer(config, db);
    adminApp = await buildAdminServer(config, db);
  });

  afterAll(async () => {
    await adminApp?.close();
    await app?.close();
    await db?.end();
  });

  it('reserves reference before POST, reuses idempotent operation, isolates tenants', async () => {
    let calls = 0;
    const originalDescriptor = Object.getOwnPropertyDescriptor(XenditClient.prototype, 'createPaymentRequest');
    XenditClient.prototype.createPaymentRequest = async (body) => {
      calls += 1;
      const reference = body['reference_id'];
      const route = await db.query<{ tenant_id: string }>(
        'SELECT tenant_id FROM reference_routes WHERE environment = $1 AND reference_value = $2',
        ['test', reference],
      );
      expect(route.rows[0]?.tenant_id).toBe(tenantId);
      return {
        statusCode: 201,
        body: { payment_request_id: `pr-test-${randomUUID()}`, reference_id: reference as string, status: 'PENDING' },
      };
    };
    try {
      const body = { reference_id: `client-${randomUUID()}`, type: 'PAY', country: 'ID', currency: 'IDR', request_amount: 10_000, channel_code: 'DANA' };
      const headers = { authorization: `Bearer ${apiKey}`, 'idempotency-key': randomUUID() };
      const [first, second] = await Promise.all([
        app.inject({ method: 'POST', url: '/v1/payment-requests', headers, payload: body }),
        app.inject({ method: 'POST', url: '/v1/payment-requests', headers, payload: body }),
      ]);
      expect([first.statusCode, second.statusCode].sort()).toEqual([201, 202]);
      expect(calls).toBe(1);
      const firstBody = first.json<{ operation_id: string; resource_id?: string }>();
      expect(second.json<{ operation_id: string }>().operation_id).toBe(firstBody.operation_id);
      const settled = await app.inject({
        method: 'GET', url: `/v1/operations/${firstBody.operation_id}`,
        headers: { authorization: `Bearer ${apiKey}` },
      });
      expect(settled.json<{ status: string }>().status).toBe('SUCCEEDED');
      const foreign = await app.inject({
        method: 'GET', url: `/v1/operations/${firstBody.operation_id}`,
        headers: { authorization: `Bearer ${secondApiKey}` },
      });
      expect(foreign.statusCode).toBe(404);
    } finally {
      if (originalDescriptor) Object.defineProperty(XenditClient.prototype, 'createPaymentRequest', originalDescriptor);
    }
  });

  it('marks uncertain provider outcomes without retrying upstream', async () => {
    let calls = 0;
    const originalDescriptor = Object.getOwnPropertyDescriptor(XenditClient.prototype, 'createPaymentRequest');
    XenditClient.prototype.createPaymentRequest = () => {
      calls += 1;
      return Promise.resolve({ statusCode: 503, body: { error_code: 'TEMPORARY_ERROR', message: 'Provider unavailable' } });
    };
    try {
      const body = {
        reference_id: `unknown-${randomUUID()}`, type: 'PAY', country: 'ID', currency: 'IDR',
        request_amount: 10_000, channel_code: 'DANA',
      };
      const headers = { authorization: `Bearer ${apiKey}`, 'idempotency-key': randomUUID() };
      const first = await app.inject({ method: 'POST', url: '/v1/payment-requests', headers, payload: body });
      const second = await app.inject({ method: 'POST', url: '/v1/payment-requests', headers, payload: body });
      expect(first.statusCode).toBe(202);
      expect(second.statusCode).toBe(202);
      expect(first.json<{ status: string }>().status).toBe('UNKNOWN');
      expect(second.json<{ operation_id: string }>().operation_id)
        .toBe(first.json<{ operation_id: string }>().operation_id);
      expect(calls).toBe(1);
    } finally {
      if (originalDescriptor) Object.defineProperty(XenditClient.prototype, 'createPaymentRequest', originalDescriptor);
    }
  });

  it('preserves destination state when rotating only its callback token', async () => {
    const destination = await db.query<{ id: string }>(
      `SELECT id FROM destinations WHERE tenant_id = $1 AND environment = 'test'`,
      [tenantId],
    );
    const destinationId = destination.rows[0]?.id;
    if (!destinationId) throw new Error('Test destination missing');
    const encrypted = encrypt('old-callback-token', config.encryptionKey, `destination:${tenantId}:test:callback`);
    await db.query(
      `UPDATE destinations SET enabled = true, max_attempts = 7,
         callback_token_ciphertext = $2, callback_token_nonce = $3, callback_token_tag = $4
       WHERE id = $1`,
      [destinationId, encrypted.ciphertext, encrypted.nonce, encrypted.authTag],
    );

    const response = await adminApp.inject({
      method: 'PUT',
      url: `/admin/tenants/${tenantId}/destination`,
      headers: { authorization: `Bearer ${config.adminToken}` },
      payload: {
        url: 'https://api.placers.id/xendit/webhook',
        callback_token: 'rotated-callback-token',
      },
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json<{ destination: { enabled: boolean; max_attempts: number } }>().destination)
      .toMatchObject({ enabled: true, max_attempts: 7 });
  });

  it('creates a protected refund and reuses the idempotent result', async () => {
    const paymentRequestId = `pr-refund-${randomUUID()}`;
    const paymentId = `py-refund-${randomUUID()}`;
    const providerRefundId = `rf-${randomUUID()}`;
    await createRefundFixture(db, tenantId, paymentRequestId, paymentId, '10000.50');

    let calls = 0;
    let providerBody: Record<string, unknown> | undefined;
    const originalDescriptor = Object.getOwnPropertyDescriptor(XenditClient.prototype, 'createRefund');
    XenditClient.prototype.createRefund = (body) => {
      calls += 1;
      providerBody = body;
      return Promise.resolve({
        statusCode: 201,
        body: {
          id: providerRefundId,
          payment_id: paymentId,
          payment_request_id: paymentRequestId,
          status: 'PENDING',
        },
      });
    };
    try {
      const key = `refund-${randomUUID()}`;
      const body = {
        payment_request_id: paymentRequestId,
        payment_id: paymentId,
        amount: 5000.25,
        currency: 'IDR',
        reason: 'REQUESTED_BY_CUSTOMER',
      };
      const headers = { authorization: `Bearer ${apiKey}`, 'idempotency-key': key };
      const first = await app.inject({ method: 'POST', url: '/v1/refunds', headers, payload: body });
      const second = await app.inject({ method: 'POST', url: '/v1/refunds', headers, payload: body });
      expect(first.statusCode, first.body).toBe(201);
      expect(second.statusCode, second.body).toBe(201);
      expect(calls).toBe(1);
      expect(providerBody).toMatchObject({ payment_request_id: paymentRequestId, amount: 5000.25 });
      expect(providerBody).not.toHaveProperty('payment_id');
      expect(providerBody?.['reference_id']).toMatch(/^xpg_plc_[a-f0-9]{32}$/);

      const operation = first.json<{ operation_id: string; status: string }>();
      expect(operation.status).toBe('SUCCEEDED');
      expect(second.json<{ operation_id: string }>().operation_id).toBe(operation.operation_id);
      const refund = await db.query<{ status: string; amount: string; provider_refund_id: string }>(
        `SELECT status, amount::text, provider_refund_id FROM refunds WHERE operation_id = $1`,
        [operation.operation_id],
      );
      expect(refund.rows[0]).toMatchObject({ status: 'PENDING', amount: '5000.250000', provider_refund_id: providerRefundId });
      const read = await app.inject({
        method: 'GET', url: `/v1/refunds/${providerRefundId}`,
        headers: { authorization: `Bearer ${apiKey}` },
      });
      expect(read.statusCode, read.body).toBe(200);
      const foreign = await app.inject({
        method: 'GET', url: `/v1/refunds/${providerRefundId}`,
        headers: { authorization: `Bearer ${secondApiKey}` },
      });
      expect(foreign.statusCode).toBe(404);
    } finally {
      if (originalDescriptor) Object.defineProperty(XenditClient.prototype, 'createRefund', originalDescriptor);
    }
  });

  it('blocks ambiguous refunds and rejects cumulative decimal overflow', async () => {
    const ambiguousRequestId = `pr-ambiguous-${randomUUID()}`;
    const ambiguousPaymentId = `py-ambiguous-${randomUUID()}`;
    await createRefundFixture(db, tenantId, ambiguousRequestId, ambiguousPaymentId, '10000');
    await db.query(
      `INSERT INTO resource_mappings (
         environment, resource_type, resource_id, tenant_id,
         parent_resource_type, parent_resource_id, source
       ) VALUES ('test','payment',$1,$2,'payment_request',$3,'WEBHOOK')`,
      [`py-ambiguous-${randomUUID()}`, tenantId, ambiguousRequestId],
    );
    const ambiguous = await app.inject({
      method: 'POST', url: '/v1/refunds',
      headers: { authorization: `Bearer ${apiKey}`, 'idempotency-key': `refund-${randomUUID()}` },
      payload: {
        payment_request_id: ambiguousRequestId, payment_id: ambiguousPaymentId,
        amount: 1, currency: 'IDR', reason: 'OTHERS',
      },
    });
    expect(ambiguous.statusCode, ambiguous.body).toBe(409);
    expect(ambiguous.json<{ error: { code: string } }>().error.code).toBe('REFUND_TARGET_AMBIGUOUS');

    const paymentRequestId = `pr-ceiling-${randomUUID()}`;
    const paymentId = `py-ceiling-${randomUUID()}`;
    await createRefundFixture(db, tenantId, paymentRequestId, paymentId, '0.300000');
    const existing = await db.query<{ id: string }>(
      `INSERT INTO operations (
         tenant_id, environment, kind, idempotency_key, request_hash, request_body, status
       ) VALUES ($1,'test','REFUND_CREATE',$2,digest($2,'sha256'),'{}'::jsonb,'SUCCEEDED')
       RETURNING id`,
      [tenantId, `fixture-${randomUUID()}`],
    );
    await db.query(
      `INSERT INTO refunds (
         operation_id, tenant_id, environment, payment_id, payment_request_id,
         amount, currency, status, reason
       ) VALUES ($1,$2,'test',$3,$4,0.200000,'IDR','SUCCEEDED','OTHERS')`,
      [existing.rows[0]?.id, tenantId, paymentId, paymentRequestId],
    );
    const overflow = await app.inject({
      method: 'POST', url: '/v1/refunds',
      headers: { authorization: `Bearer ${apiKey}`, 'idempotency-key': `refund-${randomUUID()}` },
      payload: {
        payment_request_id: paymentRequestId, payment_id: paymentId,
        amount: 0.100001, currency: 'IDR', reason: 'OTHERS',
      },
    });
    expect(overflow.statusCode, overflow.body).toBe(409);
    expect(overflow.json<{ error: { code: string } }>().error.code).toBe('REFUND_CEILING_EXCEEDED');
  });

  it('marks a mismatched refund response UNKNOWN without trusting its resource ID', async () => {
    const paymentRequestId = `pr-mismatch-${randomUUID()}`;
    const paymentId = `py-mismatch-${randomUUID()}`;
    const wrongPaymentId = `py-wrong-${randomUUID()}`;
    const providerRefundId = `rf-mismatch-${randomUUID()}`;
    await createRefundFixture(db, tenantId, paymentRequestId, paymentId, '10000');

    const originalDescriptor = Object.getOwnPropertyDescriptor(XenditClient.prototype, 'createRefund');
    XenditClient.prototype.createRefund = () => Promise.resolve({
      statusCode: 201,
      body: {
        id: providerRefundId, payment_id: wrongPaymentId,
        payment_request_id: paymentRequestId, status: 'PENDING',
      },
    });
    try {
      const response = await app.inject({
        method: 'POST', url: '/v1/refunds',
        headers: { authorization: `Bearer ${apiKey}`, 'idempotency-key': `refund-${randomUUID()}` },
        payload: {
          payment_request_id: paymentRequestId, payment_id: paymentId,
          amount: 1000, currency: 'IDR', reason: 'OTHERS',
        },
      });
      expect(response.statusCode, response.body).toBe(202);
      const operation = response.json<{ operation_id: string; status: string; error_code: string }>();
      expect(operation).toMatchObject({ status: 'UNKNOWN', error_code: 'REFUND_TARGET_MISMATCH' });
      const refund = await db.query<{ status: string; provider_refund_id: string | null }>(
        'SELECT status, provider_refund_id FROM refunds WHERE operation_id = $1', [operation.operation_id],
      );
      expect(refund.rows[0]).toMatchObject({ status: 'UNKNOWN', provider_refund_id: null });
      const mapping = await db.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM resource_mappings
          WHERE environment = 'test' AND resource_type = 'refund' AND resource_id = $1`,
        [providerRefundId],
      );
      expect(mapping.rows[0]?.count).toBe('0');
    } finally {
      if (originalDescriptor) Object.defineProperty(XenditClient.prototype, 'createRefund', originalDescriptor);
    }
  });

  it('does not regress terminal refund status on out-of-order callbacks', async () => {
    const paymentRequestId = `pr-webhook-${randomUUID()}`;
    const paymentId = `py-webhook-${randomUUID()}`;
    const providerRefundId = `rf-webhook-${randomUUID()}`;
    await createRefundFixture(db, tenantId, paymentRequestId, paymentId, '10000');
    const operation = await db.query<{ id: string; provider_reference: string }>(
      `INSERT INTO operations (
         tenant_id, environment, kind, idempotency_key, request_hash, request_body,
         provider_reference, status, provider_resource_type, provider_resource_id
       ) VALUES ($1,'test','REFUND_CREATE',$2,digest($2,'sha256'),'{}'::jsonb,$3,'SUCCEEDED','refund',$4)
       RETURNING id, provider_reference`,
      [tenantId, `fixture-${randomUUID()}`, `xpg_plc_${randomUUID().replaceAll('-', '')}`, providerRefundId],
    );
    await db.query(
      `INSERT INTO refunds (
         operation_id, tenant_id, environment, payment_id, payment_request_id,
         provider_refund_id, amount, currency, status, reason
       ) VALUES ($1,$2,'test',$3,$4,$5,1000,'IDR','PENDING','OTHERS')`,
      [operation.rows[0]?.id, tenantId, paymentId, paymentRequestId, providerRefundId],
    );
    await db.query(
      `INSERT INTO resource_mappings (
         environment, resource_type, resource_id, tenant_id, operation_id, source
       ) VALUES ('test','refund',$1,$2,$3,'API_RESPONSE')`,
      [providerRefundId, tenantId, operation.rows[0]?.id],
    );

    const sendRefund = (event: string, status: string) => app.inject({
      method: 'POST', url: '/webhooks/refunds',
      headers: { 'x-callback-token': 'provider-callback-secret', 'content-type': 'application/json' },
      payload: Buffer.from(JSON.stringify({
        event, business_id: 'business-test',
        data: {
          id: providerRefundId, payment_id: paymentId, payment_request_id: paymentRequestId,
          reference_id: operation.rows[0]?.provider_reference, business_id: 'business-test', status,
        },
      })),
    });
    const succeeded = await sendRefund('refund.succeeded', 'SUCCEEDED');
    const lateFailure = await sendRefund('refund.failed', 'FAILED');
    expect(succeeded.statusCode, succeeded.body).toBe(202);
    expect(lateFailure.statusCode, lateFailure.body).toBe(202);
    const current = await db.query<{ status: string }>('SELECT status FROM refunds WHERE operation_id = $1', [operation.rows[0]?.id]);
    expect(current.rows[0]?.status).toBe('SUCCEEDED');
  });

  it('rejects mismatched refund webhook identity without changing reserved amount', async () => {
    const paymentRequestId = `pr-refund-identity-${randomUUID()}`;
    const paymentId = `py-refund-identity-${randomUUID()}`;
    const providerRefundId = `rf-refund-identity-${randomUUID()}`;
    await createRefundFixture(db, tenantId, paymentRequestId, paymentId, '10000');
    const operation = await db.query<{ id: string; provider_reference: string }>(
      `INSERT INTO operations (
         tenant_id, environment, kind, idempotency_key, request_hash, request_body,
         provider_reference, status, provider_resource_type, provider_resource_id
       ) VALUES ($1,'test','REFUND_CREATE',$2,digest($2,'sha256'),'{}'::jsonb,$3,'SUCCEEDED','refund',$4)
       RETURNING id, provider_reference`,
      [tenantId, `fixture-${randomUUID()}`, `xpg_plc_${randomUUID().replaceAll('-', '')}`, providerRefundId],
    );
    await db.query(
      `INSERT INTO refunds (
         operation_id, tenant_id, environment, payment_id, payment_request_id,
         provider_refund_id, amount, currency, status, reason
       ) VALUES ($1,$2,'test',$3,$4,$5,1000,'IDR','PENDING','OTHERS')`,
      [operation.rows[0]?.id, tenantId, paymentId, paymentRequestId, providerRefundId],
    );
    await db.query(
      `INSERT INTO resource_mappings (
         environment, resource_type, resource_id, tenant_id, operation_id, source
       ) VALUES ('test','refund',$1,$2,$3,'API_RESPONSE')`,
      [providerRefundId, tenantId, operation.rows[0]?.id],
    );
    const response = await app.inject({
      method: 'POST', url: '/webhooks/refunds',
      headers: { 'x-callback-token': 'provider-callback-secret', 'content-type': 'application/json' },
      payload: Buffer.from(JSON.stringify({
        event: 'refund.failed', business_id: 'business-test',
        data: {
          id: providerRefundId, payment_id: `py-unrelated-${randomUUID()}`,
          payment_request_id: paymentRequestId,
          reference_id: operation.rows[0]?.provider_reference,
          business_id: 'business-test', status: 'FAILED',
        },
      })),
    });
    expect(response.statusCode, response.body).toBe(202);
    expect(response.json<{ route_status: string }>().route_status).toBe('QUARANTINED');
    const current = await db.query<{ status: string }>('SELECT status FROM refunds WHERE operation_id = $1', [operation.rows[0]?.id]);
    expect(current.rows[0]?.status).toBe('PENDING');
  });

  it('keeps delivery attempt history monotonic across admin replay', async () => {
    const event = await db.query<{ id: string }>(
      `INSERT INTO webhook_events (
         environment, ingress_path, event_type, dedup_key, business_id,
         raw_body, parsed_body, route_status, route_reason, tenant_id, routed_at
       ) VALUES ('test','payments','payment.capture',$1,'business-test',$2,$3,'ROUTED','REFERENCE_MATCH',$4,now())
       RETURNING id`,
      [`replay-${randomUUID()}`, Buffer.from('{}'), {}, tenantId],
    );
    const destination = await db.query<{ id: string }>(
      `SELECT id FROM destinations WHERE tenant_id = $1 AND environment = 'test'`,
      [tenantId],
    );
    const delivery = await db.query<{ id: string }>(
      `INSERT INTO deliveries (
         webhook_event_id, tenant_id, destination_id, status, attempt_count,
         replay_start_attempt, completed_at
       ) VALUES ($1,$2,$3,'DEAD',3,0,now()) RETURNING id`,
      [event.rows[0]?.id, tenantId, destination.rows[0]?.id],
    );
    await db.query(
      `INSERT INTO delivery_attempts (delivery_id, attempt_number, completed_at, error)
       VALUES ($1,1,now(),'one'),($1,2,now(),'two'),($1,3,now(),'three')`,
      [delivery.rows[0]?.id],
    );
    const encrypted = encrypt('replay-secret', config.encryptionKey, `destination:${tenantId}:test:callback`);
    await db.query(
      `UPDATE destinations SET enabled = true, callback_token_ciphertext = $2,
         callback_token_nonce = $3, callback_token_tag = $4 WHERE id = $1`,
      [destination.rows[0]?.id, encrypted.ciphertext, encrypted.nonce, encrypted.authTag],
    );
    const replay = await adminApp.inject({
      method: 'POST', url: `/admin/deliveries/${delivery.rows[0]?.id}/replay`,
      headers: { authorization: `Bearer ${config.adminToken}` },
    });
    expect(replay.statusCode, replay.body).toBe(200);
    const current = await db.query<{ status: string; attempt_count: number; replay_start_attempt: number }>(
      'SELECT status, attempt_count, replay_start_attempt FROM deliveries WHERE id = $1',
      [delivery.rows[0]?.id],
    );
    expect(current.rows[0]).toMatchObject({ status: 'PENDING', attempt_count: 3, replay_start_attempt: 3 });
    const attempts = await db.query<{ attempts: string }>(
      'SELECT count(*)::text AS attempts FROM delivery_attempts WHERE delivery_id = $1',
      [delivery.rows[0]?.id],
    );
    expect(attempts.rows[0]?.attempts).toBe('3');
  });

  it('routes reusable captures by payment and records request parent', async () => {
    const reference = `reusable-${randomUUID()}`;
    const paymentRequestId = `pr-${randomUUID()}`;
    await db.query(
      `INSERT INTO reference_routes (environment, reference_value, tenant_id, source)
       VALUES ('test',$1,$2,'IMPORT')`,
      [reference, tenantId],
    );
    const headers = { 'x-callback-token': 'provider-callback-secret', 'content-type': 'application/json' };
    const sendCapture = async (paymentId: string) => app.inject({
      method: 'POST', url: '/webhooks/payments', headers,
      payload: Buffer.from(JSON.stringify({
        event: 'payment.capture', business_id: 'business-test',
        data: {
          payment_id: paymentId, payment_request_id: paymentRequestId, reference_id: reference,
          business_id: 'business-test', amount: 10_000, currency: 'IDR',
        },
      })),
    });
    const firstId = `py-${randomUUID()}`;
    const secondId = `py-${randomUUID()}`;
    const first = await sendCapture(firstId);
    const second = await sendCapture(secondId);
    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(202);
    expect(first.json<{ event_id: string }>().event_id)
      .not.toBe(second.json<{ event_id: string }>().event_id);
    const parents = await db.query<{ payment_id: string; parent_resource_id: string }>(
      `SELECT resource_id AS payment_id, parent_resource_id FROM resource_mappings
        WHERE environment = 'test' AND resource_type = 'payment'
          AND resource_id = ANY($1::text[])`,
      [[firstId, secondId]],
    );
    expect(parents.rows).toHaveLength(2);
    expect(parents.rows.every((row) => row.parent_resource_id === paymentRequestId)).toBe(true);
  });

  it('quarantines conflicting resource owners without broadcasting', async () => {
    const paymentId = `py-${randomUUID()}`;
    const paymentRequestId = `pr-${randomUUID()}`;
    await db.query(
      `INSERT INTO resource_mappings (environment, resource_type, resource_id, tenant_id, source)
       VALUES ('test','payment',$1,$2,'IMPORT'), ('test','payment_request',$3,$4,'IMPORT')`,
      [paymentId, tenantId, paymentRequestId, secondTenantId],
    );
    const response = await app.inject({
      method: 'POST', url: '/webhooks/payments',
      headers: { 'x-callback-token': 'provider-callback-secret', 'content-type': 'application/json' },
      payload: Buffer.from(JSON.stringify({
        event: 'payment.capture', business_id: 'business-test',
        data: {
          payment_id: paymentId, payment_request_id: paymentRequestId,
          business_id: 'business-test', amount: 10_000, currency: 'IDR',
        },
      })),
    });
    expect(response.statusCode, response.body).toBe(202);
    expect(response.json<{ route_status: string }>().route_status).toBe('QUARANTINED');
    const eventId = response.json<{ event_id: string }>().event_id;
    const deliveries = await db.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM deliveries WHERE webhook_event_id = $1',
      [eventId],
    );
    expect(deliveries.rows[0]?.count).toBe('0');
  });

  it('preserves raw bytes and emits one delivery for duplicate callback', async () => {
    const destination = await db.query<{ id: string }>(
      'SELECT id FROM destinations WHERE tenant_id = $1 AND environment = $2', [tenantId, 'test'],
    );
    const encrypted = encrypt('downstream-secret', config.encryptionKey, `destination:${tenantId}:test:callback`);
    await db.query(
      `UPDATE destinations SET enabled = true, callback_token_ciphertext = $2,
        callback_token_nonce = $3, callback_token_tag = $4 WHERE id = $1`,
      [destination.rows[0]?.id, encrypted.ciphertext, encrypted.nonce, encrypted.authTag],
    );
    const reference = `legacy-${randomUUID()}`;
    await db.query(
      `INSERT INTO reference_routes (environment, reference_value, tenant_id, source)
       VALUES ('test',$1,$2,'IMPORT')`,
      [reference, tenantId],
    );
    const paymentId = `py-${randomUUID()}`;
    const paymentRequestId = `pr-${randomUUID()}`;
    const raw = Buffer.from(`{ "event" : "payment.capture", "business_id":"business-test", "data": {"payment_id":"${paymentId}","payment_request_id":"${paymentRequestId}","reference_id":"${reference}","business_id":"business-test","amount":10000,"currency":"IDR"} }`);
    const retry = Buffer.from(JSON.stringify({
      created: '2026-09-30T12:00:00.000Z',
      business_id: 'business-test',
      event: 'payment.capture',
      data: {
        currency: 'IDR', business_id: 'business-test', amount: 10_000,
        reference_id: reference, payment_request_id: paymentRequestId, payment_id: paymentId,
      },
    }));
    const headers = { 'x-callback-token': 'provider-callback-secret', 'content-type': 'application/json' };
    const first = await app.inject({ method: 'POST', url: '/webhooks/payments', headers, payload: raw });
    const second = await app.inject({ method: 'POST', url: '/webhooks/payments', headers, payload: retry });
    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(202);
    const id = first.json<{ event_id: string }>().event_id;
    expect(second.json<{ duplicate: boolean }>().duplicate).toBe(true);
    const saved = await db.query<{ raw_body: Buffer; route_status: string }>(
      'SELECT raw_body, route_status FROM webhook_events WHERE id = $1', [id],
    );
    expect(saved.rows[0]?.raw_body.equals(raw)).toBe(true);
    expect(saved.rows[0]?.route_status).toBe('ROUTED');
    const deliveries = await db.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM deliveries WHERE webhook_event_id = $1', [id],
    );
    expect(deliveries.rows[0]?.count).toBe('1');
    const conflict = await app.inject({
      method: 'POST', url: '/webhooks/payments', headers,
      payload: Buffer.from(JSON.stringify({
        event: 'payment.capture', business_id: 'business-test',
        data: {
          payment_id: paymentId, payment_request_id: paymentRequestId, reference_id: reference,
          business_id: 'business-test', amount: 99_999, currency: 'IDR',
        },
      })),
    });
    expect(conflict.statusCode, conflict.body).toBe(202);
    expect(conflict.json<{ duplicate: boolean; route_status: string }>()).toMatchObject({
      duplicate: true,
      route_status: 'QUARANTINED',
    });
    const storedConflict = await db.query<{ raw_body: Buffer }>(
      'SELECT raw_body FROM webhook_conflicts WHERE webhook_event_id = $1', [id],
    );
    expect(storedConflict.rows).toHaveLength(1);
    const invalid = await app.inject({ method: 'POST', url: '/webhooks/payments',
      headers: { 'x-callback-token': 'wrong', 'content-type': 'application/json' }, payload: raw });
    expect(invalid.statusCode).toBe(401);
  });
});
