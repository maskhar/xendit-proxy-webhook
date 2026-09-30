import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z, ZodError } from 'zod';
import type { Config } from '../config/env.js';
import type { Database, DbClient } from '../db/pool.js';
import { transaction } from '../db/pool.js';
import { parseJsonBody } from '../http.js';
import { extractRoutingSignals } from '../routing/extract.js';
import { resolveRoute } from '../routing/resolve.js';
import { generateApiKey } from '../security/api-keys.js';
import { encrypt } from '../security/crypto.js';
import { AppError } from '../security/errors.js';
import type { JsonObject } from '../security/json.js';
import { assertSafeDestination } from '../security/url-policy.js';
import { applyRoute } from '../webhooks/ingest.js';
import { authenticateAdmin } from './auth.js';

const uuid = z.uuid();
const idParams = z.object({ id: uuid });
const keyParams = z.object({ id: uuid });
const limitQuery = z.object({ limit: z.coerce.number().int().min(1).max(200).default(50) });
const scopes = z.enum([
  'payment:create', 'payment:read', 'payment:cancel',
  'session:create', 'session:read', 'refund:create', 'refund:read',
]);
const keyInput = z.strictObject({
  label: z.string().trim().min(1).max(100),
  scopes: z.array(scopes).min(1).max(7).refine((items) => new Set(items).size === items.length),
  expires_at: z.iso.datetime({ offset: true }).nullable().optional(),
});
const headerName = /^[a-z0-9-]+$/;
const reservedHeaders = new Set([
  'host', 'content-type', 'content-length', 'x-callback-token',
  'x-proxy-event-id', 'x-proxy-delivery-id', 'x-proxy-event-type',
  'user-agent', 'connection', 'transfer-encoding',
]);
const destinationInput = z.strictObject({
  url: z.url().max(2048),
  enabled: z.boolean().optional(),
  callback_token: z.string().min(1).max(2048).optional(),
  extra_headers: z.record(z.string(), z.string().max(4096)).optional(),
  max_attempts: z.number().int().min(1).max(50).optional(),
});
const policyInput = z.strictObject({
  enabled: z.boolean().optional(),
  allowed_currencies: z.array(z.string().regex(/^[A-Z]{3}$/)).max(50).optional(),
  allowed_channels: z.array(z.string().regex(/^[A-Za-z0-9_-]{1,100}$/)).max(100).optional(),
  return_url_hosts: z.array(z.string().regex(/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/)).max(100).optional(),
  max_refund_amount: z.number().finite().positive().nullable().optional(),
}).refine((value) => Object.keys(value).length > 0, 'At least one policy field is required');
const mappingInput = z.strictObject({
  tenant_id: uuid,
  references: z.array(z.string().min(1).max(255)).max(100).optional(),
  resources: z.array(z.strictObject({
    resource_type: z.enum(['payment', 'payment_request', 'payment_session', 'refund', 'invoice', 'payment_token']),
    resource_id: z.string().min(1).max(255),
  })).max(100).optional(),
}).refine((value) => (value.references?.length ?? 0) + (value.resources?.length ?? 0) > 0,
  'At least one mapping is required');

type TenantRow = { id: string; slug: string; code: string; enabled: boolean };

function params(request: FastifyRequest): { id: string } {
  return idParams.parse(request.params);
}

function input(request: FastifyRequest): JsonObject {
  return parseJsonBody(request);
}

async function tenant(client: DbClient, id: string): Promise<TenantRow> {
  const result = await client.query<TenantRow>(
    'SELECT id, slug, code, enabled FROM tenants WHERE id = $1 FOR UPDATE', [id],
  );
  if (!result.rows[0]) throw new AppError(404, 'NOT_FOUND', 'Tenant not found');
  return result.rows[0];
}

async function audit(client: DbClient, config: Config, action: string, targetType: string, targetId: string, detail: object = {}): Promise<void> {
  await client.query(
    `INSERT INTO audit_log (environment, actor_type, actor_id, action, target_type, target_id, detail)
     VALUES ($1, 'ADMIN', 'admin-token', $2, $3, $4, $5)`,
    [config.APP_ENV, action, targetType, targetId, JSON.stringify(detail)],
  );
}

function verifyHeaders(headers: Record<string, string>): void {
  for (const [name, value] of Object.entries(headers)) {
    if (!headerName.test(name) || reservedHeaders.has(name) || /[\r\n\0]/.test(value) || value.length === 0) {
      throw new AppError(400, 'INVALID_DESTINATION_HEADERS', 'Unsafe destination header');
    }
  }
}

export function registerAdminRoutes(app: FastifyInstance, db: Database, config: Config): void {
  app.addHook('onRequest', (request, _reply, done) => {
    try {
      authenticateAdmin(config, request);
      done();
    } catch (error) {
      done(error as Error);
    }
  });
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof ZodError) {
      return reply.code(400).send({ error: { code: 'VALIDATION_ERROR', message: 'Request validation failed', issues: error.issues } });
    }
    if (error instanceof AppError) {
      return reply.code(error.statusCode).send({ error: { code: error.code, message: error.message, detail: error.detail } });
    }
    app.log.error({ err: error }, 'Unhandled admin request error');
    return reply.code(500).send({ error: { code: 'INTERNAL_ERROR', message: 'Internal server error' } });
  });

  app.get('/admin/tenants', async () => {
    const result = await db.query(
      `SELECT t.id, t.slug, t.code, t.display_name, t.enabled, t.allowed_currencies,
              t.allowed_channels, t.return_url_hosts, t.max_refund_amount::text,
              d.id AS destination_id, d.url AS destination_url, d.enabled AS destination_enabled
         FROM tenants t LEFT JOIN destinations d ON d.tenant_id = t.id AND d.environment = $1
        ORDER BY t.slug`,
      [config.APP_ENV],
    );
    return { tenants: result.rows };
  });

  app.get<{ Params: { id: string } }>('/admin/tenants/:id/api-keys', async (request) => {
    const { id } = params(request);
    const result = await db.query(
      `SELECT k.id, k.label, k.key_prefix, k.scopes, k.expires_at, k.revoked_at,
              k.last_used_at, k.created_at FROM tenant_api_keys k
         JOIN tenants t ON t.id = k.tenant_id
        WHERE k.tenant_id = $1 AND k.environment = $2 ORDER BY k.created_at DESC`,
      [id, config.APP_ENV],
    );
    return { api_keys: result.rows };
  });

  app.post<{ Params: { id: string } }>('/admin/tenants/:id/api-keys', async (request, reply) => {
    const { id } = params(request);
    const data = keyInput.parse(input(request));
    if (data.expires_at && Date.parse(data.expires_at) <= Date.now()) {
      throw new AppError(400, 'INVALID_EXPIRY', 'API key expiry must be in future');
    }
    const generated = generateApiKey(config.APP_ENV);
    const row = await transaction(db, async (client) => {
      await tenant(client, id);
      const result = await client.query<{ id: string; key_prefix: string; label: string; scopes: string[] }>(
        `INSERT INTO tenant_api_keys (tenant_id, environment, label, key_prefix, key_hash, scopes, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, key_prefix, label, scopes`,
        [id, config.APP_ENV, data.label, generated.prefix, generated.hash, data.scopes, data.expires_at ?? null],
      );
      const key = result.rows[0];
      if (!key) throw new Error('API key was not created');
      await audit(client, config, 'API_KEY_CREATED', 'tenant_api_key', key.id, { tenant_id: id, label: data.label, scopes: data.scopes });
      return key;
    });
    return reply.code(201).send({ ...row, token: generated.token });
  });

  app.post<{ Params: { id: string } }>('/admin/api-keys/:id/rotate', async (request) => {
    const { id } = keyParams.parse(request.params);
    const generated = generateApiKey(config.APP_ENV);
    const key = await transaction(db, async (client) => {
      const result = await client.query<{ id: string; tenant_id: string; label: string; key_prefix: string }>(
        `UPDATE tenant_api_keys SET key_prefix = $3, key_hash = $4, last_used_at = NULL
          WHERE id = $1 AND environment = $2 AND revoked_at IS NULL
            AND (expires_at IS NULL OR expires_at > now())
          RETURNING id, tenant_id, label, key_prefix`,
        [id, config.APP_ENV, generated.prefix, generated.hash],
      );
      const row = result.rows[0];
      if (!row) throw new AppError(404, 'NOT_FOUND', 'Active API key not found');
      await audit(client, config, 'API_KEY_ROTATED', 'tenant_api_key', id, { tenant_id: row.tenant_id });
      return row;
    });
    return { ...key, token: generated.token };
  });

  app.post<{ Params: { id: string } }>('/admin/api-keys/:id/revoke', async (request) => {
    const { id } = params(request);
    return transaction(db, async (client) => {
      const result = await client.query<{ tenant_id: string }>(
        `UPDATE tenant_api_keys SET revoked_at = now()
          WHERE id = $1 AND environment = $2 AND revoked_at IS NULL RETURNING tenant_id`,
        [id, config.APP_ENV],
      );
      const row = result.rows[0];
      if (!row) throw new AppError(404, 'NOT_FOUND', 'Active API key not found');
      await audit(client, config, 'API_KEY_REVOKED', 'tenant_api_key', id, { tenant_id: row.tenant_id });
      return { revoked: true, id };
    });
  });

  app.put<{ Params: { id: string } }>('/admin/tenants/:id/destination', async (request) => {
    const { id } = params(request);
    const data = destinationInput.parse(input(request));
    verifyHeaders(data.extra_headers ?? {});
    const url = await assertSafeDestination(data.url);
    const callback = data.callback_token === undefined ? undefined
      : encrypt(data.callback_token, config.encryptionKey, `destination:${id}:${config.APP_ENV}:callback`);
    const headers = data.extra_headers === undefined ? undefined
      : encrypt(JSON.stringify(data.extra_headers), config.encryptionKey, `destination:${id}:${config.APP_ENV}:headers`);
    return transaction(db, async (client) => {
      await tenant(client, id);
      const result = await client.query<{ id: string; url: string; enabled: boolean; max_attempts: number }>(
        `INSERT INTO destinations (tenant_id, environment, url, enabled,
            callback_token_ciphertext, callback_token_nonce, callback_token_tag,
            extra_headers_ciphertext, extra_headers_nonce, extra_headers_tag, max_attempts)
         VALUES ($1,$2,$3,COALESCE($4::boolean,false),$5,$6,$7,$8,$9,$10,COALESCE($11::integer,12))
         ON CONFLICT (tenant_id, environment) DO UPDATE SET
           url = EXCLUDED.url, enabled = COALESCE($4::boolean, destinations.enabled),
           callback_token_ciphertext = COALESCE(EXCLUDED.callback_token_ciphertext, destinations.callback_token_ciphertext),
           callback_token_nonce = COALESCE(EXCLUDED.callback_token_nonce, destinations.callback_token_nonce),
           callback_token_tag = COALESCE(EXCLUDED.callback_token_tag, destinations.callback_token_tag),
           extra_headers_ciphertext = COALESCE(EXCLUDED.extra_headers_ciphertext, destinations.extra_headers_ciphertext),
           extra_headers_nonce = COALESCE(EXCLUDED.extra_headers_nonce, destinations.extra_headers_nonce),
           extra_headers_tag = COALESCE(EXCLUDED.extra_headers_tag, destinations.extra_headers_tag),
           max_attempts = COALESCE($11::integer, destinations.max_attempts), updated_at = now()
         RETURNING id, url, enabled, max_attempts`,
        [id, config.APP_ENV, url.toString(), data.enabled ?? null,
          callback?.ciphertext ?? null, callback?.nonce ?? null, callback?.authTag ?? null,
          headers?.ciphertext ?? null, headers?.nonce ?? null, headers?.authTag ?? null,
          data.max_attempts ?? null],
      );
      const destination = result.rows[0];
      if (!destination) throw new Error('Destination was not saved');
      await audit(client, config, 'DESTINATION_UPDATED', 'destination', destination.id, {
        tenant_id: id, enabled: destination.enabled, url: destination.url,
        callback_token_changed: callback !== undefined, extra_headers_changed: headers !== undefined,
      });
      return { destination };
    });
  });

  app.patch<{ Params: { id: string } }>('/admin/tenants/:id/policy', async (request) => {
    const { id } = params(request);
    const data = policyInput.parse(input(request));
    for (const values of [data.allowed_currencies, data.allowed_channels, data.return_url_hosts]) {
      if (values && new Set(values).size !== values.length) {
        throw new AppError(400, 'INVALID_POLICY', 'Policy lists must contain unique values');
      }
    }
    return transaction(db, async (client) => {
      await tenant(client, id);
      const result = await client.query(
        `UPDATE tenants SET
          enabled = COALESCE($2, enabled),
          allowed_currencies = COALESCE($3, allowed_currencies),
          allowed_channels = COALESCE($4, allowed_channels),
          return_url_hosts = COALESCE($5, return_url_hosts),
          max_refund_amount = CASE WHEN $6::boolean THEN $7::numeric ELSE max_refund_amount END,
          updated_at = now()
         WHERE id = $1 RETURNING id, slug, enabled, allowed_currencies,
           allowed_channels, return_url_hosts, max_refund_amount::text`,
        [id, data.enabled ?? null, data.allowed_currencies ?? null,
          data.allowed_channels ?? null, data.return_url_hosts ?? null,
          data.max_refund_amount !== undefined, data.max_refund_amount ?? null],
      );
      await audit(client, config, 'TENANT_POLICY_UPDATED', 'tenant', id, data);
      return { tenant: result.rows[0] as unknown };
    });
  });

  app.post('/admin/mappings/import', async (request, reply) => {
    const data = mappingInput.parse(input(request));
    const imported = await transaction(db, async (client) => {
      await tenant(client, data.tenant_id);
      for (const reference of data.references ?? []) {
        const result = await client.query<{ tenant_id: string }>(
          `INSERT INTO reference_routes (environment, reference_value, tenant_id, source)
           VALUES ($1,$2,$3,'IMPORT')
           ON CONFLICT (environment, provider, reference_value)
           DO UPDATE SET tenant_id = reference_routes.tenant_id
           WHERE reference_routes.tenant_id = EXCLUDED.tenant_id RETURNING tenant_id`,
          [config.APP_ENV, reference, data.tenant_id],
        );
        if (result.rows[0]?.tenant_id !== data.tenant_id) {
          throw new AppError(409, 'ROUTE_CONFLICT', 'Reference belongs to another tenant');
        }
      }
      for (const resource of data.resources ?? []) {
        const result = await client.query<{ tenant_id: string }>(
          `INSERT INTO resource_mappings (environment, resource_type, resource_id, tenant_id, source)
           VALUES ($1,$2,$3,$4,'IMPORT')
           ON CONFLICT (environment, provider, resource_type, resource_id)
           DO UPDATE SET tenant_id = resource_mappings.tenant_id
           WHERE resource_mappings.tenant_id = EXCLUDED.tenant_id RETURNING tenant_id`,
          [config.APP_ENV, resource.resource_type, resource.resource_id, data.tenant_id],
        );
        if (result.rows[0]?.tenant_id !== data.tenant_id) {
          throw new AppError(409, 'ROUTE_CONFLICT', 'Resource belongs to another tenant');
        }
      }
      await audit(client, config, 'MAPPINGS_IMPORTED', 'tenant', data.tenant_id, {
        references: data.references ?? [], resources: data.resources ?? [],
      });
      return { tenant_id: data.tenant_id, references: data.references?.length ?? 0, resources: data.resources?.length ?? 0 };
    });
    return reply.code(201).send(imported);
  });

  app.get('/admin/events/unrouted', async (request) => {
    const { limit } = limitQuery.parse(request.query);
    const result = await db.query(
      `SELECT e.id, e.ingress_path, e.event_type, e.business_id, e.route_status, e.route_reason,
              e.parsed_body, e.received_at,
              (SELECT count(*)::int FROM webhook_conflicts c WHERE c.webhook_event_id = e.id) AS conflict_count
         FROM webhook_events e
        WHERE e.environment = $1 AND (
          e.route_status IN ('UNROUTED', 'QUARANTINED')
          OR EXISTS (SELECT 1 FROM webhook_conflicts c WHERE c.webhook_event_id = e.id)
        )
        ORDER BY e.received_at DESC LIMIT $2`, [config.APP_ENV, limit],
    );
    return { events: result.rows };
  });

  app.get('/admin/events/conflicts', async (request) => {
    const { limit } = limitQuery.parse(request.query);
    const result = await db.query(
      `SELECT c.id, c.webhook_event_id, c.received_at, c.parsed_body,
              e.event_type, e.route_status, e.tenant_id
         FROM webhook_conflicts c JOIN webhook_events e ON e.id = c.webhook_event_id
        WHERE c.environment = $1
        ORDER BY c.received_at DESC LIMIT $2`, [config.APP_ENV, limit],
    );
    return { conflicts: result.rows };
  });

  app.get('/admin/deliveries/dead', async (request) => {
    const { limit } = limitQuery.parse(request.query);
    const result = await db.query(
      `SELECT d.id, d.webhook_event_id, d.tenant_id, d.destination_id, d.attempt_count,
              d.last_http_status, d.last_error, d.updated_at, e.event_type
         FROM deliveries d JOIN webhook_events e ON e.id = d.webhook_event_id
        WHERE e.environment = $1 AND d.status = 'DEAD'
        ORDER BY d.updated_at DESC LIMIT $2`, [config.APP_ENV, limit],
    );
    return { deliveries: result.rows };
  });

  app.get('/admin/operations/unknown', async (request) => {
    const { limit } = limitQuery.parse(request.query);
    const result = await db.query(
      `SELECT id, tenant_id, kind, status, client_reference, provider_reference,
              provider_resource_type, provider_resource_id, error_code, error_detail,
              created_at, updated_at FROM operations
        WHERE environment = $1 AND (
          status = 'UNKNOWN'
          OR (status IN ('RESERVED', 'IN_FLIGHT') AND updated_at < now() - interval '5 minutes')
        )
        ORDER BY updated_at DESC LIMIT $2`, [config.APP_ENV, limit],
    );
    return { operations: result.rows };
  });

  app.post<{ Params: { id: string } }>('/admin/events/:id/reroute', async (request) => {
    const { id } = params(request);
    return transaction(db, async (client) => {
      const result = await client.query<{
        parsed_body: JsonObject; ingress_path: string; route_status: string; route_reason: string;
        business_id: string | null;
      }>(
        `SELECT parsed_body, ingress_path, route_status, route_reason, business_id
           FROM webhook_events WHERE id = $1 AND environment = $2 FOR UPDATE`,
        [id, config.APP_ENV],
      );
      const event = result.rows[0];
      if (!event) throw new AppError(404, 'NOT_FOUND', 'Webhook event not found');
      if (event.route_status === 'ROUTED' || event.route_reason === 'UNSUPPORTED_EVENT') {
        throw new AppError(409, 'REROUTE_NOT_ALLOWED', 'Event cannot be rerouted');
      }
      if (event.business_id && event.business_id !== config.XENDIT_BUSINESS_ID) {
        throw new AppError(409, 'BUSINESS_MISMATCH', 'Webhook business ID mismatch');
      }
      const signals = extractRoutingSignals(event.parsed_body, event.ingress_path);
      const decision = await resolveRoute(client, config.APP_ENV, signals, event.parsed_body);
      if (decision.status !== 'ROUTED') {
        throw new AppError(409, 'ROUTE_NOT_FOUND', 'Event still lacks unique tenant mapping', decision.reason);
      }
      await applyRoute(client, config, id, decision, signals, event.parsed_body);
      const current = await client.query<{ route_status: string; route_reason: string; tenant_id: string | null }>(
        'SELECT route_status, route_reason, tenant_id FROM webhook_events WHERE id = $1', [id],
      );
      const routed = current.rows[0];
      if (!routed || routed.route_status !== 'ROUTED') {
        throw new AppError(409, 'ROUTE_CONFLICT', 'Event could not be routed', routed?.route_reason);
      }
      await audit(client, config, 'WEBHOOK_REROUTED', 'webhook_event', id, {
        tenant_id: routed.tenant_id, reason: routed.route_reason,
      });
      return { id, ...routed };
    });
  });

  app.post<{ Params: { id: string } }>('/admin/deliveries/:id/replay', async (request) => {
    const { id } = params(request);
    return transaction(db, async (client) => {
      const result = await client.query<{
        webhook_event_id: string;
        tenant_id: string;
        previous_attempts: number;
      }>(
        `UPDATE deliveries d SET status = 'PENDING', next_attempt_at = now(),
                replay_start_attempt = d.attempt_count,
                completed_at = NULL, last_error = NULL, last_http_status = NULL,
                lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
           FROM webhook_events e, destinations dest
          WHERE d.id = $1 AND d.webhook_event_id = e.id AND d.destination_id = dest.id
            AND e.environment = $2 AND e.route_status = 'ROUTED'
            AND e.tenant_id = d.tenant_id AND dest.tenant_id = d.tenant_id
            AND dest.environment = $2 AND dest.enabled AND d.status = 'DEAD'
          RETURNING d.webhook_event_id, d.tenant_id, d.replay_start_attempt AS previous_attempts`,
        [id, config.APP_ENV],
      );
      const delivery = result.rows[0];
      if (!delivery) throw new AppError(409, 'REPLAY_NOT_ALLOWED', 'Only dead deliveries to enabled destinations can be replayed');
      await audit(client, config, 'DELIVERY_REPLAYED', 'delivery', id, {
        tenant_id: delivery.tenant_id, webhook_event_id: delivery.webhook_event_id,
        previous_attempts: delivery.previous_attempts,
      });
      return { id, status: 'PENDING', previous_attempts: delivery.previous_attempts };
    });
  });

  app.get('/admin/audit', async (request) => {
    const { limit } = limitQuery.parse(request.query);
    const result = await db.query(
      `SELECT id, actor_type, actor_id, action, target_type, target_id, detail, created_at
         FROM audit_log WHERE environment = $1 ORDER BY id DESC LIMIT $2`,
      [config.APP_ENV, limit],
    );
    return { audit: result.rows };
  });
}
