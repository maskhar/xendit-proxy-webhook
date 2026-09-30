import type { Config } from '../config/env.js';
import type { Database, DbClient } from '../db/pool.js';
import { transaction } from '../db/pool.js';
import { matchesAnyToken, sha256Hex } from '../security/crypto.js';
import { canonicalJson } from '../security/canonical-json.js';
import { AppError } from '../security/errors.js';
import { asJsonObject, getNumber, getObject, getString, type JsonObject } from '../security/json.js';
import { extractRoutingSignals, type RoutingSignals } from '../routing/extract.js';
import { resolveRoute, type RoutingDecision } from '../routing/resolve.js';

export type IngestResult = {
  eventId: string;
  duplicate: boolean;
  status: RoutingDecision['status'];
};

export function verifyWebhookToken(config: Config, candidate: string | undefined): void {
  if (!candidate || !matchesAnyToken(candidate, config.xenditCallbackTokens)) {
    throw new AppError(401, 'INVALID_WEBHOOK_TOKEN', 'Webhook token is invalid');
  }
}

export async function ingestWebhook(
  db: Database,
  config: Config,
  rawBody: Buffer,
  ingressPath: string,
): Promise<IngestResult> {
  let body: JsonObject;
  try {
    body = asJsonObject(JSON.parse(rawBody.toString('utf8')) as unknown);
  } catch {
    throw new AppError(400, 'INVALID_WEBHOOK_JSON', 'Webhook requires a JSON object');
  }
  const signals = extractRoutingSignals(body, ingressPath);
  if (signals.businessId && signals.businessId !== config.XENDIT_BUSINESS_ID) {
    throw new AppError(403, 'BUSINESS_MISMATCH', 'Webhook business ID mismatch');
  }
  if (['payments', 'sessions', 'refunds', 'invoices'].includes(ingressPath) && !signals.businessId) {
    throw new AppError(422, 'BUSINESS_ID_REQUIRED', 'Webhook business or invoice user ID is required');
  }

  const supported = isSupportedEvent(ingressPath, signals.eventType);
  const dedup = dedupIdentifier(signals, body, rawBody);
  return transaction(db, async (client) => {
    const inserted = await client.query<{ id: string }>(
      `INSERT INTO webhook_events (
         environment, ingress_path, event_type, dedup_key, weak_dedup,
         business_id, raw_body, parsed_body, headers, route_status, route_reason
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'{}'::jsonb,'UNROUTED','PENDING_ROUTE')
       ON CONFLICT (environment, event_type, dedup_key) DO NOTHING RETURNING id`,
      [
        config.APP_ENV,
        ingressPath,
        signals.eventType,
        dedup.key,
        dedup.weak,
        signals.businessId ?? null,
        rawBody,
        body,
      ],
    );
    const newEvent = inserted.rows[0];
    if (!newEvent) {
      const existing = await client.query<{
        id: string;
        route_status: RoutingDecision['status'];
        raw_body: Buffer;
        parsed_body: JsonObject;
      }>(
        `SELECT id, route_status, raw_body, parsed_body FROM webhook_events
          WHERE environment = $1 AND event_type = $2 AND dedup_key = $3`,
        [config.APP_ENV, signals.eventType, dedup.key],
      );
      const row = existing.rows[0];
      if (!row) throw new Error('Webhook duplicate row disappeared');
      if (row.raw_body.equals(rawBody) || sameLogicalWebhook(row.parsed_body, body)) {
        return { eventId: row.id, duplicate: true, status: row.route_status };
      }
      await client.query(
        `INSERT INTO webhook_conflicts (webhook_event_id, environment, raw_body, parsed_body)
         VALUES ($1,$2,$3,$4)`,
        [row.id, config.APP_ENV, rawBody, body],
      );
      await client.query(
        `INSERT INTO audit_log (environment, actor_type, action, target_type, target_id, detail)
         VALUES ($1,'SYSTEM','WEBHOOK_DEDUP_CONFLICT','webhook_event',$2,$3)`,
        [config.APP_ENV, row.id, { event_type: signals.eventType, dedup_key: dedup.key }],
      );
      return { eventId: row.id, duplicate: true, status: 'QUARANTINED' };
    }

    const decision: RoutingDecision = supported
      ? await resolveRoute(client, config.APP_ENV, signals, body)
      : { status: 'QUARANTINED', reason: 'UNSUPPORTED_EVENT' };
    const applied = await applyRoute(client, config, newEvent.id, decision, signals, body);
    return { eventId: newEvent.id, duplicate: false, status: applied.status };
  });
}

function sameLogicalWebhook(first: JsonObject, second: JsonObject): boolean {
  const withoutDeliveryTimestamp = (value: JsonObject): JsonObject => {
    const rest = { ...value };
    delete rest['created'];
    return rest;
  };
  return canonicalJson(withoutDeliveryTimestamp(first)) === canonicalJson(withoutDeliveryTimestamp(second));
}

function isSupportedEvent(ingress: string, eventType: string): boolean {
  const supported: Record<string, ReadonlySet<string>> = {
    payments: new Set([
      'payment.capture',
      'payment.failure',
      'payment.authorization',
      'payment.expiry',
      'payment_request.expiry',
      'payment_token.activation',
      'payment_token.failure',
      'payment_token.expiry',
    ]),
    sessions: new Set(['payment_session.completed', 'payment_session.expired']),
    refunds: new Set(['refund.succeeded', 'refund.failed']),
    invoices: new Set(['invoice.PAID', 'invoice.EXPIRED']),
    legacy: new Set([
      'virtual_account.paid',
      'ewallet.capture',
      'qr.payment',
    ]),
  };
  return supported[ingress]?.has(eventType) ?? false;
}

function dedupIdentifier(signals: RoutingSignals, body: JsonObject, rawBody: Buffer): { key: string; weak: boolean } {
  const captureKey = signals.captureIds.length > 0
    ? `:${signals.captureIds.slice().sort().join(',')}`
    : '';
  if (signals.primaryId) {
    return { key: `resource:${signals.primaryId}${captureKey}`, weak: false };
  }
  return { key: `raw:${sha256Hex(rawBody)}`, weak: true };
}

export async function applyRoute(
  client: DbClient,
  config: Config,
  eventId: string,
  decision: RoutingDecision,
  signals: RoutingSignals,
  body: JsonObject,
): Promise<RoutingDecision> {
  const tenantId = decision.tenantId;
  let status = decision.status;
  let reason = decision.reason;
  if (status === 'ROUTED' && tenantId) {
    const conflict = await refundIdentityConflict(client, config, tenantId, signals, body);
    if (conflict) {
      status = 'QUARANTINED';
      reason = conflict;
    }
  }
  if (status === 'ROUTED' && tenantId) {
    const conflict = await assignResourceMappings(client, config, tenantId, signals);
    if (conflict) {
      status = 'QUARANTINED';
      reason = conflict;
    }
  }
  if (status === 'ROUTED' && tenantId) {
    await recordCapturedPayment(client, config, tenantId, signals, body);
    await recordRefundStatus(client, config, tenantId, signals, body);
  }
  await client.query(
    `UPDATE webhook_events SET tenant_id = $2, route_status = $3, route_reason = $4,
        routed_at = CASE WHEN $3 = 'ROUTED' THEN now() ELSE NULL END
      WHERE id = $1`,
    [eventId, status === 'ROUTED' ? tenantId : null, status, reason],
  );
  if (status === 'ROUTED' && tenantId) {
    await client.query(
      `INSERT INTO deliveries (webhook_event_id, tenant_id, destination_id, status)
       SELECT $1, $2, d.id, 'PENDING' FROM destinations d
       WHERE d.tenant_id = $2 AND d.environment = $3 AND d.enabled
       ON CONFLICT (webhook_event_id, destination_id) DO NOTHING`,
      [eventId, tenantId, config.APP_ENV],
    );
  }
  return {
    status,
    reason,
    ...(status === 'ROUTED' && tenantId ? { tenantId } : {}),
  };
}

async function refundIdentityConflict(
  client: DbClient,
  config: Config,
  tenantId: string,
  signals: RoutingSignals,
  body: JsonObject,
): Promise<string | undefined> {
  if (!signals.eventType.startsWith('refund.')) return undefined;
  const data = getObject(body, 'data') ?? body;
  const refundId = signals.resourceIds.find(({ type }) => type === 'refund')?.id;
  const reference = getString(data, 'reference_id');
  const paymentId = getString(data, 'payment_id');
  const paymentRequestId = getString(data, 'payment_request_id');
  const status = getString(data, 'status');
  if (!paymentId || !paymentRequestId ||
      (signals.eventType === 'refund.succeeded' && status !== 'SUCCEEDED') ||
      (signals.eventType === 'refund.failed' && status !== 'FAILED' && status !== 'CANCELLED')) {
    return 'REFUND_IDENTITY_UNVERIFIED';
  }
  const matched = await client.query<{ id: string }>(
    `SELECT r.id FROM refunds r JOIN operations o ON o.id = r.operation_id
      WHERE r.environment = $1 AND r.tenant_id = $2
        AND r.payment_id = $3 AND r.payment_request_id = $4
        AND ($5::text IS NULL OR r.provider_refund_id IS NULL OR r.provider_refund_id = $5)
        AND ((r.provider_refund_id = $5 AND $5 IS NOT NULL)
          OR (o.provider_reference = $6 AND $6 IS NOT NULL))`,
    [config.APP_ENV, tenantId, paymentId, paymentRequestId, refundId ?? null, reference ?? null],
  );
  if (matched.rows.length !== 1) return 'REFUND_IDENTITY_UNVERIFIED';
  return undefined;
}

async function assignResourceMappings(
  client: DbClient,
  config: Config,
  tenantId: string,
  signals: RoutingSignals,
): Promise<string | undefined> {
  const paymentRequestId = signals.resourceIds.find(({ type }) => type === 'payment_request')?.id;
  for (const { type, id } of signals.resourceIds) {
    const result = await client.query<{ tenant_id: string }>(
      `INSERT INTO resource_mappings (
         environment, resource_type, resource_id, tenant_id,
         parent_resource_type, parent_resource_id, source
       ) VALUES ($1,$2,$3,$4,$5,$6,'WEBHOOK')
       ON CONFLICT (environment, provider, resource_type, resource_id)
       DO UPDATE SET
         parent_resource_type = COALESCE(resource_mappings.parent_resource_type, EXCLUDED.parent_resource_type),
         parent_resource_id = COALESCE(resource_mappings.parent_resource_id, EXCLUDED.parent_resource_id)
       WHERE resource_mappings.tenant_id = EXCLUDED.tenant_id
         AND (resource_mappings.parent_resource_id IS NULL
           OR EXCLUDED.parent_resource_id IS NULL
           OR resource_mappings.parent_resource_id = EXCLUDED.parent_resource_id)
       RETURNING tenant_id`,
      [
        config.APP_ENV, type, id, tenantId,
        type === 'payment' && paymentRequestId ? 'payment_request' : null,
        type === 'payment' ? paymentRequestId ?? null : null,
      ],
    );
    if (result.rows[0]?.tenant_id !== tenantId) return `RESOURCE_OWNER_CONFLICT:${type}`;
  }
  return undefined;
}

async function recordCapturedPayment(
  client: DbClient,
  config: Config,
  tenantId: string,
  signals: RoutingSignals,
  body: JsonObject,
): Promise<void> {
  if (signals.eventType !== 'payment.capture') return;
  const paymentId = signals.resourceIds.find(({ type }) => type === 'payment')?.id;
  if (!paymentId) return;
  const paymentRequestId = signals.resourceIds.find(({ type }) => type === 'payment_request')?.id;
  const data = getObject(body, 'data') ?? body;
  const payment = getObject(data, 'payment') ?? data;
  const captures = payment['captures'];
  const captureAmounts = Array.isArray(captures)
    ? captures.map((capture) => capture !== null && typeof capture === 'object' && !Array.isArray(capture)
      ? getNumber(capture, 'capture_amount')
      : undefined)
    : [];
  const amount = getNumber(payment, 'capture_amount', 'amount')
    ?? (captureAmounts.length === 1 ? captureAmounts[0] : undefined);
  const currency = getString(payment, 'currency');
  if (!amount || !currency || amount <= 0) return;
  const result = await client.query<{ tenant_id: string }>(
    `INSERT INTO payment_amounts (environment, payment_id, tenant_id, payment_request_id,
                                   amount, currency, captured_at)
       VALUES ($1,$2,$3,$4,$5,$6,now())
       ON CONFLICT (environment, payment_id)
       DO UPDATE SET captured_at = COALESCE(payment_amounts.captured_at, now())
       WHERE payment_amounts.tenant_id = EXCLUDED.tenant_id
         AND payment_amounts.currency = EXCLUDED.currency
         AND payment_amounts.amount = EXCLUDED.amount
         AND payment_amounts.payment_request_id IS NOT DISTINCT FROM EXCLUDED.payment_request_id
       RETURNING tenant_id`,
    [config.APP_ENV, paymentId, tenantId, paymentRequestId ?? null, amount, currency],
  );
  if (result.rows[0]?.tenant_id !== tenantId) {
    throw new AppError(409, 'PAYMENT_AMOUNT_CONFLICT', 'Payment amount belongs to another tenant');
  }
}

async function recordRefundStatus(
  client: DbClient,
  config: Config,
  tenantId: string,
  signals: RoutingSignals,
  body: JsonObject,
): Promise<void> {
  if (!signals.eventType.startsWith('refund.')) return;
  const refundId = signals.resourceIds.find(({ type }) => type === 'refund')?.id;
  const data = getObject(body, 'data') ?? body;
  const reference = getString(data, 'reference_id');
  const status = getString(data, 'status');
  if (!status || !['SUCCEEDED', 'FAILED', 'PENDING', 'CANCELLED'].includes(status)) return;
  if (status !== (signals.eventType === 'refund.succeeded' ? 'SUCCEEDED' : 'FAILED') &&
      !(signals.eventType === 'refund.failed' && status === 'CANCELLED')) return;
  const paymentId = getString(data, 'payment_id');
  const paymentRequestId = getString(data, 'payment_request_id');
  const result = await client.query<{ id: string }>(
    `UPDATE refunds r SET status = CASE
         WHEN r.status IN ('SUCCEEDED', 'FAILED') THEN r.status
         WHEN $1 = 'CANCELLED' THEN 'FAILED'
         ELSE $1 END,
         provider_refund_id = COALESCE(r.provider_refund_id, $2), updated_at = now()
       FROM operations o
      WHERE r.operation_id = o.id AND r.tenant_id = $3 AND r.environment = $4
        AND r.payment_id = $6 AND r.payment_request_id = $7
        AND ($2::text IS NULL OR r.provider_refund_id IS NULL OR r.provider_refund_id = $2)
        AND ((r.provider_refund_id = $2 AND $2 IS NOT NULL)
          OR (o.provider_reference = $5 AND $5 IS NOT NULL))
      RETURNING r.id`,
    [status, refundId ?? null, tenantId, config.APP_ENV, reference ?? null,
      paymentId ?? null, paymentRequestId ?? null],
  );
  if (result.rows.length === 0) {
    await client.query(
      `INSERT INTO audit_log (environment, actor_type, action, target_type, target_id, detail)
       VALUES ($1,'SYSTEM','UNMATCHED_REFUND_WEBHOOK','refund',$2,$3)`,
      [config.APP_ENV, refundId ?? null, { event: signals.eventType }],
    );
  }
}
