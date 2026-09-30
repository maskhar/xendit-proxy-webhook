import { RE2JS } from 're2js';
import type { AppEnvironment } from '../config/types.js';
import type { DbClient } from '../db/pool.js';
import { getObject, type JsonObject, type JsonValue } from '../security/json.js';
import type { RoutingSignals } from './extract.js';

export type RoutingDecision = {
  status: 'ROUTED' | 'UNROUTED' | 'QUARANTINED';
  tenantId?: string;
  reason: string;
};

type TenantRow = { id: string };

async function selectOwners(
  client: DbClient,
  sql: string,
  parameters: unknown[],
  reason: string,
): Promise<RoutingDecision | undefined> {
  const result = await client.query<TenantRow>(sql, parameters);
  const owners = [...new Set(result.rows.map((row) => row.id))];
  if (owners.length === 1 && owners[0]) return { status: 'ROUTED', tenantId: owners[0], reason };
  if (owners.length > 1) return { status: 'QUARANTINED', reason: `${reason}: multiple tenants` };
  return undefined;
}

export async function resolveRoute(
  client: DbClient,
  environment: AppEnvironment,
  signals: RoutingSignals,
  body: JsonObject,
): Promise<RoutingDecision> {
  if (signals.resourceIds.length > 0) {
    const identifiers = signals.resourceIds.map((signal) => [signal.type, signal.id]);
    const mappedOwners = await client.query<TenantRow>(
      `SELECT DISTINCT t.id
         FROM resource_mappings m
         JOIN tenants t ON t.id = m.tenant_id AND t.enabled
        WHERE m.environment = $1 AND m.provider = 'xendit'
          AND (m.resource_type, m.resource_id) IN (
            SELECT resource_type, resource_id FROM jsonb_to_recordset($2::jsonb)
              AS x(resource_type text, resource_id text)
          )`,
      [environment, JSON.stringify(identifiers.map(([resource_type, resource_id]) => ({ resource_type, resource_id })))],
    );
    const owners = [...new Set(mappedOwners.rows.map((row) => row.id))];
    if (owners.length > 1) return { status: 'QUARANTINED', reason: 'RESOURCE_MAPPING: multiple tenants' };
    const mappedTenantId = owners[0];
    if (mappedTenantId) {
      if (signals.referenceId) {
        const referenceOwner = await selectOwners(
          client,
          `SELECT t.id FROM reference_routes r
             JOIN tenants t ON t.id = r.tenant_id AND t.enabled
            WHERE r.environment = $1 AND r.provider = 'xendit' AND r.reference_value = $2`,
          [environment, signals.referenceId],
          'REFERENCE_MAPPING',
        );
        if (referenceOwner?.status === 'ROUTED' && referenceOwner.tenantId !== mappedTenantId) {
          return { status: 'QUARANTINED', reason: 'RESOURCE_REFERENCE_CONFLICT' };
        }
      }
      return { status: 'ROUTED', tenantId: mappedTenantId, reason: 'RESOURCE_MAPPING' };
    }
  }

  if (signals.referenceId) {
    const reserved = await selectOwners(
      client,
      `SELECT t.id FROM reference_routes r
         JOIN tenants t ON t.id = r.tenant_id AND t.enabled
        WHERE r.environment = $1 AND r.provider = 'xendit' AND r.reference_value = $2`,
      [environment, signals.referenceId],
      'REFERENCE_MAPPING',
    );
    if (reserved) return reserved;

    const tagged = /^xpg_([a-z0-9]{2,12})_[a-f0-9]{32}$/.exec(signals.referenceId);
    if (tagged) {
      const match = await selectOwners(
        client,
        'SELECT id FROM tenants WHERE code = $1 AND enabled',
        [tagged[1]],
        'TENANT_REFERENCE_PREFIX',
      );
      if (match) return match;
    }
  }

  const rules = await client.query<{
    tenant_id: string;
    field_path: string;
    pattern: string;
    name: string;
  }>(
    `SELECT tenant_id, field_path, pattern, name FROM legacy_rules
      WHERE environment = $1 AND enabled ORDER BY priority ASC, id ASC LIMIT 100`,
    [environment],
  );
  const matches = new Set<string>();
  for (const rule of rules.rows) {
    const value = getPath(body, rule.field_path);
    if (typeof value !== 'string' || value.length > 1_000) continue;
    try {
      if (RE2JS.compile(rule.pattern).testExact(value)) matches.add(rule.tenant_id);
    } catch {
      return { status: 'QUARANTINED', reason: `INVALID_LEGACY_RULE:${rule.name}` };
    }
  }
  if (matches.size > 1) return { status: 'QUARANTINED', reason: 'LEGACY_RULE_CONFLICT' };
  const tenantId = [...matches][0];
  if (tenantId) return { status: 'ROUTED', tenantId, reason: 'LEGACY_RULE' };
  return { status: 'UNROUTED', reason: 'NO_MAPPING' };
}

function getPath(body: JsonObject, path: string): JsonValue | undefined {
  const parts = path.split('.');
  if (parts.length > 6) return undefined;
  let current: JsonValue | undefined = body;
  for (const part of parts) {
    if (current === null || Array.isArray(current) || typeof current !== 'object') return undefined;
    const object = getObject(current, part);
    current = object ?? current[part];
  }
  return current;
}
