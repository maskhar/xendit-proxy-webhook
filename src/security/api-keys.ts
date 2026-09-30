import { randomBytes } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import type { AppEnvironment, Scope, TenantContext } from '../config/types.js';
import type { Database } from '../db/pool.js';
import { AppError } from './errors.js';
import { sha256 } from './crypto.js';

const scopes = new Set<Scope>([
  'payment:create',
  'payment:read',
  'payment:cancel',
  'session:create',
  'session:read',
  'refund:create',
  'refund:read',
]);

export type GeneratedApiKey = { token: string; prefix: string; hash: Buffer };

export function generateApiKey(environment: AppEnvironment): GeneratedApiKey {
  const locator = randomBytes(9).toString('base64url');
  const secret = randomBytes(32).toString('base64url');
  const prefix = `xpg_${environment}_${locator}`;
  const token = `${prefix}_${secret}`;
  return { token, prefix, hash: sha256(token) };
}

function getPrefix(token: string): string | undefined {
  const match = /^(xpg_(?:test|live)_[A-Za-z0-9_-]{12})_[A-Za-z0-9_-]{43}$/.exec(token);
  return match?.[1];
}

export async function authenticateTenant(
  db: Database,
  environment: AppEnvironment,
  request: FastifyRequest,
): Promise<TenantContext> {
  const authorization = request.headers.authorization;
  if (!authorization?.startsWith('Bearer ')) throw new AppError(401, 'UNAUTHORIZED', 'Bearer token required');

  const token = authorization.slice(7);
  const prefix = getPrefix(token);
  if (!prefix) throw new AppError(401, 'UNAUTHORIZED', 'Invalid API key');

  const result = await db.query<{
    api_key_id: string;
    tenant_id: string;
    tenant_slug: string;
    tenant_code: string;
    scopes: string[];
    key_hash: Buffer;
  }>(
    `SELECT k.id AS api_key_id, t.id AS tenant_id, t.slug AS tenant_slug,
            t.code AS tenant_code, k.scopes, k.key_hash
       FROM tenant_api_keys k
       JOIN tenants t ON t.id = k.tenant_id
      WHERE k.key_prefix = $1 AND k.environment = $2 AND k.revoked_at IS NULL
        AND (k.expires_at IS NULL OR k.expires_at > now()) AND t.enabled`,
    [prefix, environment],
  );
  const row = result.rows[0];
  if (!row || !sha256(token).equals(row.key_hash)) {
    throw new AppError(401, 'UNAUTHORIZED', 'Invalid API key');
  }

  void db.query('UPDATE tenant_api_keys SET last_used_at = now() WHERE id = $1', [row.api_key_id]).catch(() => undefined);
  const validScopes = row.scopes.filter((scope): scope is Scope => scopes.has(scope as Scope));
  return {
    tenantId: row.tenant_id,
    tenantSlug: row.tenant_slug,
    tenantCode: row.tenant_code,
    apiKeyId: row.api_key_id,
    scopes: new Set(validScopes),
  };
}

export function requireScope(context: TenantContext, scope: Scope): void {
  if (!context.scopes.has(scope)) throw new AppError(403, 'FORBIDDEN', `Missing scope: ${scope}`);
}
