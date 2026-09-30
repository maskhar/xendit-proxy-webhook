import { randomUUID } from 'node:crypto';
import type { AppEnvironment } from '../config/types.js';
import type { Database, DbClient } from '../db/pool.js';
import { transaction } from '../db/pool.js';
import { canonicalJson } from '../security/canonical-json.js';
import { sha256 } from '../security/crypto.js';
import { AppError } from '../security/errors.js';
import type { JsonObject } from '../security/json.js';
import type { Operation, OperationKind } from './types.js';

type OperationRow = {
  id: string;
  tenant_id: string;
  environment: AppEnvironment;
  kind: OperationKind;
  idempotency_key: string;
  request_hash: Buffer;
  request_body: JsonObject;
  client_reference: string | null;
  provider_reference: string | null;
  status: Operation['status'];
  provider_resource_type: string | null;
  provider_resource_id: string | null;
  provider_http_status: number | null;
  response_body: JsonObject | null;
  error_code: string | null;
  error_detail: string | null;
  created_at: Date;
  updated_at: Date;
};

function mapOperation(row: OperationRow): Operation {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    environment: row.environment,
    kind: row.kind,
    idempotencyKey: row.idempotency_key,
    requestHash: row.request_hash,
    requestBody: row.request_body,
    clientReference: row.client_reference,
    providerReference: row.provider_reference,
    status: row.status,
    providerResourceType: row.provider_resource_type,
    providerResourceId: row.provider_resource_id,
    providerHttpStatus: row.provider_http_status,
    responseBody: row.response_body,
    errorCode: row.error_code,
    errorDetail: row.error_detail,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function providerReference(tenantCode: string, operationId: string): string {
  return `xpg_${tenantCode}_${operationId.replaceAll('-', '')}`;
}

export type ReserveOperationInput = {
  tenantId: string;
  tenantCode: string;
  environment: AppEnvironment;
  kind: OperationKind;
  idempotencyKey: string;
  requestBody: JsonObject;
  clientReference?: string;
  reserveReference?: boolean;
};

export async function reserveOperation(
  db: Database,
  input: ReserveOperationInput,
): Promise<{ operation: Operation; created: boolean }> {
  if (input.idempotencyKey.length < 8 || input.idempotencyKey.length > 255) {
    throw new AppError(400, 'INVALID_IDEMPOTENCY_KEY', 'Idempotency-Key must be 8-255 characters');
  }
  const requestHash = sha256(canonicalJson(input.requestBody));

  return transaction(db, async (client) => {
    const id = randomUUID();
    const reference = input.reserveReference === false ? null : providerReference(input.tenantCode, id);
    const inserted = await client.query<OperationRow>(
      `INSERT INTO operations (
         id, tenant_id, environment, kind, idempotency_key, request_hash, request_body,
         client_reference, provider_reference, status
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'RESERVED')
       ON CONFLICT (tenant_id, environment, kind, idempotency_key) DO NOTHING
       RETURNING *`,
      [
        id,
        input.tenantId,
        input.environment,
        input.kind,
        input.idempotencyKey,
        requestHash,
        input.requestBody,
        input.clientReference ?? null,
        reference,
      ],
    );
    const newOperation = inserted.rows[0];
    if (newOperation) {
      if (reference) {
        await client.query(
          `INSERT INTO reference_routes
             (environment, reference_value, tenant_id, operation_id, source)
           VALUES ($1,$2,$3,$4,'GATEWAY')`,
          [input.environment, reference, input.tenantId, id],
        );
      }
      return { operation: mapOperation(newOperation), created: true };
    }

    const existing = await client.query<OperationRow>(
      `SELECT * FROM operations
        WHERE tenant_id = $1 AND environment = $2 AND kind = $3 AND idempotency_key = $4
        FOR UPDATE`,
      [input.tenantId, input.environment, input.kind, input.idempotencyKey],
    );
    const row = existing.rows[0];
    if (!row) throw new Error('Operation conflict row disappeared');
    if (!row.request_hash.equals(requestHash)) {
      throw new AppError(409, 'IDEMPOTENCY_CONFLICT', 'Idempotency-Key was used with a different request');
    }
    return { operation: mapOperation(row), created: false };
  });
}

export async function claimOperation(
  db: Database,
  operationId: string,
  allowedStatuses: readonly Operation['status'][] = ['RESERVED'],
): Promise<Operation | undefined> {
  const result = await db.query<OperationRow>(
    `UPDATE operations SET status = 'IN_FLIGHT', started_at = now(), updated_at = now()
      WHERE id = $1 AND status = ANY($2::text[]) RETURNING *`,
    [operationId, allowedStatuses],
  );
  return result.rows[0] ? mapOperation(result.rows[0]) : undefined;
}

export type CompleteOperationInput = {
  operationId: string;
  environment: AppEnvironment;
  tenantId: string;
  status: 'SUCCEEDED' | 'FAILED' | 'UNKNOWN';
  httpStatus?: number;
  responseBody?: JsonObject;
  resourceType?: string;
  resourceId?: string;
  parentResourceType?: string;
  parentResourceId?: string;
  errorCode?: string;
  errorDetail?: string;
};

export async function completeOperation(
  db: Database,
  input: CompleteOperationInput,
): Promise<Operation> {
  return transaction(db, (client) => completeOperationWithClient(client, input));
}

export async function completeOperationWithClient(
  client: DbClient,
  input: CompleteOperationInput,
): Promise<Operation> {
  if (input.resourceType && input.resourceId) {
    await insertResourceMapping(client, {
      environment: input.environment,
      tenantId: input.tenantId,
      operationId: input.operationId,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      ...(input.parentResourceType ? { parentResourceType: input.parentResourceType } : {}),
      ...(input.parentResourceId ? { parentResourceId: input.parentResourceId } : {}),
    });
  }
  const result = await client.query<OperationRow>(
    `UPDATE operations SET status = $2, provider_http_status = $3, response_body = $4,
        provider_resource_type = $5, provider_resource_id = $6, error_code = $7,
        error_detail = $8, completed_at = CASE WHEN $2 = 'UNKNOWN' THEN NULL ELSE now() END,
        updated_at = now()
      WHERE id = $1 RETURNING *`,
    [
      input.operationId,
      input.status,
      input.httpStatus ?? null,
      input.responseBody ?? null,
      input.resourceType ?? null,
      input.resourceId ?? null,
      input.errorCode ?? null,
      input.errorDetail?.slice(0, 4_000) ?? null,
    ],
  );
  const row = result.rows[0];
  if (!row) throw new Error('Operation not found while completing');
  return mapOperation(row);
}

async function insertResourceMapping(
  client: DbClient,
  input: {
    environment: AppEnvironment;
    tenantId: string;
    operationId?: string;
    resourceType: string;
    resourceId: string;
    parentResourceType?: string;
    parentResourceId?: string;
  },
): Promise<void> {
  const result = await client.query<{ tenant_id: string }>(
    `INSERT INTO resource_mappings (
       environment, resource_type, resource_id, tenant_id, operation_id,
       parent_resource_type, parent_resource_id, source
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,'API_RESPONSE')
     ON CONFLICT (environment, provider, resource_type, resource_id)
     DO UPDATE SET operation_id = COALESCE(resource_mappings.operation_id, EXCLUDED.operation_id),
                   parent_resource_type = COALESCE(resource_mappings.parent_resource_type, EXCLUDED.parent_resource_type),
                   parent_resource_id = COALESCE(resource_mappings.parent_resource_id, EXCLUDED.parent_resource_id)
     WHERE resource_mappings.tenant_id = EXCLUDED.tenant_id
       AND (resource_mappings.parent_resource_id IS NULL
         OR EXCLUDED.parent_resource_id IS NULL
         OR resource_mappings.parent_resource_id = EXCLUDED.parent_resource_id)
     RETURNING tenant_id`,
    [
      input.environment,
      input.resourceType,
      input.resourceId,
      input.tenantId,
      input.operationId ?? null,
      input.parentResourceType ?? null,
      input.parentResourceId ?? null,
    ],
  );
  if (result.rows[0]?.tenant_id !== input.tenantId) {
    throw new AppError(409, 'ROUTE_CONFLICT', 'Provider resource is assigned to another tenant');
  }
}

export async function getOperation(
  db: Database,
  tenantId: string,
  environment: AppEnvironment,
  id: string,
): Promise<Operation | undefined> {
  const result = await db.query<OperationRow>(
    'SELECT * FROM operations WHERE id = $1 AND tenant_id = $2 AND environment = $3',
    [id, tenantId, environment],
  );
  return result.rows[0] ? mapOperation(result.rows[0]) : undefined;
}

export async function getResourceOwner(
  db: Database,
  environment: AppEnvironment,
  resourceType: string,
  resourceId: string,
): Promise<string | undefined> {
  const result = await db.query<{ tenant_id: string }>(
    `SELECT tenant_id FROM resource_mappings
      WHERE environment = $1 AND provider = 'xendit' AND resource_type = $2 AND resource_id = $3`,
    [environment, resourceType, resourceId],
  );
  return result.rows[0]?.tenant_id;
}
