import type { Database, DbClient } from '../db/pool.js';
import { transaction } from '../db/pool.js';
import { AppError, errorMessage } from '../security/errors.js';
import { getString, type JsonObject } from '../security/json.js';
import { ProviderTransportError, type ProviderResponse } from '../xendit/client.js';
import { claimOperation, completeOperation, completeOperationWithClient, type CompleteOperationInput } from './repository.js';
import type { Operation } from './types.js';

export type ProviderCall = () => Promise<ProviderResponse>;

type ProviderResponseIssue = {
  code: string;
  detail: string;
};

export async function executeReservedOperation(
  db: Database,
  operation: Operation,
  call: ProviderCall,
  resource: (body: JsonObject) => { type?: string; id?: string; parentType?: string; parentId?: string },
  validateResponse?: (response: ProviderResponse) => ProviderResponseIssue | undefined,
  onCompletion?: (client: DbClient, result: Operation) => Promise<void>,
): Promise<Operation> {
  if (operation.status !== 'RESERVED') return operation;
  const claimed = await claimOperation(db, operation.id);
  if (!claimed) return operation;

  let completion: CompleteOperationInput;
  try {
    const response = await call();
    const identified = resource(response.body);
    const success = response.statusCode >= 200 && response.statusCode < 300;
    const issue = success ? validateResponse?.(response) : undefined;
    const uncertain = response.statusCode >= 500 || issue !== undefined;
    completion = {
      operationId: operation.id,
      environment: operation.environment,
      tenantId: operation.tenantId,
      status: success && !issue ? 'SUCCEEDED' : uncertain ? 'UNKNOWN' : 'FAILED',
      httpStatus: response.statusCode,
      responseBody: response.body,
      ...(success && !issue && identified.type ? { resourceType: identified.type } : {}),
      ...(success && !issue && identified.id ? { resourceId: identified.id } : {}),
      ...(success && !issue && identified.parentType ? { parentResourceType: identified.parentType } : {}),
      ...(success && !issue && identified.parentId ? { parentResourceId: identified.parentId } : {}),
      ...(issue ? { errorCode: issue.code, errorDetail: issue.detail } : {}),
      ...(!success ? { errorCode: getString(response.body, 'error_code') ?? 'XENDIT_ERROR' } : {}),
      ...(!success ? { errorDetail: getString(response.body, 'message') ?? `HTTP ${response.statusCode}` } : {}),
    };
  } catch (error) {
    const uncertain = error instanceof ProviderTransportError ? error.uncertain : true;
    completion = {
      operationId: operation.id,
      environment: operation.environment,
      tenantId: operation.tenantId,
      status: uncertain ? 'UNKNOWN' : 'FAILED',
      errorCode: error instanceof AppError ? error.code : 'PROVIDER_TRANSPORT_ERROR',
      errorDetail: errorMessage(error),
    };
  }

  if (!onCompletion) return completeOperation(db, completion);
  return transaction(db, async (client) => {
    const result = await completeOperationWithClient(client, completion);
    await onCompletion(client, result);
    return result;
  });
}

export function operationHttpStatus(operation: Operation): number {
  if (operation.status === 'SUCCEEDED') return operation.providerHttpStatus ?? 200;
  if (operation.status === 'FAILED') return operation.providerHttpStatus ?? 422;
  return 202;
}

export function publicOperation(operation: Operation): JsonObject {
  const result: JsonObject = {
    operation_id: operation.id,
    kind: operation.kind,
    status: operation.status,
    created_at: operation.createdAt.toISOString(),
    updated_at: operation.updatedAt.toISOString(),
  };
  if (operation.clientReference) result['client_reference_id'] = operation.clientReference;
  if (operation.providerResourceType) result['resource_type'] = operation.providerResourceType;
  if (operation.providerResourceId) result['resource_id'] = operation.providerResourceId;
  if (operation.responseBody) result['provider_response'] = operation.responseBody;
  if (operation.errorCode) result['error_code'] = operation.errorCode;
  if (operation.errorDetail) result['error_detail'] = operation.errorDetail;
  return result;
}

export function identifyPaymentRequest(body: JsonObject): { type?: string; id?: string } {
  const id = getString(body, 'payment_request_id', 'id');
  return id ? { type: 'payment_request', id } : {};
}

export function identifyPaymentSession(body: JsonObject): { type?: string; id?: string } {
  const id = getString(body, 'payment_session_id', 'id');
  return id ? { type: 'payment_session', id } : {};
}

export function identifyRefund(body: JsonObject): {
  type?: string;
  id?: string;
  parentType?: string;
  parentId?: string;
} {
  const id = getString(body, 'id', 'refund_id');
  const parentId = getString(body, 'payment_request_id');
  return {
    ...(id ? { type: 'refund', id } : {}),
    ...(parentId ? { parentType: 'payment_request', parentId } : {}),
  };
}

export function withProviderReference(body: JsonObject, providerReference: string): JsonObject {
  return { ...body, reference_id: providerReference };
}
