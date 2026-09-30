import type { JsonObject } from '../security/json.js';

export type OperationKind =
  | 'PAYMENT_REQUEST_CREATE'
  | 'PAYMENT_REQUEST_CANCEL'
  | 'PAYMENT_SESSION_CREATE'
  | 'LEGACY_INVOICE_CREATE'
  | 'REFUND_CREATE';

export type OperationStatus = 'RESERVED' | 'IN_FLIGHT' | 'SUCCEEDED' | 'FAILED' | 'UNKNOWN';

export type Operation = {
  id: string;
  tenantId: string;
  environment: 'test' | 'live';
  kind: OperationKind;
  idempotencyKey: string;
  requestHash: Buffer;
  requestBody: JsonObject;
  clientReference: string | null;
  providerReference: string | null;
  status: OperationStatus;
  providerResourceType: string | null;
  providerResourceId: string | null;
  providerHttpStatus: number | null;
  responseBody: JsonObject | null;
  errorCode: string | null;
  errorDetail: string | null;
  createdAt: Date;
  updatedAt: Date;
};
