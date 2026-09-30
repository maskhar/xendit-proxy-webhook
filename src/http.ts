import type { FastifyRequest } from 'fastify';
import { AppError } from './security/errors.js';
import { asJsonObject, type JsonObject } from './security/json.js';

export function parseJsonBody(request: FastifyRequest): JsonObject {
  if (!Buffer.isBuffer(request.body)) throw new AppError(400, 'INVALID_JSON', 'JSON body required');
  try {
    return asJsonObject(JSON.parse(request.body.toString('utf8')) as unknown);
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(400, 'INVALID_JSON', 'Request body contains invalid JSON');
  }
}

export function requireIdempotencyKey(request: FastifyRequest): string {
  const value = request.headers['idempotency-key'];
  if (typeof value !== 'string') {
    throw new AppError(400, 'IDEMPOTENCY_KEY_REQUIRED', 'Idempotency-Key header is required');
  }
  return value;
}

export function requirePathId(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,255}$/.test(value)) {
    throw new AppError(400, 'INVALID_PATH_PARAMETER', `${name} is invalid`);
  }
  return value;
}
