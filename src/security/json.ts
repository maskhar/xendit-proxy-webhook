import { AppError } from './errors.js';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export function asJsonObject(value: unknown): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    throw new AppError(400, 'INVALID_JSON', 'JSON object required');
  }
  return value as JsonObject;
}

export function getString(object: JsonObject, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = object[key];
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return undefined;
}

export function getObject(object: JsonObject, key: string): JsonObject | undefined {
  const value = object[key];
  return value !== null && !Array.isArray(value) && typeof value === 'object'
    ? value
    : undefined;
}

export function getNumber(object: JsonObject, ...keys: string[]): number | undefined {
  for (const key of keys) {
    const value = object[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  }
  return undefined;
}
