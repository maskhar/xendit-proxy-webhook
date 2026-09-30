import { z } from 'zod';
import type { Database } from '../db/pool.js';
import { AppError } from '../security/errors.js';
import type { JsonObject, JsonValue } from '../security/json.js';

const jsonValue: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([z.string(), z.number(), z.boolean(), z.null(), z.array(jsonValue), z.record(z.string(), jsonValue)]),
);
const jsonObject = z.record(z.string(), jsonValue);

export const paymentRequestSchema = z.strictObject({
  reference_id: z.string().min(1).max(255),
  type: z.enum(['PAY', 'REUSABLE_PAYMENT_CODE']),
  country: z.string().length(2).default('ID'),
  currency: z.string().length(3),
  request_amount: z.number().positive().optional(),
  channel_code: z.string().min(1).max(100).optional(),
  channel_properties: jsonObject.optional(),
  capture_method: z.enum(['AUTOMATIC', 'MANUAL']).optional(),
  description: z.string().max(1_000).optional(),
  customer_id: z.string().min(1).max(255).optional(),
  metadata: jsonObject.optional(),
}).superRefine((body, context) => {
  if (!body['channel_code']) {
    context.addIssue({ code: 'custom', message: 'channel_code is required' });
  }
  if (body.type !== 'REUSABLE_PAYMENT_CODE' && body.request_amount === undefined) {
    context.addIssue({ code: 'custom', message: 'request_amount is required for this type' });
  }
});

export const paymentSessionSchema = z.strictObject({
  reference_id: z.string().min(1).max(64),
  session_type: z.literal('PAY'),
  mode: z.literal('PAYMENT_LINK'),
  amount: z.number().positive(),
  currency: z.string().length(3),
  country: z.string().length(2).default('ID'),
  customer_id: z.string().min(1).max(255).optional(),
  channel_properties: jsonObject.optional(),
  description: z.string().max(1_000).optional(),
  success_return_url: z.string().url().optional(),
  cancel_return_url: z.string().url().optional(),
  expires_at: z.string().datetime({ offset: true }).optional(),
  locale: z.string().min(2).max(10).optional(),
  metadata: jsonObject.optional(),
  allow_save_payment_method: z.enum(['OPTIONAL', 'FORCED', 'DISABLED']).optional(),
});

export type TenantPolicy = {
  currencies: string[];
  channels: string[];
  returnUrlHosts: string[];
};

export async function loadTenantPolicy(db: Database, tenantId: string): Promise<TenantPolicy> {
  const result = await db.query<{
    allowed_currencies: string[];
    allowed_channels: string[];
    return_url_hosts: string[];
  }>('SELECT allowed_currencies, allowed_channels, return_url_hosts FROM tenants WHERE id = $1 AND enabled', [tenantId]);
  const row = result.rows[0];
  if (!row) throw new AppError(403, 'TENANT_DISABLED', 'Tenant is disabled');
  return {
    currencies: row.allowed_currencies,
    channels: row.allowed_channels,
    returnUrlHosts: row.return_url_hosts,
  };
}

export function enforceTenantPolicy(body: JsonObject, policy: TenantPolicy): void {
  const currency = body['currency'];
  if (typeof currency === 'string' && !policy.currencies.includes(currency)) {
    throw new AppError(403, 'CURRENCY_NOT_ALLOWED', `Currency ${currency} is not allowed`);
  }
  const channel = body['channel_code'];
  if (typeof channel === 'string' && !policy.channels.includes(channel)) {
    throw new AppError(403, 'CHANNEL_NOT_ALLOWED', `Channel ${channel} is not allowed`);
  }
  rejectSensitiveFields(body);
  validateUrls(body, policy.returnUrlHosts);
}

function rejectSensitiveFields(value: JsonValue, key = ''): void {
  if (/^(?:card_details|card_number|cvn|cvv|card_cvn|payment_token_id)$/i.test(key)) {
    throw new AppError(400, 'UNSUPPORTED_PAYMENT_FIELD', `${key} cannot be supplied through gateway`);
  }
  if (Array.isArray(value)) {
    for (const child of value) rejectSensitiveFields(child, key);
  } else if (value !== null && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value)) rejectSensitiveFields(child, childKey);
  }
}

function validateUrls(value: JsonValue, allowedHosts: string[], key = ''): void {
  if (Array.isArray(value)) {
    for (const child of value) validateUrls(child, allowedHosts, key);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value)) validateUrls(child, allowedHosts, childKey);
    return;
  }
  if (typeof value !== 'string' || !/(?:return|redirect)_url$/i.test(key)) return;

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AppError(400, 'INVALID_RETURN_URL', `${key} must be a valid URL`);
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port) {
    throw new AppError(400, 'INVALID_RETURN_URL', `${key} must use HTTPS without credentials or custom port`);
  }
  const hostname = parsed.hostname.toLowerCase();
  if (!allowedHosts.some((host) => hostname === host || hostname.endsWith(`.${host}`))) {
    throw new AppError(403, 'RETURN_URL_NOT_ALLOWED', `Return URL host ${hostname} is not allowed`);
  }
}
