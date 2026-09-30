import { readFileSync } from 'node:fs';
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  APP_ENV: z.enum(['test', 'live']).default('test'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(3000),
  ADMIN_HOST: z.string().default('127.0.0.1'),
  ADMIN_PORT: z.coerce.number().int().positive().default(3001),
  DATABASE_URL: z.string().min(1).optional(),
  DATABASE_URL_FILE: z.string().min(1).optional(),
  DATABASE_MAX_CONNECTIONS: z.coerce.number().int().positive().default(20),
  XENDIT_API_BASE_URL: z.string().url().default('https://api.xendit.co'),
  ALLOW_INSECURE_XENDIT_BASE_URL: z.enum(['false', 'true']).default('false'),
  XENDIT_API_VERSION: z.string().default('2024-11-11'),
  XENDIT_BUSINESS_ID: z.string().min(1),
  XENDIT_API_KEY_FILE: z.string().min(1),
  XENDIT_CALLBACK_TOKEN_FILE: z.string().min(1),
  XENDIT_PREVIOUS_CALLBACK_TOKEN_FILE: z.string().optional(),
  ENCRYPTION_KEY_FILE: z.string().min(1),
  ADMIN_TOKEN_FILE: z.string().min(1),
  PROVIDER_TIMEOUT_MS: z.coerce.number().int().positive().default(20_000),
  WEBHOOK_BODY_LIMIT_BYTES: z.coerce.number().int().positive().default(1_048_576),
  API_BODY_LIMIT_BYTES: z.coerce.number().int().positive().default(262_144),
  DELIVERY_BATCH_SIZE: z.coerce.number().int().positive().max(100).default(20),
  DELIVERY_POLL_MS: z.coerce.number().int().positive().default(1_000),
  DELIVERY_LEASE_MS: z.coerce.number().int().positive().default(60_000),
  DELIVERY_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
});

export type Config = Omit<z.infer<typeof schema>, 'DATABASE_URL'> & {
  DATABASE_URL: string;
  xenditApiKey: string;
  xenditCallbackTokens: readonly string[];
  encryptionKey: Buffer;
  adminToken: string;
};

function secret(path: string): string {
  return readFileSync(path, 'utf8').trim();
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.parse(env);
  if (!parsed.DATABASE_URL_FILE && !parsed.DATABASE_URL) {
    throw new Error('DATABASE_URL_FILE or DATABASE_URL is required');
  }
  if (parsed.NODE_ENV === 'production' && parsed.DATABASE_URL && !parsed.DATABASE_URL_FILE) {
    throw new Error('DATABASE_URL_FILE is required in production');
  }
  const providerUrl = new URL(parsed.XENDIT_API_BASE_URL);
  if (parsed.ALLOW_INSECURE_XENDIT_BASE_URL === 'true' && parsed.NODE_ENV !== 'test') {
    throw new Error('ALLOW_INSECURE_XENDIT_BASE_URL is restricted to NODE_ENV=test');
  }
  if (parsed.ALLOW_INSECURE_XENDIT_BASE_URL !== 'true' &&
      (providerUrl.protocol !== 'https:' || providerUrl.hostname !== 'api.xendit.co' ||
       providerUrl.port || providerUrl.pathname !== '/' || providerUrl.search || providerUrl.hash)) {
    throw new Error('XENDIT_API_BASE_URL must be https://api.xendit.co outside isolated tests');
  }
  const encryptionKey = Buffer.from(secret(parsed.ENCRYPTION_KEY_FILE), 'base64');
  if (encryptionKey.length !== 32) {
    throw new Error('ENCRYPTION_KEY_FILE must contain a base64-encoded 32-byte key');
  }

  const callbackTokens = [
    secret(parsed.XENDIT_CALLBACK_TOKEN_FILE),
    parsed.XENDIT_PREVIOUS_CALLBACK_TOKEN_FILE
      ? secret(parsed.XENDIT_PREVIOUS_CALLBACK_TOKEN_FILE)
      : undefined,
  ].filter((value): value is string => Boolean(value));

  return {
    ...parsed,
    DATABASE_URL: parsed.DATABASE_URL_FILE
      ? secret(parsed.DATABASE_URL_FILE)
      : (parsed.DATABASE_URL as string),
    xenditApiKey: secret(parsed.XENDIT_API_KEY_FILE),
    xenditCallbackTokens: callbackTokens,
    encryptionKey,
    adminToken: secret(parsed.ADMIN_TOKEN_FILE),
  };
}
