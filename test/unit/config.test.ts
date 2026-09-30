import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/env.js';

function secrets(): Record<string, string> {
  const directory = mkdtempSync(join(tmpdir(), 'xproxy-config-'));
  const files: Record<string, string> = {};
  for (const [name, value] of Object.entries({
    xendit: 'xnd_secret', callback: 'callback', encryption: Buffer.alloc(32, 1).toString('base64'), admin: 'admin',
  })) {
    const path = join(directory, name);
    writeFileSync(path, value);
    files[name] = path;
  }
  return files;
}

describe('loadConfig', () => {
  it('loads secrets from files and rejects provider substitution', () => {
    const files = secrets();
    const base = {
      NODE_ENV: 'test', APP_ENV: 'test', DATABASE_URL: 'postgres://localhost/db',
      XENDIT_BUSINESS_ID: 'business', XENDIT_API_KEY_FILE: files['xendit'],
      XENDIT_CALLBACK_TOKEN_FILE: files['callback'], ENCRYPTION_KEY_FILE: files['encryption'],
      ADMIN_TOKEN_FILE: files['admin'],
    };
    expect(loadConfig(base).xenditApiKey).toBe('xnd_secret');
    expect(() => loadConfig({ ...base, XENDIT_API_BASE_URL: 'https://attacker.example' })).toThrow(/must be/);
    expect(loadConfig({ ...base, XENDIT_API_BASE_URL: 'http://127.0.0.1:9999', ALLOW_INSECURE_XENDIT_BASE_URL: 'true' }).XENDIT_API_BASE_URL)
      .toBe('http://127.0.0.1:9999');
  });
});
