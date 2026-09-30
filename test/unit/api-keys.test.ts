import { describe, expect, it } from 'vitest';
import { generateApiKey } from '../../src/security/api-keys.js';
import { sha256 } from '../../src/security/crypto.js';

describe('tenant API keys', () => {
  it('creates environment-bound token and hash', () => {
    const generated = generateApiKey('test');
    expect(generated.token.startsWith('xpg_test_')).toBe(true);
    expect(generated.token.startsWith(`${generated.prefix}_`)).toBe(true);
    expect(generated.hash.equals(sha256(generated.token))).toBe(true);
  });
});
