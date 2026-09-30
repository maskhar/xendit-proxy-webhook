import { describe, expect, it } from 'vitest';
import { decrypt, encrypt, matchesAnyToken, randomToken, sha256Hex } from '../../src/security/crypto.js';

describe('crypto', () => {
  it('encrypts with authenticated purpose binding', () => {
    const key = Buffer.alloc(32, 7);
    const encrypted = encrypt('tenant-secret', key, 'destination:a:test:callback');
    expect(decrypt(encrypted, key, 'destination:a:test:callback').toString()).toBe('tenant-secret');
    expect(() => decrypt(encrypted, key, 'destination:b:test:callback')).toThrow();
  });

  it('compares tokens and hashes deterministically', () => {
    expect(matchesAnyToken('secret', ['old', 'secret'])).toBe(true);
    expect(matchesAnyToken('wrong', ['old', 'secret'])).toBe(false);
    expect(sha256Hex('x')).toHaveLength(64);
    expect(randomToken()).not.toBe(randomToken());
  });
});
