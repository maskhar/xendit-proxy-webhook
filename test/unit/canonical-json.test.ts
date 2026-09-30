import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../../src/security/canonical-json.js';

describe('canonicalJson', () => {
  it('sorts nested object keys while retaining array order', () => {
    expect(canonicalJson({ z: 1, a: { y: 2, x: 3 }, list: [{ b: 1, a: 2 }] }))
      .toBe('{"a":{"x":3,"y":2},"list":[{"a":2,"b":1}],"z":1}');
  });
});
