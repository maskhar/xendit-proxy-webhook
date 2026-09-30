import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

export function sha256(value: string | Buffer): Buffer {
  return createHash('sha256').update(value).digest();
}

export function sha256Hex(value: string | Buffer): string {
  return sha256(value).toString('hex');
}

export function timingSafeTokenEqual(candidate: string, expected: string): boolean {
  const candidateHash = sha256(candidate);
  const expectedHash = sha256(expected);
  return timingSafeEqual(candidateHash, expectedHash);
}

export function matchesAnyToken(candidate: string, expected: readonly string[]): boolean {
  let matched = false;
  for (const token of expected) {
    matched = timingSafeTokenEqual(candidate, token) || matched;
  }
  return matched;
}

export type EncryptedValue = {
  ciphertext: Buffer;
  nonce: Buffer;
  authTag: Buffer;
};

export function encrypt(plaintext: string | Buffer, key: Buffer, purpose: string): EncryptedValue {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(purpose, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, nonce, authTag: cipher.getAuthTag() };
}

export function decrypt(value: EncryptedValue, key: Buffer, purpose: string): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, value.nonce);
  decipher.setAAD(Buffer.from(purpose, 'utf8'));
  decipher.setAuthTag(value.authTag);
  return Buffer.concat([decipher.update(value.ciphertext), decipher.final()]);
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}
