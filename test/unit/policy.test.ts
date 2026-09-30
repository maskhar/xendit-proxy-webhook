import { describe, expect, it } from 'vitest';
import { enforceTenantPolicy, paymentRequestSchema, paymentSessionSchema } from '../../src/payments/policy.js';

describe('payment policy', () => {
  const policy = { currencies: ['IDR'], channels: ['DANA'], returnUrlHosts: ['example.com'] };

  it('accepts an allowlisted payment request', () => {
    const body = paymentRequestSchema.parse({
      reference_id: 'order-1', type: 'PAY', country: 'ID', currency: 'IDR', request_amount: 10_000,
      channel_code: 'DANA', channel_properties: { success_return_url: 'https://pay.example.com/success' },
    });
    expect(() => enforceTenantPolicy(JSON.parse(JSON.stringify(body)) as Record<string, string>, policy)).not.toThrow();
  });

  it('rejects non-allowlisted redirect host', () => {
    const body = paymentSessionSchema.parse({
      reference_id: 'order-1', session_type: 'PAY', mode: 'PAYMENT_LINK',
      amount: 10_000, currency: 'IDR', country: 'ID', success_return_url: 'https://evil.example/steal',
    });
    expect(() => enforceTenantPolicy(JSON.parse(JSON.stringify(body)) as Record<string, string>, policy)).toThrow(/not allowed/);
  });

  it('requires amount except reusable payment codes', () => {
    expect(() => paymentRequestSchema.parse({
      reference_id: 'order-1', type: 'PAY', currency: 'IDR', channel_code: 'DANA',
    })).toThrow();
    expect(() => paymentRequestSchema.parse({
      reference_id: 'order-1', type: 'REUSABLE_PAYMENT_CODE', currency: 'IDR', channel_code: 'DANA',
    })).not.toThrow();
  });
});
