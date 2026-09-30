import { describe, expect, it } from 'vitest';
import { extractRoutingSignals } from '../../src/routing/extract.js';

describe('extractRoutingSignals', () => {
  it('extracts Payments v3 envelope without collapsing reusable payments', () => {
    const first = extractRoutingSignals({
      event: 'payment.capture',
      api_version: 'v3',
      data: {
        business_id: 'biz',
        reference_id: 'xpg_plc_0123456789abcdef0123456789abcdef',
        payment_request_id: 'pr-one',
        payment_id: 'py-one',
        captures: [{ capture_id: 'cap-one' }],
      },
    }, 'payments');
    const second = extractRoutingSignals({
      event: 'payment.capture',
      data: {
        business_id: 'biz',
        reference_id: 'same',
        payment_request_id: 'pr-one',
        payment_id: 'py-two',
      },
    }, 'payments');
    expect(first.primaryId).toBe('py-one');
    expect(first.captureIds).toEqual(['cap-one']);
    expect(second.primaryId).toBe('py-two');
  });

  it('extracts session business ID from envelope', () => {
    const result = extractRoutingSignals({
      event: 'payment_session.completed',
      business_id: 'biz',
      data: { payment_session_id: 'ps-one', reference_id: 'ref' },
    }, 'sessions');
    expect(result.businessId).toBe('biz');
    expect(result.primaryId).toBe('ps-one');
  });

  it('supports legacy invoice shape', () => {
    const result = extractRoutingSignals({ id: 'inv-one', external_id: 'legacy-order', status: 'PAID' }, 'invoices');
    expect(result.eventType).toBe('invoice.PAID');
    expect(result.primaryId).toBe('inv-one');
    expect(result.referenceId).toBe('legacy-order');
  });
});
