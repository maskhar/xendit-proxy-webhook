import { getObject, getString, type JsonObject } from '../security/json.js';

export type RoutingSignals = {
  eventType: string;
  businessId?: string;
  referenceId?: string;
  resourceIds: { type: string; id: string }[];
  primaryId?: string;
  captureIds: string[];
};

export function extractRoutingSignals(body: JsonObject, ingress: string): RoutingSignals {
  const data = getObject(body, 'data') ?? body;
  const eventType = ingress === 'invoices'
    ? `invoice.${getString(body, 'status') ?? 'unknown'}`
    : getString(body, 'event', 'event_type', 'type') ?? `${ingress}.unknown`;
  const payment = getObject(data, 'payment') ?? data;
  const resourceIds: RoutingSignals['resourceIds'] = [];

  const candidates: [string, string | undefined][] = [
    ['payment', getString(payment, 'payment_id') ?? getString(data, 'payment_id')],
    ['payment_request', getString(payment, 'payment_request_id') ?? getString(data, 'payment_request_id')],
    ['payment_session', getString(data, 'payment_session_id')],
    ['refund', getString(data, 'refund_id') ?? (ingress === 'refunds' ? getString(data, 'id') : undefined)],
    ['invoice', getString(data, 'invoice_id') ?? (ingress === 'invoices' ? getString(data, 'id') : undefined)],
    ['payment_token', getString(data, 'payment_token_id')],
  ];
  for (const [type, id] of candidates) {
    if (id && !resourceIds.some((entry) => entry.type === type && entry.id === id)) {
      resourceIds.push({ type, id });
    }
  }

  const captures = data['captures'] ?? payment['captures'];
  const captureIds = Array.isArray(captures)
    ? captures.flatMap((capture) => {
      if (capture !== null && typeof capture === 'object' && !Array.isArray(capture)) {
        const id = getString(capture, 'capture_id');
        return id ? [id] : [];
      }
      return [];
    })
    : [];
  const primaryId = eventType.startsWith('refund.')
    ? resourceIds.find((entry) => entry.type === 'refund')?.id
    : eventType.startsWith('payment_session.')
      ? resourceIds.find((entry) => entry.type === 'payment_session')?.id
      : eventType.startsWith('payment_request.')
        ? resourceIds.find((entry) => entry.type === 'payment_request')?.id
        : eventType.startsWith('payment_token.')
          ? resourceIds.find((entry) => entry.type === 'payment_token')?.id
          : eventType.startsWith('invoice.')
            ? resourceIds.find((entry) => entry.type === 'invoice')?.id
            : resourceIds.find((entry) => entry.type === 'payment')?.id;

  return {
    eventType,
    resourceIds,
    captureIds,
    ...(primaryId ? { primaryId } : {}),
    ...(getString(data, 'business_id') ?? getString(body, 'business_id') ?? (ingress === 'invoices' ? getString(body, 'user_id') : undefined)
      ? { businessId: getString(data, 'business_id') ?? getString(body, 'business_id') ?? getString(body, 'user_id') }
      : {}),
    ...(getString(payment, 'reference_id', 'external_id') ?? getString(data, 'reference_id', 'external_id')
      ? { referenceId: getString(payment, 'reference_id', 'external_id') ?? getString(data, 'reference_id', 'external_id') }
      : {}),
  } as RoutingSignals;
}
