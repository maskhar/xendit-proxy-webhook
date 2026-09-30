# Tenant integration contract (Test Mode first)

Only gateway operations below are intended for tenant applications. All requests use `Authorization: Bearer <gateway-tenant-key>` issued for exact tenant and `APP_ENV`; never send Xendit secret key to tenant. Mutation calls require stable `Idempotency-Key` (8–255 characters); reuse same key and same body when repeating *identical* intent, not another key after timeout. Keep operation ID in order database. Different body for same key conflicts. Configure allowed currency/channel/return URL hosts per tenant; tenant cannot choose webhook destination in API call. Do not use request `metadata` as routing key or expect it in callback; gateway routes through reserved provider reference and exact resource mappings.

## Available routes and payloads

- `POST /v1/payment-requests`: provider `POST /v3/payment_requests` with `api-version: 2024-11-11`. Gateway allowlist accepts `reference_id`, `type: PAY | REUSABLE_PAYMENT_CODE`, `country`, `currency`, `request_amount` (required for `PAY`), **required `channel_code`** and allowed `channel_properties`, plus limited policy fields. `PAY_AND_SAVE`, `payment_token_id`, inline customer/card data and arbitrary provider fields are **not supported**. Tenant channel allowlist must be populated before use; empty list rejects all channels. Payment methods and exact channel properties vary by Xendit account/channel; check current [provider schema](https://docs.xendit.co/apidocs/create-payment-request) and tests before using any channel. No raw passthrough.
- `GET /v1/payment-requests/:id`: requires `payment:read` and existing tenant mapping. `POST /v1/payment-requests/:id/cancel`: `payment:cancel` + idempotency key; check whether current provider/channel permits cancel. No payment or refund is inferred merely from cancel response.
- `POST /v1/payment-sessions`: provider `POST /sessions`. Current allowlist supports `session_type: PAY`, `mode: PAYMENT_LINK` only, with `reference_id`, `amount`, `currency`, optional approved `success_return_url`/`cancel_return_url`, and optional existing `customer_id`. Inline `customer` data is not supported. `GET /v1/payment-sessions/:id` requires `session:read`. Session `COMPLETED` describes checkout lifecycle; corroborate underlying Payment event/status for transaction outcome.
- `POST /v1/refunds`: provider `POST /refunds`. Gateway requires `refund:create` plus exact owned `payment_request_id`, `payment_id`, `amount`, `currency` and `reason`; valid reason set is `FRAUDULENT`, `DUPLICATE`, `REQUESTED_BY_CUSTOMER`, `CANCELLATION`, `OTHERS`. `payment_id` is used locally for ownership/captured-amount/ceiling validation and stripped before provider POST because Xendit's request schema targets `payment_request_id`. For safety, gateway currently permits refunds only for a gateway-created one-off `PAY` request with exactly one mapped payment; reusable or imported requests remain blocked until provider-supported target selection is established. Successful provider response must identify the same `payment_id` and `payment_request_id`; otherwise operation/refund remains `UNKNOWN` and returned refund ID is not added as trusted route. Refund callbacks must match stored payment and payment-request identities, and an already terminal local refund is not regressed by an out-of-order callback. Gateway exposes no amount-omission shortcut for full refunds: send explicit amount/currency. Captured payment mapping must already contain matching request, amount and currency. Pending/unknown refunds count against ceiling until resolved. Do not assume all channels accept partial refunds or that Xendit response means refund completed. `GET /v1/refunds/:id` requires `refund:read` and returns locally recorded state, not a fresh provider query.
- `GET /v1/operations/:id`: returns operation status (requires corresponding read scope); `RESERVED`, `IN_FLIGHT`, `SUCCEEDED`, `FAILED`, `UNKNOWN`. Persist operation ID and monitor `UNKNOWN` until reconciled. Gateway responses contain `operation_id`, `kind`, `status`, timestamps and optional provider response; they are **not** a transparent Xendit response.

Examples below are **illustrative**, use fake identifiers, and require tenant policy/channel support before execution.

```sh
# Payment Request v3. Substitute a channel and its valid properties for account/country.
curl -X POST 'https://xendit-test.example.com/v1/payment-requests' \
  -H 'Authorization: Bearer <tenant-gateway-key>' \
  -H 'Idempotency-Key: order-123-pr-1' -H 'Content-Type: application/json' \
  --data '{"reference_id":"order-123","type":"PAY","country":"ID","currency":"IDR","request_amount":10000,"channel_code":"<activated-channel>","channel_properties":{}}'

# Hosted Payment Session. Return domains must be allowlisted for tenant.
curl -X POST 'https://xendit-test.example.com/v1/payment-sessions' \
  -H 'Authorization: Bearer <tenant-gateway-key>' \
  -H 'Idempotency-Key: order-124-session-1' -H 'Content-Type: application/json' \
  --data '{"reference_id":"order-124","session_type":"PAY","mode":"PAYMENT_LINK","amount":10000,"country":"ID","currency":"IDR","success_return_url":"https://store.example.com/paid","cancel_return_url":"https://store.example.com/cancelled"}'

# Refund captured payment after ownership and original amount are recorded.
curl -X POST 'https://xendit-test.example.com/v1/refunds' \
  -H 'Authorization: Bearer <refund-enabled-tenant-key>' \
  -H 'Idempotency-Key: order-123-refund-1' -H 'Content-Type: application/json' \
  --data '{"payment_request_id":"pr-example-owned","payment_id":"py-example-owned","amount":5000,"currency":"IDR","reason":"REQUESTED_BY_CUSTOMER"}'

# Query same operation before deciding next action.
curl -H 'Authorization: Bearer <tenant-gateway-key>' \
  'https://xendit-test.example.com/v1/operations/<operation-id>'
```

## Webhook ingress allowlist

| Ingress | Event names accepted for routing |
|---|---|
| `/webhooks/payments` | `payment.capture`, `payment.failure`, `payment.authorization`, `payment.expiry`, `payment_request.expiry`, `payment_token.activation`, `payment_token.failure`, `payment_token.expiry` |
| `/webhooks/sessions` | `payment_session.completed`, `payment_session.expired` |
| `/webhooks/refunds` | `refund.succeeded`, `refund.failed` |
| `/webhooks/invoices` | Invoice body status `PAID` or `EXPIRED`, normalized as `invoice.PAID` / `invoice.EXPIRED` |
| `/webhooks/legacy` | `virtual_account.paid`, `ewallet.capture`, `qr.payment` |

Names outside allowlist are persisted as `QUARANTINED` with no downstream delivery. Payments/Sessions/Refunds require body `business_id`; Invoice requires matching `user_id` (fallback `business_id`). Legacy rejects mismatching ID when present, but exact payload/ID/reference extraction for every legacy product remains unverified until real Test Mode fixtures pass. Event-name allowlist is not provider-account enablement and does not prove each event's semantics.

## Tenant webhook handling

Downstream receives raw Xendit body bytes but **new headers** from gateway. Verify `x-callback-token` against that tenant's independent proxy token; this is not Xendit callback token. Store stable event/resource ID and transaction amount; validate tenant/order ownership, amount, currency and final status before fulfillment. Make consumer idempotent: Xendit itself retries webhook (up to six), and gateway worker can retry after timeout/crash even when receiver processed prior attempt. Never infer final payment from browser return URL alone. `payment.capture` can include capture IDs; reusable Payment Request can contain multiple distinct payment IDs. Dedup by exact event and payment/capture identity, not only request ID.

**Supabase Edge Function:** gateway-to-function requests do not automatically carry a valid Supabase JWT. Configure function authentication explicitly: either use a public function with strict proxy-token validation and restrict deployment/network as appropriate, or require a separate authorization header secret configured by admin in destination extra headers. Do **not** disable auth broadly without compensating verification. Test token rotation and replay handling before switching function URL.

## Legacy invoices are separate

`POST /v2/invoices` created legacy Payment Link/Invoice and emits Invoice `PAID`/`EXPIRED` callbacks. Current gateway has **no tenant-facing legacy Invoice create route**; direct migration to gateway requires a new, separately reviewed adapter if old create flow must continue. New `/sessions` with `mode: PAYMENT_LINK` creates Payment Session with `ACTIVE`/`COMPLETED`/`EXPIRED` and different webhook payload/IDs. Do not mechanically rename Invoice fields/events; redesign per [Xendit migration guide](https://docs.xendit.co/docs/migrate-to-payment-session). Historical invoices still need ID/reference mapping for callbacks until fully settled or expired, even when newly created checkouts move to Sessions.

## Unknown POST and refunds

Timeout or 5xx after Xendit accepted POST can leave operation `UNKNOWN` with no provider resource ID. A process crash after marking operation `IN_FLIGHT` can instead leave it stranded there; `RESERVED` after a failed local pre-provider validation also needs investigation. Gateway does not auto-repeat an `IN_FLIGHT` or `UNKNOWN` POST. Search authorized Xendit Dashboard records and webhook history for unique provider reference, compare business ID, amount, currency and timestamps, import verified resource mapping with admin tooling, then resolve operation per tested admin procedure. If Xendit cannot confirm whether request exists, escalate to support; do not turn a new idempotency key into an automatic retry. Refund eligibility depends on product/channel, account balance and provider policy; refund webhook `succeeded`/`failed` is provider processing status and does not guarantee beneficiary account settlement. Existing transaction/import data without trustworthy captured amount must be reconciled before refund is enabled.

Official references: [payment requests v3](https://docs.xendit.co/apidocs/create-payment-request), [Sessions API](https://docs.xendit.co/apidocs/create-session), [refund](https://docs.xendit.co/apidocs/refund-payment-request), [webhook validation and retries](https://docs.xendit.co/docs/handling-webhooks).
