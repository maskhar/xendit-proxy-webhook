# Migration and cutover checklist

This is operator checklist, not authorization to change DNS, VPS, tenant code or Xendit Dashboard. Complete in Xendit **Test Mode**, retain old endpoints, obtain explicit approval, then schedule live cutover. Because one dashboard event URL can serve all websites, switching before complete ownership mapping risks sending every callback to wrong/no tenant.

## 1. Inventory before deployment

- List all five current tenants (`placers`, `epochstream`, `katalis`, `supabase-carubra`, `carubra`), actual owners, production domains, current Xendit products, exact dashboard event settings, endpoint URLs, callback auth behavior and payload fixtures. Migration seeds **disabled, unverified candidate URLs** below; compare each with actual application code and owner before enabling:

  | Tenant slug | Seeded disabled downstream URL |
  |---|---|
  | `placers` | `https://api.placers.id/xendit/webhook` |
  | `epochstream` | `https://epochstream.org/wp-json/epochstream/v1/webhook/xendit` |
  | `katalis` | `https://epochstream.org/wp-json/katalis/v1/webhook/xendit` |
  | `supabase-carubra` | `https://supabase.carubra.com/functions/v1/xendit-webhook` |
  | `carubra` | `https://carubra.com/api/v1/xendit-webhook` |

  These are **not** proof of live endpoints or permission to send tests there.
- Inventory every unsettled/historical resource per tenant: Invoice IDs/external IDs, Payment Request IDs/references, Payment/payment/capture IDs, Payment Session IDs, refund IDs, legacy VA/e-wallet channel IDs and any reusable request that may receive future payments. Export source evidence and preserve immutable backup.
- Confirm which legacy callbacks still occur. A regex/prefix rule is allowed only when ownership is exclusive and tested against the full corpus. Shared, empty or ambiguous identifiers must be imported as exact ID/reference mappings or kept on old route; never broadcast.
- Review each downstream handler. It must accept original body bytes and events it uses, verify independent gateway token, deduplicate, validate amount/currency/reference, reject or safely ignore unknown events, and return 2xx only after durable processing. Confirm Supabase JWT/extra header design explicitly.
- Record Xendit Test/Live business IDs, API keys and callback tokens separately. Verify gateway `APP_ENV` equals credential/dashboard environment. Never reuse database, encryption key, tenant API key or domain between Test and Live.

## 2. Prepare Test Mode gateway

1. Create deployment secret files from `.env.example`, keep them outside image/git and back them up securely. Build, migrate and start DB/API/worker without changing dashboard URLs.
2. Review migrations, seeded tenants and disabled destinations. Correct destination URLs, create unique downstream callback token per tenant, add required headers, then keep destination disabled until test receiver is ready. Set **explicit nonempty channel allowlist** per tenant before Payment Request creation; empty list blocks all channels. Issue least-privilege tenant API key: read/create scopes separately; only authorized application gets `refund:create`.
3. Import exact legacy ID/reference mappings through reviewed private admin route. Current admin surface cannot create/manage/dry-run legacy rules or import captured payment amount/currency. Before cutover, add and test those capabilities or use separately reviewed, audited migration/SQL procedure against backups; never improvise against Live. Dry-run every proposed legacy rule across representative and adversarial samples, resolve all collisions/unknown owners/shared prefixes, and import refundable captured amounts only from authoritative records.
4. Run fake/provider Test Mode flows for every supported API/event. Verify body bytes preserved; Xendit token never reaches tenant; duplicate callback makes one delivery; reusable request sends each unique payment once; webhook-before-API-response maps later; unknown/conflicting event stays `UNROUTED`/`QUARANTINED`; worker retries/dead-letter/replay; tenant isolation; refund ownership/ceiling; timeout/5xx becomes `UNKNOWN` with no POST retry.
5. Enable one Test Mode destination at a time, send controlled callbacks and verify receiver state. Disable it again on mismatch. No test should send an actual webhook to a live endpoint without owner approval.

## 3. Webhook URL migration

Xendit settings may have separate URL fields per event/product. Confirm actual Dashboard names and available Test/Live separation; do not assume one universal URL. Intended gateway categories, only after corresponding handler is implemented and verified:

| Category | Candidate gateway URL | Expected events requiring fixture verification |
|---|---|---|
| Payments v3 | `/webhooks/payments` | `payment.capture`, `payment.authorization`, `payment.failure`, `payment.expiry`, `payment_request.expiry`, `payment_token.activation/failure/expiry` only where account emits them |
| Payment Session | `/webhooks/sessions` | `payment_session.completed`, `payment_session.expired` |
| Legacy Invoice v2 | `/webhooks/invoices` | Invoice `PAID`, `EXPIRED` payloads, not v3 payloads |
| Refund | `/webhooks/refunds` | `refund.succeeded`, `refund.failed` |
| Legacy channel-specific | `/webhooks/legacy` only after exact extractor/fixture verification | VA/e-wallet and other existing transactions only |

Ingress routes parse generic JSON and routing IDs, then quarantine event names outside explicit per-route allowlist; route presence is **not** an event-support guarantee. Invoice additionally requires `user_id` (or fallback `business_id`) matching configured Xendit business. For each enabled Dashboard event, prove expected event name, ID/reference extraction, dedup key and tenant resolution from real Test Mode fixture. Unverified event stays off gateway.

For each actual event setting:

1. Verify all historical mappings and all five destinations **before** first shared URL change. Take screenshots/export of old URL, callback token and recent event history; prepare exact rollback value.
2. Put gateway monitoring on screen: DB/readiness, worker heartbeat, ingress count, invalid token/business mismatch, `UNROUTED`, `QUARANTINED`, delivery retry/dead count and downstream response latency. Confirm backup completed.
3. Change **Test Mode** event URL only. Send provider-generated fixture, then verify Xendit 2xx, persisted raw event, correct one-tenant route, downstream 2xx and business state. Use dashboard resend to prove duplicate safety.
4. Repeat category by category. Do not switch next category while any event is unknown, conflicting, dead or unsupported.
5. After acceptance and separate approval, repeat controlled sequence in Live during low traffic. Observe longer than Xendit retry window and each product's settlement lifecycle. Keep legacy application endpoints available until no outstanding transactions can callback.

### Immediate rollback triggers

Rollback that event URL to recorded old endpoint if gateway readiness fails, authentication rejects valid Xendit callback, route conflicts/unknown spikes, wrong tenant receives event, downstream cannot process exact payload, raw body differs, latency risks provider timeout, DB persistence fails or monitoring/worker unavailable. Do not broadcast backlog. Preserve gateway events and logs, stop replay, identify affected IDs, reconcile provider/dashboard against each tenant, then retry migration only after root cause and tests.

## 4. API migration per website

Webhook routing for old transactions must work **before** moving create calls. Then migrate gateway API tenant by tenant; these API changes do not need simultaneous five-site cutover.

1. Issue Test Mode tenant key/scopes and store it in website secret manager. Never share key across websites. Add stable idempotency key tied to business intent and persist `operation_id`.
2. Test allowlisted Payment Request or Payment Session payload, return URLs and channel policy. Verify successful, failed, expired, user-cancelled, delayed and duplicate flows. Browser redirect is not payment confirmation.
3. For legacy Invoice-to-Session migration, implement new request/response and webhooks as new model; continue routing old Invoice callbacks. Do not claim `/v2/invoices` and `/sessions` equivalent.
4. Test timeout/unknown handling: query operation, stop automatic duplicate order/payment, reconcile manually. Train support/operator runbook.
5. Promote one tenant with approval, monitor, then repeat. Preserve ability to restore website create calls while gateway still routes transactions already created through it.

## 5. Add two future tenants

Do not reuse placeholder tenants. Current private admin API can list and configure seeded tenants but **cannot create tenants**; adding two requires a new reviewed, tested tenant-creation procedure (or separately audited migration/SQL with backup) before issuing credentials. For each new tenant, create unique slug/code, environment-specific API key/scopes and currency/channel/return URL policy; configure HTTPS public destination after SSRF/DNS review; set unique encrypted proxy token and any Supabase header; keep disabled; import verified historical IDs/references; dry-run any proposed legacy rules against complete corpus using separately reviewed tooling (admin rule management/dry-run is not implemented); test callback/idempotency/refund isolation in Test Mode; enable destination; then migrate API. Import of captured payment amounts and resolution of `UNKNOWN` operations also lack admin routes; complete separately reviewed reconciliation procedures before relying on those functions. Shared domain/path or prefix is not proof of ownership.

## Acceptance evidence required for live readiness review

- Build/typecheck/test results and image digest; `docker compose config`; migration/rollback rehearsal.
- Exact Test Mode request/response and raw webhook fixtures for every enabled product/event.
- Five tenant plus future tenant ownership matrix, conflict-free import counts and quarantine review.
- Per-destination authentication/idempotency evidence, including Supabase authorization decision.
- `UNKNOWN`, refund, replay/dead-letter and rollback exercises.
- Database + encryption-key backup/restore test, RPO/RTO, monitoring/alert ownership.
- DNS/TLS/firewall/VPS review and approved dashboard change record.

Until evidence exists, deployment remains candidate only, not live ready.
