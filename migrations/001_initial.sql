CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  code text NOT NULL UNIQUE CHECK (code ~ '^[a-z0-9]{2,12}$'),
  display_name text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  allowed_currencies text[] NOT NULL DEFAULT ARRAY['IDR']::text[],
  allowed_channels text[] NOT NULL DEFAULT ARRAY[]::text[],
  return_url_hosts text[] NOT NULL DEFAULT ARRAY[]::text[],
  max_refund_amount numeric(24,6),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  label text NOT NULL,
  key_prefix text NOT NULL,
  key_hash bytea NOT NULL UNIQUE CHECK (octet_length(key_hash) = 32),
  scopes text[] NOT NULL,
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, environment, label)
);
CREATE INDEX tenant_api_keys_lookup_idx ON tenant_api_keys (key_prefix, environment)
  WHERE revoked_at IS NULL;

CREATE TABLE destinations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  url text NOT NULL CHECK (url ~ '^https://'),
  enabled boolean NOT NULL DEFAULT false,
  callback_token_ciphertext bytea,
  callback_token_nonce bytea,
  callback_token_tag bytea,
  extra_headers_ciphertext bytea,
  extra_headers_nonce bytea,
  extra_headers_tag bytea,
  max_attempts integer NOT NULL DEFAULT 12 CHECK (max_attempts BETWEEN 1 AND 50),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, environment),
  CHECK (
    NOT enabled OR (
      callback_token_ciphertext IS NOT NULL AND
      callback_token_nonce IS NOT NULL AND octet_length(callback_token_nonce) = 12 AND
      callback_token_tag IS NOT NULL AND octet_length(callback_token_tag) = 16
    )
  )
);

CREATE TABLE operations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  kind text NOT NULL CHECK (kind IN (
    'PAYMENT_REQUEST_CREATE', 'PAYMENT_REQUEST_CANCEL',
    'PAYMENT_SESSION_CREATE', 'LEGACY_INVOICE_CREATE', 'REFUND_CREATE'
  )),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 255),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  request_body jsonb NOT NULL,
  client_reference text,
  provider_reference text,
  status text NOT NULL CHECK (status IN ('RESERVED', 'IN_FLIGHT', 'SUCCEEDED', 'FAILED', 'UNKNOWN')),
  provider_resource_type text,
  provider_resource_id text,
  provider_http_status integer,
  response_body jsonb,
  error_code text,
  error_detail text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, environment, kind, idempotency_key),
  UNIQUE (environment, provider_reference)
);
CREATE INDEX operations_tenant_idx ON operations (tenant_id, environment, created_at DESC);
CREATE INDEX operations_unknown_idx ON operations (environment, updated_at)
  WHERE status = 'UNKNOWN';

CREATE TABLE reference_routes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  provider text NOT NULL DEFAULT 'xendit',
  reference_value text NOT NULL,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  operation_id uuid REFERENCES operations(id) ON DELETE SET NULL,
  source text NOT NULL CHECK (source IN ('GATEWAY', 'IMPORT', 'ADMIN')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (environment, provider, reference_value)
);
CREATE INDEX reference_routes_tenant_idx ON reference_routes (tenant_id, environment);

CREATE TABLE resource_mappings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  provider text NOT NULL DEFAULT 'xendit',
  resource_type text NOT NULL,
  resource_id text NOT NULL,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  operation_id uuid REFERENCES operations(id) ON DELETE SET NULL,
  parent_resource_type text,
  parent_resource_id text,
  source text NOT NULL CHECK (source IN ('API_RESPONSE', 'WEBHOOK', 'IMPORT', 'ADMIN')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (environment, provider, resource_type, resource_id)
);
CREATE INDEX resource_mappings_parent_idx ON resource_mappings (
  environment, provider, parent_resource_type, parent_resource_id
) WHERE parent_resource_id IS NOT NULL;
CREATE INDEX resource_mappings_tenant_idx ON resource_mappings (tenant_id, environment, resource_type);

CREATE TABLE legacy_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  field_path text NOT NULL CHECK (field_path ~ '^[a-zA-Z0-9_.-]+$'),
  pattern text NOT NULL,
  priority integer NOT NULL DEFAULT 100,
  enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (environment, name)
);
CREATE INDEX legacy_rules_active_idx ON legacy_rules (environment, priority, id) WHERE enabled;

CREATE TABLE webhook_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  ingress_path text NOT NULL,
  event_type text NOT NULL,
  dedup_key text NOT NULL,
  weak_dedup boolean NOT NULL DEFAULT false,
  business_id text,
  raw_body bytea NOT NULL,
  parsed_body jsonb NOT NULL,
  headers jsonb NOT NULL DEFAULT '{}'::jsonb,
  tenant_id uuid REFERENCES tenants(id) ON DELETE RESTRICT,
  route_status text NOT NULL CHECK (route_status IN ('ROUTED', 'UNROUTED', 'QUARANTINED')),
  route_reason text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  routed_at timestamptz,
  UNIQUE (environment, event_type, dedup_key)
);
CREATE INDEX webhook_events_unrouted_idx ON webhook_events (environment, received_at)
  WHERE route_status IN ('UNROUTED', 'QUARANTINED');
CREATE INDEX webhook_events_tenant_idx ON webhook_events (tenant_id, environment, received_at DESC);

CREATE TABLE deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_event_id uuid NOT NULL REFERENCES webhook_events(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  destination_id uuid NOT NULL REFERENCES destinations(id) ON DELETE RESTRICT,
  status text NOT NULL CHECK (status IN ('PENDING', 'LEASED', 'RETRY', 'SUCCEEDED', 'DEAD', 'CANCELLED')),
  attempt_count integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_owner text,
  lease_expires_at timestamptz,
  last_http_status integer,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  UNIQUE (webhook_event_id, destination_id)
);
CREATE INDEX deliveries_claim_idx ON deliveries (next_attempt_at, created_at)
  WHERE status IN ('PENDING', 'RETRY');
CREATE INDEX deliveries_expired_lease_idx ON deliveries (lease_expires_at)
  WHERE status = 'LEASED';

CREATE TABLE delivery_attempts (
  id bigserial PRIMARY KEY,
  delivery_id uuid NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  attempt_number integer NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  http_status integer,
  duration_ms integer,
  error text,
  response_excerpt text,
  UNIQUE (delivery_id, attempt_number)
);

CREATE TABLE refunds (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id) ON DELETE RESTRICT,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  payment_id text NOT NULL,
  payment_request_id text,
  provider_refund_id text,
  amount numeric(24,6) NOT NULL CHECK (amount > 0),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  status text NOT NULL CHECK (status IN ('RESERVED', 'PENDING', 'SUCCEEDED', 'FAILED', 'UNKNOWN')),
  reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (environment, provider_refund_id)
);
CREATE INDEX refunds_payment_idx ON refunds (tenant_id, environment, payment_id, status);

CREATE TABLE payment_amounts (
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  payment_id text NOT NULL,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  payment_request_id text,
  amount numeric(24,6) NOT NULL CHECK (amount > 0),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  captured_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (environment, payment_id)
);

CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  actor_type text NOT NULL CHECK (actor_type IN ('TENANT', 'ADMIN', 'SYSTEM')),
  actor_id text,
  action text NOT NULL,
  target_type text,
  target_id text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_created_idx ON audit_log (environment, created_at DESC);

CREATE TABLE worker_heartbeats (
  worker_id text PRIMARY KEY,
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb
);

INSERT INTO tenants (slug, code, display_name, return_url_hosts)
VALUES
  ('placers', 'plc', 'Placers', ARRAY['placers.id', 'api.placers.id']),
  ('epochstream', 'eps', 'Epochstream', ARRAY['epochstream.org']),
  ('katalis', 'kat', 'Katalis', ARRAY['epochstream.org']),
  ('supabase-carubra', 'scb', 'Supabase Carubra', ARRAY['supabase.carubra.com']),
  ('carubra', 'car', 'Carubra', ARRAY['carubra.com'])
ON CONFLICT (slug) DO NOTHING;

INSERT INTO destinations (tenant_id, environment, url, enabled)
SELECT t.id, env.environment, configured.url, false
FROM tenants t
JOIN (VALUES
  ('placers', 'https://api.placers.id/xendit/webhook'),
  ('epochstream', 'https://epochstream.org/wp-json/epochstream/v1/webhook/xendit'),
  ('katalis', 'https://epochstream.org/wp-json/katalis/v1/webhook/xendit'),
  ('supabase-carubra', 'https://supabase.carubra.com/functions/v1/xendit-webhook'),
  ('carubra', 'https://carubra.com/api/v1/xendit-webhook')
) configured(slug, url) ON configured.slug = t.slug
CROSS JOIN (VALUES
  ('test'::text), ('live'::text)
) env(environment)
ON CONFLICT (tenant_id, environment) DO NOTHING;
