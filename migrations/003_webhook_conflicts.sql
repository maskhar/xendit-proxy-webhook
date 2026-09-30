CREATE TABLE webhook_conflicts (
  id bigserial PRIMARY KEY,
  webhook_event_id uuid NOT NULL REFERENCES webhook_events(id) ON DELETE CASCADE,
  environment text NOT NULL CHECK (environment IN ('test', 'live')),
  raw_body bytea NOT NULL,
  parsed_body jsonb NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX webhook_conflicts_event_idx
  ON webhook_conflicts (webhook_event_id, received_at DESC);
