ALTER TABLE deliveries
  ADD COLUMN replay_start_attempt integer NOT NULL DEFAULT 0
  CHECK (replay_start_attempt >= 0 AND replay_start_attempt <= attempt_count);
