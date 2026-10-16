-- A console disconnect marks the connection; the device's heartbeat answer then names it.
ALTER TABLE audit_conn ADD COLUMN disconnect_at timestamptz;
-- Console log rows written by the CLI have no operator.
ALTER TABLE audit_console ALTER COLUMN operator DROP NOT NULL;
