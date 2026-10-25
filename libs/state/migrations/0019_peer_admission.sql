-- Device admission (rustdesk docs/design-device-admission.md): 0 pending, 1 admitted, 2 rejected.
-- Existing devices are admitted; hbbs inserts new devices as pending while DEVICE_ADMISSION=Y.
ALTER TABLE peer ADD COLUMN admission smallint NOT NULL DEFAULT 1;
-- The last decision: when, and by whom (admin user name, "cli", or "rule:<name>" in phase 2).
ALTER TABLE peer ADD COLUMN admission_at text;
ALTER TABLE peer ADD COLUMN admission_by text;
CREATE INDEX index_peer_admission ON peer (admission);
