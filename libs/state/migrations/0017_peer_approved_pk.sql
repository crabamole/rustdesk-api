-- The new key a device's owner approved by logging in on the device; hbbs takes it once
-- (rustdesk docs/design-device-key-change.md).
ALTER TABLE peer ADD COLUMN approved_pk bytea;
