-- Device admission webhook (rustdesk docs/design-device-admission.md §5): the last call per device.
ALTER TABLE peer ADD COLUMN admission_webhook_at text;
ALTER TABLE peer ADD COLUMN admission_webhook_result text;
