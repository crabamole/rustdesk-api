-- Viewer clipboard text that arrived on a device (rustdesk docs/design-clipboard-monitoring.md).
CREATE TABLE audit_clipboard (
    guid bytea PRIMARY KEY NOT NULL,
    remote bytea NOT NULL,
    local bytea,
    created_at text NOT NULL DEFAULT current_timestamp,
    type smallint NOT NULL,
    format text NOT NULL,
    size bigint NOT NULL,
    info text NOT NULL,
    "user" bytea
);
CREATE INDEX index_audit_clipboard_created_at ON audit_clipboard (created_at);
CREATE INDEX index_audit_clipboard_remote ON audit_clipboard (remote);
CREATE UNIQUE INDEX audit_clipboard_nonce ON audit_clipboard ((info::jsonb->>'nonce')) WHERE info::jsonb->>'nonce' <> '';
