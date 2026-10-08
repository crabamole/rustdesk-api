-- One row per OIDC login that reached the callback (rustdesk docs/design-login-audit.md).
CREATE TABLE audit_login (
    guid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now(),
    outcome text NOT NULL,
    detail text NOT NULL DEFAULT '',
    client text NOT NULL,
    "user" bytea REFERENCES "user" (guid) ON DELETE SET NULL,
    user_name text NOT NULL DEFAULT '',
    rustdesk_id text NOT NULL DEFAULT '',
    hostname text NOT NULL DEFAULT '',
    os text NOT NULL DEFAULT '',
    ip text NOT NULL DEFAULT ''
);
CREATE INDEX index_audit_login_created_at ON audit_login (created_at);
CREATE INDEX index_audit_login_user ON audit_login ("user");
