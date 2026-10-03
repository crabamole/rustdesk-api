-- Viewer user of a connection, resolved from hbbs's conn_audit_ref (audit-api-spec §11).
ALTER TABLE audit_conn ADD COLUMN "user" bytea;
ALTER TABLE audit_file ADD COLUMN "user" bytea;
CREATE INDEX index_audit_conn_user ON audit_conn ("user");

CREATE TABLE audit_conn_ref (
    ref text PRIMARY KEY NOT NULL,
    "user" bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- File records stored the viewer in remote; Pro and the read API use remote = controlled device.
UPDATE audit_file SET remote = local, local = remote WHERE local IS NOT NULL;
