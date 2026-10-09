-- insert_audit_conn_ref purges rows older than a day on every mint; without this each mint seq-scans.
CREATE INDEX audit_conn_ref_created_at ON audit_conn_ref (created_at);
