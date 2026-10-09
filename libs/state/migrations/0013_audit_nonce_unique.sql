-- A retried audit record is stored once, also when two api-server pods take it at the same time.
-- Duplicates stored before keep their row but lose the nonce.
UPDATE audit_conn a SET info = (a.info::jsonb || '{"nonce": ""}')::text FROM audit_conn b
 WHERE a.info::jsonb->>'nonce' <> '' AND a.info::jsonb->>'nonce' = b.info::jsonb->>'nonce'
   AND (a.created_at, a.guid) > (b.created_at, b.guid);
UPDATE audit_file a SET info = (a.info::jsonb || '{"nonce": ""}')::text FROM audit_file b
 WHERE a.info::jsonb->>'nonce' <> '' AND a.info::jsonb->>'nonce' = b.info::jsonb->>'nonce'
   AND (a.created_at, a.guid) > (b.created_at, b.guid);
UPDATE audit_alarm a SET info = (a.info::jsonb || '{"nonce": ""}')::text FROM audit_alarm b
 WHERE a.info::jsonb->>'nonce' <> '' AND a.info::jsonb->>'nonce' = b.info::jsonb->>'nonce'
   AND (a.created_at, a.guid) > (b.created_at, b.guid);
CREATE UNIQUE INDEX audit_conn_nonce ON audit_conn ((info::jsonb->>'nonce')) WHERE info::jsonb->>'nonce' <> '';
CREATE UNIQUE INDEX audit_file_nonce ON audit_file ((info::jsonb->>'nonce')) WHERE info::jsonb->>'nonce' <> '';
CREATE UNIQUE INDEX audit_alarm_nonce ON audit_alarm ((info::jsonb->>'nonce')) WHERE info::jsonb->>'nonce' <> '';
