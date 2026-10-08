-- Device lists must not show the UUID that ties an ID to its machine (rustdesk docs/design-audit-authentication.md).
-- Row by row: a malformed info must not stop the server from starting.
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT guid, info FROM peer WHERE info LIKE '%"uuid"%' LOOP
        BEGIN
            UPDATE peer SET info = (r.info::jsonb - 'uuid')::text WHERE guid = r.guid;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE WARNING 'peer %: info is not JSON, left as is', encode(r.guid, 'hex');
        END;
    END LOOP;
END $$;

-- A ref attributes only records of the device it was minted for.
ALTER TABLE audit_conn_ref ADD COLUMN target text NOT NULL DEFAULT '';
