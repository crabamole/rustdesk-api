-- Devices echo modified_at back in every heartbeat; epoch milliseconds, compared for equality.
ALTER TABLE strategy ALTER COLUMN modified_at DROP DEFAULT;
ALTER TABLE strategy ALTER COLUMN modified_at TYPE bigint
    USING (extract(epoch FROM modified_at::timestamp) * 1000)::bigint;
ALTER TABLE strategy ALTER COLUMN modified_at SET DEFAULT 0;
UPDATE strategy SET options = '{}' WHERE options = '';
