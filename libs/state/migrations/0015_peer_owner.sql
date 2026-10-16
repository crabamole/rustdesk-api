-- Same-user access: the session of the last cRustDesk login on the device that the device signed,
-- and the key that signed it. Logout and the expired-session purge clear it.
ALTER TABLE peer ADD COLUMN owner_session varchar(100) REFERENCES session (id) ON DELETE SET NULL;
ALTER TABLE peer ADD COLUMN owner_pk bytea;
-- Session deletes look up owners through the foreign key.
CREATE INDEX index_peer_owner_session ON peer (owner_session);
