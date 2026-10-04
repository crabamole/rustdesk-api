-- Machines that logged in through OIDC from a native client; viewers never register with hbbs.
CREATE TABLE viewer_device (
    id text NOT NULL,
    uuid text NOT NULL,
    hostname text NOT NULL DEFAULT '',
    os text NOT NULL DEFAULT '',
    "user" bytea NOT NULL REFERENCES "user" (guid) ON DELETE CASCADE,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_login timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, uuid)
);
CREATE INDEX index_viewer_device_last_seen ON viewer_device (last_seen);
