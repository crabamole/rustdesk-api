-- hbbs presence (rustdesk docs/design-multi-replica.md); owned here, hbbs only reads and writes it.
CREATE UNLOGGED TABLE hbbs_pod (
  pod      text PRIMARY KEY,           -- StatefulSet pod name, e.g. rustdesk-hbbs-0
  addr     text NOT NULL,              -- host:port of the pod's internal port (pod IP:21120)
  epoch    uuid NOT NULL,              -- new per process start
  alive_at timestamptz NOT NULL
);
CREATE UNLOGGED TABLE peer_presence (
  id    text PRIMARY KEY,              -- RustDesk device ID
  pod   text NOT NULL,
  epoch uuid NOT NULL,
  gen   bigint NOT NULL,               -- per-process registration counter (WS_PEER_GENERATION)
  since timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX peer_presence_pod ON peer_presence (pod, epoch);
