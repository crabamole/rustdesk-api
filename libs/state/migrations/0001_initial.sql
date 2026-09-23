-- Initial schema. Owned by sctgdesk-api-server; hbbs only reads/writes table peer.
CREATE TABLE IF NOT EXISTS team (
    guid bytea PRIMARY KEY NOT NULL,
    name varchar(100) NOT NULL,
    email varchar(100) NOT NULL,
    note varchar(300),
    info text NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp,
    updated_at text NOT NULL DEFAULT current_timestamp
);
INSERT INTO team VALUES('\x018f255622f77778a006702ca5c23714','Default','Default',NULL,'{}','2024-04-28 15:32:33','2024-04-28 15:32:33') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS session (
    "id" VARCHAR(100) PRIMARY KEY,
    "ttl_secs" INTEGER NOT NULL,
    "user" bytea NOT NULL,
    info text,
    expiry_at text NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp
);
CREATE TABLE IF NOT EXISTS peer (
    guid bytea PRIMARY KEY NOT NULL,
    id varchar(100) NOT NULL,
    uuid bytea NOT NULL,
    pk bytea NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp,
    "user" bytea,
    status smallint NOT NULL DEFAULT 1,
    note varchar(300),
    region text,
    strategy bytea,
    info text NOT NULL DEFAULT '{}',
    last_online text NOT NULL DEFAULT '2011-11-16 11:55:19'
);
CREATE TABLE IF NOT EXISTS "user" (
    guid bytea PRIMARY KEY NOT NULL,
    name varchar(100) NOT NULL,
    email varchar(100),
    phone char(30),
    password varchar(100) NOT NULL,
    note varchar(300),
    status smallint NOT NULL,
    grp bytea NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp,
    team bytea NOT NULL,
    role smallint NOT NULL,
    info text NOT NULL DEFAULT '{}',
    strategy bytea,
    tfa bytea
);
INSERT INTO "user" VALUES('\x018f2556230179eb91a2cffe5ced4236','admin','admin@example.org',NULL,'$2b$12$.SfrHeV5frv0FQTM8X33OerLMu1YthqJdMP1oqpFUGh7dfgr41iGG','',1,'\x018f255622fb73ee9afdbbcdc0cc387b','2024-04-28 15:32:33','\x018f255622f77778a006702ca5c23714',1,'{"email_alarm_notification":true}',NULL,NULL) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS "ab_legacy" (
    "user_guid" bytea NOT NULL,
    "ab" text NOT NULL,
    FOREIGN KEY("user_guid") REFERENCES "user"("guid"),
    PRIMARY KEY("user_guid")
);
CREATE TABLE IF NOT EXISTS grp (
    guid bytea PRIMARY KEY NOT NULL,
    team bytea NOT NULL,
    name varchar(100) NOT NULL,
    note varchar(300),
    created_at text NOT NULL DEFAULT current_timestamp,
    info text NOT NULL DEFAULT '{}'
);
INSERT INTO grp VALUES('\x018f255622fb73ee9afdbbcdc0cc387b','\x018f255622f77778a006702ca5c23714','Default',NULL,'2024-04-28 15:32:33','{}') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS user_data (
    "user" bytea NOT NULL,
    type varchar(30) NOT NULL,
    data text NOT NULL,
    updated_at text NOT NULL,
    PRIMARY KEY("user", type)
);
CREATE TABLE IF NOT EXISTS audit_conn (
    guid bytea PRIMARY KEY NOT NULL,
    type smallint,
    remote bytea NOT NULL,
    local bytea,
    created_at text NOT NULL DEFAULT current_timestamp,
    end_time text,
    note text,
    info text NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_file (
    guid bytea PRIMARY KEY NOT NULL,
    remote bytea NOT NULL,
    local bytea,
    created_at text NOT NULL DEFAULT current_timestamp,
    type smallint NOT NULL,
    path text NOT NULL,
    is_file smallint NOT NULL,
    info text NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_alarm (
    guid bytea PRIMARY KEY NOT NULL,
    type smallint NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp,
    info text NOT NULL,
    "user" bytea DEFAULT NULL,
    device bytea DEFAULT NULL
);
CREATE TABLE IF NOT EXISTS audit_console (
    guid bytea PRIMARY KEY NOT NULL,
    type smallint NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp,
    operator bytea NOT NULL,
    iop smallint NOT NULL,
    info text NOT NULL
);
CREATE TABLE IF NOT EXISTS user_third_auth (
    "user" bytea NOT NULL,
    type varchar(30) NOT NULL,
    identifier varchar(255) NOT NULL,
    expiry text,
    info text NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp,
    updated_at text NOT NULL,
    identifier_bak varchar(255) NOT NULL DEFAULT '',
    PRIMARY KEY("user", type)
);
CREATE TABLE IF NOT EXISTS strategy (
    guid bytea PRIMARY KEY NOT NULL,
    team bytea NOT NULL,
    name varchar(100) NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp,
    modified_at text NOT NULL DEFAULT current_timestamp,
    options text NOT NULL DEFAULT '',
    status smallint NOT NULL DEFAULT 0
);
INSERT INTO strategy VALUES('\x018f255623167a02b31c5599e7cd5b5e','\x018f255622f77778a006702ca5c23714','Default','2024-04-28 15:32:33','2024-04-28 15:32:33','{}',0) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS cross_grp (
    incoming bytea NOT NULL,
    outgoing bytea NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp,
    CONSTRAINT constraint_incoming_outgoing PRIMARY KEY (incoming, outgoing)
);
CREATE TABLE IF NOT EXISTS settings (
    key varchar(100) PRIMARY KEY NOT NULL,
    value text NOT NULL
);
CREATE TABLE IF NOT EXISTS "custom_client" (
    "guid" bytea PRIMARY KEY NOT NULL,
    "team" bytea NOT NULL,
    "name" varchar(100) NOT NULL,
    "os" smallint NOT NULL,
    "info" text NOT NULL,
    "status" text,
    "note" varchar(300),
    "created_at" integer NOT NULL DEFAULT extract(epoch from current_timestamp)::integer
);
CREATE TABLE IF NOT EXISTS ab (
    guid bytea PRIMARY KEY NOT NULL,
    name varchar(100) NOT NULL,
    owner bytea NOT NULL,
    personal smallint NOT NULL DEFAULT 0,
    note varchar(300),
    created_at text NOT NULL DEFAULT current_timestamp,
    info text NOT NULL
);
INSERT INTO ab VALUES('\x018f255623117efa9d25470a9160c6d5','admin''s Personal Address Book','\x018f2556230179eb91a2cffe5ced4236',1,NULL,'2024-04-28 15:32:33','{}') ON CONFLICT DO NOTHING;
INSERT INTO ab VALUES('\x018f255623117efa9d25470a9160c6d7','Default''s Shared Address Book','\x018f2556230179eb91a2cffe5ced4236',0,NULL,'2024-04-28 15:32:33','{}') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS ab_peer (
    guid bytea PRIMARY KEY NOT NULL,
    ab bytea NOT NULL,
    peer bytea,
    id text,
    note varchar(300),
    created_at text NOT NULL DEFAULT current_timestamp,
    deleted_at text,
    info text NOT NULL
);
CREATE TABLE IF NOT EXISTS ab_tag (
    ab bytea NOT NULL,
    name varchar(100) NOT NULL,
    color bigint NOT NULL,
    CONSTRAINT constraint_ab_name PRIMARY KEY (ab, name)
);
CREATE TABLE IF NOT EXISTS ab_rule (
    guid bytea PRIMARY KEY NOT NULL,
    ab bytea NOT NULL,
    "user" bytea,
    grp bytea,
    rule smallint NOT NULL,
    created_at text NOT NULL DEFAULT current_timestamp
);
INSERT INTO ab_rule VALUES('\x018f255623117efa9d25470a9160c6d9','\x018f255623117efa9d25470a9160c6d7',NULL,'\x018f255622fb73ee9afdbbcdc0cc387b',3,current_timestamp) ON CONFLICT DO NOTHING;
CREATE UNIQUE INDEX IF NOT EXISTS index_team_name on team (name);
CREATE INDEX IF NOT EXISTS index_session_user on session ("user");
CREATE INDEX IF NOT EXISTS index_session_expiry_at on session (expiry_at);
CREATE UNIQUE INDEX IF NOT EXISTS index_peer_id on peer (id);
CREATE INDEX IF NOT EXISTS index_peer_user on peer ("user");
CREATE INDEX IF NOT EXISTS index_peer_created_at on peer (created_at);
CREATE INDEX IF NOT EXISTS index_peer_status on peer (status);
CREATE UNIQUE INDEX IF NOT EXISTS index_user_name on "user" (name);
CREATE UNIQUE INDEX IF NOT EXISTS index_user_email on "user" (email);
CREATE INDEX IF NOT EXISTS index_user_group on "user" (grp);
CREATE INDEX IF NOT EXISTS index_user_team on "user" (team);
CREATE INDEX IF NOT EXISTS index_user_created_at on "user" (created_at);
CREATE INDEX IF NOT EXISTS index_user_status on "user" (status);
CREATE UNIQUE INDEX IF NOT EXISTS index_grp_name on grp (name);
CREATE INDEX IF NOT EXISTS index_grp_team on grp (team);
CREATE INDEX IF NOT EXISTS index_grp_created_at on grp (created_at);
CREATE INDEX IF NOT EXISTS index_user_data_user on user_data ("user");
CREATE INDEX IF NOT EXISTS index_user_data_type on user_data (type);
CREATE INDEX IF NOT EXISTS index_audit_conn_created_at on audit_conn (created_at);
CREATE INDEX IF NOT EXISTS index_audit_conn_remote on audit_conn (remote);
CREATE INDEX IF NOT EXISTS index_audit_conn_type on audit_conn (type);
CREATE INDEX IF NOT EXISTS index_audit_file_created_at on audit_file (created_at);
CREATE INDEX IF NOT EXISTS index_audit_file_remote on audit_file (remote);
CREATE INDEX IF NOT EXISTS index_audit_file_type on audit_file (type);
CREATE INDEX IF NOT EXISTS index_audit_alarm_created_at on audit_alarm (created_at);
CREATE INDEX IF NOT EXISTS index_audit_alarm_type on audit_alarm (type);
CREATE INDEX IF NOT EXISTS index_audit_console_created_at on audit_console (created_at);
CREATE INDEX IF NOT EXISTS index_audit_console_operator on audit_console (operator);
CREATE INDEX IF NOT EXISTS index_audit_console_type on audit_console (type);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_user_third_auth_type_identifer on user_third_auth (type, identifier);
CREATE INDEX IF NOT EXISTS index_strategy_name on strategy (name);
CREATE INDEX IF NOT EXISTS index_strategy_team on strategy (team);
CREATE INDEX IF NOT EXISTS index_cross_grp_incoming on cross_grp (incoming);
CREATE INDEX IF NOT EXISTS index_cross_grp_outgoing on cross_grp (outgoing);
CREATE INDEX IF NOT EXISTS index_user_strategy ON "user" (strategy);
CREATE INDEX IF NOT EXISTS index_peer_strategy ON peer (strategy);
CREATE INDEX IF NOT EXISTS index_audit_alarm_user ON audit_alarm ("user");
CREATE INDEX IF NOT EXISTS index_audit_alarm_device ON audit_alarm (device);
CREATE UNIQUE INDEX IF NOT EXISTS "uniq_custom_client_name" on "custom_client" ("team", "name");
CREATE INDEX IF NOT EXISTS "index_custom_client_created_at" on "custom_client" ("created_at");
CREATE UNIQUE INDEX IF NOT EXISTS index_ab_name on ab (name);
CREATE INDEX IF NOT EXISTS index_ab_owner on ab (owner);
CREATE INDEX IF NOT EXISTS index_ab_personal_created_at on ab (personal, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS index_ab_peer_ab_peer on ab_peer (ab, peer);
CREATE UNIQUE INDEX IF NOT EXISTS index_ab_peer_ab_id on ab_peer (ab, id);
CREATE INDEX IF NOT EXISTS index_ab_peer_peer on ab_peer (peer);
CREATE INDEX IF NOT EXISTS index_ab_peer_ab_created_at on ab_peer (ab, created_at);
CREATE INDEX IF NOT EXISTS index_ab_peer_ab_deleted_at on ab_peer (ab, deleted_at);
CREATE INDEX IF NOT EXISTS index_ab_rule_user on ab_rule ("user");
CREATE INDEX IF NOT EXISTS index_ab_rule_grp on ab_rule (grp);
CREATE INDEX IF NOT EXISTS index_ab_rule_ab_created_at on ab_rule (ab, created_at)
