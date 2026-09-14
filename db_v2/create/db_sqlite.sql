CREATE TABLE IF NOT EXISTS team (
                                    guid blob primary key not null,
                                    name varchar(100) not null,
                                    email varchar(100) not null,
                                    note varchar(300),
                                    info text not null,
                                    created_at text not null default(current_timestamp),
                                    updated_at text not null default(current_timestamp)
) without rowid;
INSERT OR IGNORE INTO team VALUES(X'018f255622f77778a006702ca5c23714','Default','Default',NULL,'{}','2024-04-28 15:32:33','2024-04-28 15:32:33');
CREATE TABLE IF NOT EXISTS session (
                                    "id" VARCHAR(100) PRIMARY KEY,
                                    "ttl_secs" INTEGER NOT NULL,
                                    "user" blob not null,
                                    info text,
                                    expiry_at text not null,
                                    created_at text not null default(current_timestamp)
) without rowid;
INSERT OR IGNORE INTO session VALUES('YFMotxzHT7qxoorhyNy/bA==',2592000,X'018f2556230179eb91a2cffe5ced4236','{"ip":"::ffff:192.168.65.1","device_uuid":"RTlENEQxQ0UtMkY5Mi01ODg2LUE4QzEtMkQ4QjRFOEMwNDUz","os":"macos","type":"client","name":"blingster"}','2024-05-28 15:32:52','2024-04-28 15:32:52');
CREATE TABLE IF NOT EXISTS peer (
                                    guid blob primary key not null,
                                    id varchar(100) not null,
                                    uuid blob not null,
                                    pk blob not null,
                                    created_at text not null default(current_timestamp),
                                    "user" blob,
                                    status tinyint not null default(1),
                                    note varchar(300),
                                    region text null,
                                    strategy blob,
                                    info JSON not null DEFAULT '{}', "last_online" text not null default('2011-11-16 11:55:19')) without rowid;
CREATE TABLE IF NOT EXISTS "user" (
                                    guid blob primary key not null,
                                    name varchar(100) not null,
                                    email varchar(100),
                                    phone char(30),
                                    password varchar(100) not null,
                                    note varchar(300),
                                    status tinyint not null,
                                    grp blob not null,
                                    created_at text not null default(current_timestamp),
                                    team blob not null,
                                    role tinyint not null,
                                    info JSON not null DEFAULT '{}', strategy blob, "tfa" blob null) without rowid;
INSERT OR IGNORE INTO user VALUES(X'018f2556230179eb91a2cffe5ced4236','admin','admin@example.org',NULL,'$2b$12$.SfrHeV5frv0FQTM8X33OerLMu1YthqJdMP1oqpFUGh7dfgr41iGG','',1,X'018f255622fb73ee9afdbbcdc0cc387b','2024-04-28 15:32:33',X'018f255622f77778a006702ca5c23714',1,'{"email_alarm_notification":true}',NULL,NULL);
CREATE TABLE IF NOT EXISTS "ab_legacy" (
                "user_guid"	BLOB NOT NULL,
                "ab"	JSON NOT NULL,
                FOREIGN KEY("user_guid") REFERENCES "user"("guid"),
                PRIMARY KEY("user_guid")
            );
CREATE TABLE IF NOT EXISTS grp (
                                    guid blob primary key not null,
                                    team blob not null,
                                    name varchar(100) not null,
                                    note varchar(300),
                                    created_at text not null default(current_timestamp),
                                    "info" text not null default '{}') without rowid;
INSERT OR IGNORE INTO grp VALUES(X'018f255622fb73ee9afdbbcdc0cc387b',X'018f255622f77778a006702ca5c23714','Default',NULL,'2024-04-28 15:32:33','{}');
CREATE TABLE IF NOT EXISTS user_data (
                                    "user" blob not null,
                                    type varchar(30) not null,
                                    data text not null,
                                    updated_at text not null,
                                    primary key("user", type)
) without rowid;
CREATE TABLE IF NOT EXISTS audit_conn (
                                    guid blob primary key not null,
                                    type tinyint,
                                    remote blob not null,
                                    local blob,
                                    created_at text not null default(strftime('%Y-%m-%d %H:%M:%f', 'now')),
                                    end_time text,
                                    note text,
                                    info text not null
);
CREATE TABLE IF NOT EXISTS audit_file (
                                    guid blob primary key not null,
                                    remote blob not null,
                                    local blob,
                                    created_at text not null default(strftime('%Y-%m-%d %H:%M:%f', 'now')),
                                    type tinyint not null,
                                    path text not null,
                                    is_file tinyint not null,
                                    info text not null
);
CREATE TABLE IF NOT EXISTS audit_alarm (
                                    guid blob primary key not null,
                                    type tinyint not null,
                                    created_at text not null default(strftime('%Y-%m-%d %H:%M:%f', 'now')),
                                    info text not null,
                                    user blob DEFAULT NULL, device blob DEFAULT NULL);
CREATE TABLE IF NOT EXISTS audit_console (
                                    guid blob primary key not null,
                                    type tinyint not null,
                                    created_at text not null default(strftime('%Y-%m-%d %H:%M:%f', 'now')),
                                    operator blob not null,
                                    iop smallint not null,
                                    info text not null
);
CREATE TABLE IF NOT EXISTS user_third_auth (
                                    "user" blob not null,
                                    type varchar(30) not null,
                                    identifier varchar(255) not null,
                                    expiry timestamp,
                                    info text not null,
                                    created_at text not null default(current_timestamp),
                                    updated_at text not null, "identifier_bak" varchar(255) not null default '',
                                    primary key("user", type)
) without rowid;
CREATE TABLE IF NOT EXISTS strategy (
                                    guid blob primary key not null,
                                    team blob not null,
                                    name varchar(100) not null,
                                    created_at text not null default(current_timestamp),
                                    modified_at text not null default(current_timestamp),
                                    options text not null default '',
                                    status tinyint not null default 0
) without rowid;
INSERT OR IGNORE INTO strategy VALUES(X'018f255623167a02b31c5599e7cd5b5e',X'018f255622f77778a006702ca5c23714','Default','2024-04-28 15:32:33','2024-04-28 15:32:33','{}',0);
CREATE TABLE IF NOT EXISTS cross_grp (
    incoming blob not null,
    outgoing blob not null,
    created_at text not null default(current_timestamp),
    CONSTRAINT constraint_incoming_outgoing PRIMARY KEY (incoming, outgoing)
) without rowid;
CREATE TABLE IF NOT EXISTS settings (
    key varchar(100) primary key not null,
    value text not null
) without rowid;
CREATE TABLE IF NOT EXISTS "custom_client" (
                                    "guid" blob primary key not null,
                                    "team" blob not null,
                                    "name" varchar(100) not null,
                                    "os" tinyint not null,
                                    "info" JSON not null,
                                    "status" JSON,
                                    "note" varchar(300),
                                    "created_at" integer not null default(current_timestamp)
);
CREATE TABLE IF NOT EXISTS ab (
                                    guid blob primary key not null,
                                    name varchar(100) not null,
                                    owner blob not null,
                                    personal tinyint not null default 0,
                                    note varchar(300),
                                    created_at text not null default(current_timestamp),
                                    info text not null
) without rowid;
INSERT OR IGNORE INTO ab VALUES(X'018f255623117efa9d25470a9160c6d5','admin''s Personal Address Book',X'018f2556230179eb91a2cffe5ced4236',1,NULL,'2024-04-28 15:32:33','{}');
INSERT OR IGNORE INTO ab VALUES(X'018f255623117efa9d25470a9160c6d7','Default''s Shared Address Book',X'018f2556230179eb91a2cffe5ced4236',0,NULL,'2024-04-28 15:32:33','{}');
CREATE TABLE IF NOT EXISTS ab_peer (
                                    guid blob primary key not null,
                                    ab blob not null,
                                    peer blob,
                                    id text,
                                    note varchar(300),
                                    created_at text not null default(current_timestamp),
                                    deleted_at text,
                                    info text not null
) without rowid;
CREATE TABLE IF NOT EXISTS ab_tag (
                                    ab blob not null,
                                    name varchar(100) not null,
                                    color INTEGER not null,
                                    CONSTRAINT constraint_ab_name PRIMARY KEY (ab, name)
) without rowid;
CREATE TABLE IF NOT EXISTS ab_rule (
                                    guid blob primary key not null,
                                    ab blob not null,
                                    "user" blob,
                                    grp blob,
                                    rule tinyint not null,
                                    created_at text not null default(current_timestamp)
) without rowid;
INSERT OR IGNORE INTO ab_rule VALUES(X'018f255623117efa9d25470a9160c6d9',X'018f255623117efa9d25470a9160c6d7',NULL,X'018f255622fb73ee9afdbbcdc0cc387b',3,current_timestamp);
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
CREATE INDEX IF NOT EXISTS index_user_strategy ON user (strategy);
CREATE INDEX IF NOT EXISTS index_peer_strategy ON peer (strategy);
CREATE INDEX IF NOT EXISTS index_audit_alarm_user ON audit_alarm (user);
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
