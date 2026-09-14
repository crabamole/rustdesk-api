ALTER TABLE peer RENAME TO peer_old;
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
                                    info JSON not null DEFAULT '{}',
                                    "last_online" text not null default('2011-11-16 11:55:19')
                                ) without rowid;
INSERT INTO peer(guid, id, uuid, pk, created_at, "user", status, note, region, strategy, info, last_online)
    SELECT guid, id, uuid, pk, created_at, "user", status, note, region, strategy, info, last_online FROM peer_old;
DROP TABLE peer_old;
CREATE UNIQUE INDEX IF NOT EXISTS index_peer_id on peer (id);
CREATE INDEX IF NOT EXISTS index_peer_user on peer ("user");
CREATE INDEX IF NOT EXISTS index_peer_created_at on peer (created_at);
CREATE INDEX IF NOT EXISTS index_peer_status on peer (status);
CREATE INDEX IF NOT EXISTS index_peer_strategy ON peer (strategy);
