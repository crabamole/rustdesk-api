-- Databases created from the legacy db.sql schema declare grp.created_at as
-- datetime, which the sqlx Any driver cannot decode. Rebuild grp with the
-- text column used by db_sqlite.sql. The first CREATE is a no-op when grp
-- exists and keeps the RENAME from failing when it does not.
CREATE TABLE IF NOT EXISTS grp (
                                    guid blob primary key not null,
                                    team blob not null,
                                    name varchar(100) not null,
                                    note varchar(300),
                                    created_at text not null default(current_timestamp),
                                    "info" text not null default '{}') without rowid;
ALTER TABLE grp RENAME TO grp_old;
CREATE TABLE grp (
                                    guid blob primary key not null,
                                    team blob not null,
                                    name varchar(100) not null,
                                    note varchar(300),
                                    created_at text not null default(current_timestamp),
                                    "info" text not null default '{}') without rowid;
INSERT INTO grp(guid, team, name, note, created_at, "info")
    SELECT guid, team, name, note, created_at, "info" FROM grp_old;
DROP TABLE grp_old;
CREATE UNIQUE INDEX IF NOT EXISTS index_grp_name on grp (name);
CREATE INDEX IF NOT EXISTS index_grp_team on grp (team);
CREATE INDEX IF NOT EXISTS index_grp_created_at on grp (created_at);
