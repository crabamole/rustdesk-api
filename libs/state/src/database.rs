// Copyright (c) 2024 Ronan LE MEILLAT for SCTG Development
//
// This file is part of the SCTGDesk project.
//
// SCTGDesk is free software: you can redistribute it and/or modify
// it under the terms of the Affero General Public License version 3 as
// published by the Free Software Foundation.
//
// SCTGDesk is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// Affero General Public License for more details.
//
// You should have received a copy of the Affero General Public License
// along with SCTGDesk. If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.
use crate::types;
use crate::UserId;
use sqlx::{
    postgres::{PgConnection, PgPool, PgPoolOptions},
    Connection, Row,
};
use std::collections::BTreeMap;
use std::env;
use std::time::Duration;
use utils::guid_into_uuid;
use utils::types::AddressBook;
use utils::AbPeer;
use utils::AbRule;
use utils::AbTag;
use utils::CpuCount;
use utils::Group;
use utils::Peer;
use utils::Platform;
use utils::StrategySummary;
use utils::UpdateUserRequest;
use utils::UserListResponse;

use base64::prelude::{Engine as _, BASE64_STANDARD};

use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

#[cfg(any(test, feature = "test-util"))]
pub(crate) struct AuditConnRow {
    pub conn_type: Option<i16>,
    pub local: Option<Vec<u8>>,
    pub end_time: Option<String>,
    pub info: String,
    pub note: Option<String>,
}

#[cfg(test)]
pub(crate) struct AuditFileRow {
    pub remote: Vec<u8>,
    pub local: Option<Vec<u8>>,
    pub user: Option<Vec<u8>>,
    pub info: String,
}

#[cfg(test)]
pub(crate) struct AuditAlarmRow {
    pub user: Option<Vec<u8>>,
    pub info: String,
}

#[cfg(any(test, feature = "test-util"))]
pub struct DatabaseConnection {
    pool: PgPool,
}

pub struct DatabaseUserInfo {
    pub active: bool,
    pub admin: bool,
}

#[cfg(any(test, feature = "test-util"))]
macro_rules! unwrap_or_return_tuple {
    ($first:expr, $opt:expr) => {
        match $opt {
            Some(v) => v,
            None => return ($first, None),
        }
    };
}

pub type DbError = Box<dyn std::error::Error + Send + Sync>;

/// A `MigrateError` (checksum mismatch, downgrade, ...) is permanent: it will not heal by
/// waiting, unlike a connection error. Callers use this to pick a log level.
fn is_migrate_error(e: &DbError) -> bool {
    e.downcast_ref::<sqlx::migrate::MigrateError>().is_some()
}

impl Database {
    /// One attempt: connect and apply migrations.
    pub async fn new(url: &str) -> Result<Self, DbError> {
        // sqlx's pool retries internally on connection errors until `acquire_timeout` (default
        // 30s) elapses, then reports the generic "pool timed out" error, hiding the real cause
        // and stretching our retry cadence past the spec's 1/2/4/5s backoff. Make one plain
        // connection attempt first so the real error (e.g. connection refused) surfaces
        // immediately, then build the pool.
        PgConnection::connect(url).await?.close().await?;

        let max_connections: u32 = env::var("MAX_DATABASE_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or((num_cpus::get() * 4) as u32);
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(5))
            .connect(url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Database { pool })
    }

    /// Connect and migrate, retrying until it succeeds. Kubernetes' startupProbe
    /// decides when to give up and restart the container.
    pub async fn connect_with_retry(url: &str) -> Self {
        let mut backoff = crate::retry::Backoff::new();
        loop {
            match Self::new(url).await {
                Ok(db) => return db,
                Err(e) => {
                    let delay = backoff.next_delay();
                    if is_migrate_error(&e) {
                        // Checksum mismatch, downgrade, etc: these never heal on their own, but
                        // we still retry (the startupProbe decides when to give up). Log at
                        // `error` so a CrashLoop from this is diagnosable at a glance.
                        log::error!(
                            "database migration failed ({e}), retrying in {}s",
                            delay.as_secs()
                        );
                    } else {
                        log::warn!("database not ready ({e}), retrying in {}s", delay.as_secs());
                    }
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub async fn find_user_by_name(
        &self,
        username: &str,
    ) -> (
        DatabaseConnection,
        Option<(UserId, Option<String>, DatabaseUserInfo)>,
    ) {
        let conn = DatabaseConnection {
            pool: self.pool.clone(),
        };

        let res = sqlx::query(
            "SELECT guid, status, role, email FROM \"user\" WHERE name = $1",
        )
        .bind(username)
        .fetch_one(&self.pool)
        .await;

        let res = unwrap_or_return_tuple!(conn, res.ok());

        let user_id: UserId = res.try_get::<Vec<u8>, _>("guid").unwrap();
        let email: Option<String> = res.try_get::<Option<String>, _>("email").unwrap_or(None);
        let status: i16 = res.try_get::<i16, _>("status").unwrap_or(0);
        let role: i16 = res.try_get::<i16, _>("role").unwrap_or(0);
        let dbi = DatabaseUserInfo {
            active: status == 1,
            admin: role == 1,
        };

        (conn, Some((user_id, email, dbi)))
    }

    pub async fn get_legacy_address_book(&self, user_id: UserId) -> Option<AddressBook> {
        let res = sqlx::query(
            "SELECT ab FROM ab_legacy WHERE user_guid = $1",
        )
        .bind(&user_id)
        .fetch_one(&self.pool)
        .await
        .ok()?;

        let ab_str: String = res.try_get::<String, _>("ab").unwrap_or_default();
        let ab = AddressBook {
            ab: ab_str,
            ..Default::default()
        };

        Some(ab)
    }

    pub async fn update_legacy_address_books(
        &self,
        values: Vec<(UserId, AddressBook)>,
    ) -> Option<()> {
        let values_count = values.len() as u64;
        let mut total_affected = 0u64;

        for (user_guid, ab) in &values {
            let res = sqlx::query(
                "INSERT INTO ab_legacy (user_guid, ab) VALUES ($1, $2) \
                 ON CONFLICT (user_guid) DO UPDATE SET ab = $2",
            )
            .bind(user_guid)
            .bind(&ab.ab)
            .execute(&self.pool)
            .await
            .ok()?
            .rows_affected();
            total_affected += res;
        }

        if total_affected != values_count {
            return None;
        }

        Some(())
    }

    pub async fn ui_get_all_users(&self) -> Option<Vec<types::UserInfo>> {
        let rows = sqlx::query(
            r#"SELECT
                "user".guid as id,
                "user".status,
                "user".role,
                "user".name as username,
                ab_legacy.ab
            FROM
                "user"
                LEFT JOIN ab_legacy
                    ON ab_legacy.user_guid = "user".guid"#,
        )
        .fetch_all(&self.pool)
        .await
        .ok()?;

        let mut users = Vec::new();
        for row in rows {
            let info = types::UserInfo {
                id: row.try_get::<Vec<u8>, _>("id").unwrap_or_default(),
                active: row.try_get::<i16, _>("status").unwrap_or(0) != 0,
                admin: row.try_get::<i16, _>("role").unwrap_or(0) != 0,
                username: row.try_get::<String, _>("username").unwrap_or_default(),
                address_book: row.try_get::<String, _>("ab").unwrap_or_default(),
            };
            users.push(info);
        }

        Some(users)
    }

    pub async fn ui_get_user_info(&self, username: String) -> Option<types::UserInfo> {
        let row = sqlx::query(
            r#"SELECT
                "user".guid as id,
                "user".status,
                "user".role,
                "user".name as username,
                ab_legacy.ab
            FROM
                "user"
                LEFT JOIN ab_legacy
                    ON ab_legacy.user_guid = "user".guid
            WHERE
                "user".name = $1"#,
        )
        .bind(&username)
        .fetch_one(&self.pool)
        .await
        .ok()?;

        Some(types::UserInfo {
            id: row.try_get::<Vec<u8>, _>("id").unwrap_or_default(),
            active: row.try_get::<i16, _>("status").unwrap_or(0) != 0,
            admin: row.try_get::<i16, _>("role").unwrap_or(0) != 0,
            username: row.try_get::<String, _>("username").unwrap_or_default(),
            address_book: row.try_get::<String, _>("ab").unwrap_or_default(),
        })
    }

    pub async fn create_user(
        &self,
        username: String,
        admin: bool,
    ) -> Option<UserId> {
        let guid = Uuid::new_v4().as_bytes().to_vec();
        let role: i16 = if admin { 1 } else { 0 };

        sqlx::query(
            "INSERT INTO \"user\" (guid, status, role, name, grp, team) \
             VALUES ($1, 1, $2, $3, \
             (SELECT guid FROM grp WHERE name = 'Default'), \
             (SELECT guid FROM team WHERE name = 'Default'))",
        )
        .bind(&guid)
        .bind(role)
        .bind(&username)
        .execute(&self.pool)
        .await
        .ok()?;

        Some(guid)
    }

    pub async fn delete_user(&self, uuid: &str) -> Option<()> {
        let user_id = Uuid::parse_str(uuid);
        if user_id.is_err() {
            log::error!("delete user error: {:?}", uuid);
            return None;
        }
        let user_id = user_id.unwrap().as_bytes().to_vec();

        let deleted = sqlx::query("DELETE FROM \"user\" WHERE guid = $1")
            .bind(&user_id)
            .execute(&self.pool)
            .await
            .ok()?
            .rows_affected();
        if deleted == 0 {
            return None;
        }

        sqlx::query("DELETE FROM ab_legacy WHERE user_guid = $1")
            .bind(&user_id)
            .execute(&self.pool)
            .await
            .ok();

        sqlx::query("DELETE FROM ab WHERE owner = $1")
            .bind(&user_id)
            .execute(&self.pool)
            .await
            .ok();

        sqlx::query("DELETE FROM session WHERE \"user\" = $1")
            .bind(&user_id)
            .execute(&self.pool)
            .await
            .ok();

        Some(())
    }

    pub async fn update_systeminfo(&self, systeminfo: utils::SystemInfo) -> Option<()> {
        // Peers are identified by the (id, uuid) pair reported in this upload;
        // without both there is no single row to patch.
        let id = systeminfo.id.clone()?;
        let uuid = systeminfo.uuid.clone()?;
        let uuid_decoded = BASE64_STANDARD.decode(uuid).ok()?;

        // hbbs owns `ip`; drop it and any absent (null) field so the merge
        // below cannot erase what hbbs or a prior upload already stored.
        let mut patch = serde_json::to_value(&systeminfo).ok()?;
        if let serde_json::Value::Object(map) = &mut patch {
            map.remove("ip");
            // The UUID ties the ID to the machine (hbbs, audit records); device lists must not show it.
            map.remove("uuid");
            map.retain(|_, v| !v.is_null());
        }

        let res = sqlx::query(
            "UPDATE peer \
             SET info = (COALESCE(NULLIF(info, ''), '{}')::jsonb || $1::jsonb)::text \
             WHERE id = $2 AND uuid = $3",
        )
        .bind(&patch)
        .bind(&id)
        .bind(&uuid_decoded)
        .execute(&self.pool)
        .await
        .ok()?
        .rows_affected();

        if res == 0 {
            None
        } else {
            Some(())
        }
    }

    pub async fn update_heartbeat(&self, heartbeat: utils::HeartbeatRequest) -> Option<()> {
        let uuid = heartbeat.uuid.clone();
        let uuid_decoded = BASE64_STANDARD.decode(uuid);
        if uuid_decoded.is_ok() {
            let uuid_decoded = uuid_decoded.unwrap();
            log::debug!(
                "uuid_decoded: {:?} {:?}",
                uuid_decoded,
                String::from_utf8(uuid_decoded.clone())
            );
            let res = sqlx::query(
                "UPDATE peer SET last_online = current_timestamp WHERE uuid = $1",
            )
            .bind(&uuid_decoded)
            .execute(&self.pool)
            .await;
            if res.is_err() {
                log::debug!("update_heartbeat error: {:?}", res.as_ref().err());
                return None;
            }
            let res = res.unwrap().rows_affected();

            if res == 0 {
                return None;
            } else {
                log::debug!("update_heartbeat row affected: {:?}", res);
                return Some(());
            }
        }
        None
    }

    /// The account for an OIDC identity, created on first login. `sub` is the identity;
    /// `name` and `email` are display data refreshed on every login. An account without a
    /// subject (created before 0004, or by an admin) is adopted when exactly one has `email`.
    pub async fn get_user_for_oauth2(
        &self,
        sub: &str,
        name: &str,
        email: Option<&str>,
    ) -> Option<(UserId, String, DatabaseUserInfo)> {
        if self.user_by_oidc_sub(sub).await.is_some() {
            self.refresh_oidc_user(sub, name, email).await;
        } else if !self.adopt_user_by_email(sub, name, email).await {
            self.create_oidc_user(sub, name, email).await;
        }
        self.user_by_oidc_sub(sub).await
    }

    async fn user_by_oidc_sub(&self, sub: &str) -> Option<(UserId, String, DatabaseUserInfo)> {
        let row = sqlx::query("SELECT guid, status, role, name FROM \"user\" WHERE oidc_sub = $1")
            .bind(sub)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| log::error!("get_user_for_oauth2 lookup error: {e:?}"))
            .ok()??;
        let dbi = DatabaseUserInfo {
            active: row.try_get::<i16, _>("status").unwrap_or(0) == 1,
            admin: row.try_get::<i16, _>("role").unwrap_or(0) == 1,
        };
        Some((row.try_get("guid").ok()?, row.try_get("name").ok()?, dbi))
    }

    async fn refresh_oidc_user(&self, sub: &str, name: &str, email: Option<&str>) {
        let res = sqlx::query("UPDATE \"user\" SET name = $2, email = $3 WHERE oidc_sub = $1")
            .bind(sub)
            .bind(name)
            .bind(email)
            .execute(&self.pool)
            .await;
        if let Err(e) = res {
            log::error!("get_user_for_oauth2 refresh error: {e:?}");
        }
    }

    async fn adopt_user_by_email(&self, sub: &str, name: &str, email: Option<&str>) -> bool {
        let Some(email) = email else { return false };
        let candidates: Vec<Vec<u8>> =
            match sqlx::query_scalar("SELECT guid FROM \"user\" WHERE oidc_sub IS NULL AND email = $1")
                .bind(email)
                .fetch_all(&self.pool)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    log::error!("get_user_for_oauth2 adopt lookup error: {e:?}");
                    return false;
                }
            };
        let [guid] = candidates.as_slice() else { return false };
        let res = sqlx::query("UPDATE \"user\" SET oidc_sub = $2, name = $3 WHERE guid = $1 AND oidc_sub IS NULL")
            .bind(guid)
            .bind(sub)
            .bind(name)
            .execute(&self.pool)
            .await;
        matches!(res, Ok(r) if r.rows_affected() == 1)
    }

    async fn create_oidc_user(&self, sub: &str, name: &str, email: Option<&str>) {
        let active: i16 = if env::var("OAUTH2_CREATE_USER").unwrap_or_default() == "1" { 1 } else { 0 };
        let user_guid = Uuid::new_v4().as_bytes().to_vec();
        let inserted = sqlx::query(
            "INSERT INTO \"user\"(guid, grp, team, status, role, name, email, oidc_sub) \
             VALUES ($1, \
             (SELECT guid FROM grp WHERE name = 'Default'), \
             (SELECT guid FROM team WHERE name = 'Default'), $2, 0, $3, $4, $5) \
             ON CONFLICT (oidc_sub) DO NOTHING",
        )
        .bind(&user_guid)
        .bind(active)
        .bind(name)
        .bind(email)
        .bind(sub)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(r) if r.rows_affected() == 1 => {}
            Ok(_) => return, // a concurrent first login created it
            Err(e) => {
                log::error!("get_user_for_oauth2 error while creating user: {e:?}");
                return;
            }
        }
        // Clients label the personal book themselves; the name only has to be unique.
        let ab_name = format!("personal:{}", Uuid::from_slice(&user_guid).map(|u| u.to_string()).unwrap_or_default());
        let res = sqlx::query("INSERT INTO ab(guid, name, owner, personal, info) VALUES ($1, $2, $3, 1, '{}')")
            .bind(Uuid::new_v4().as_bytes().to_vec())
            .bind(ab_name)
            .bind(&user_guid)
            .execute(&self.pool)
            .await;
        if let Err(e) = res {
            log::error!("get_user_for_oauth2 error while creating ab: {e:?}");
        }
    }

    /// Finds the one user whose email is `email` (case-insensitive). Errors list the
    /// candidates when several users share it.
    pub async fn resolve_user(&self, email: &str) -> Result<(UserId, String), String> {
        let rows = sqlx::query("SELECT guid, name, oidc_sub FROM \"user\" WHERE lower(email) = lower($1)")
            .bind(email)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("database error: {e}"))?;
        let field = |r: &sqlx::postgres::PgRow, c: &str| r.try_get::<Option<String>, _>(c).ok().flatten().unwrap_or_default();
        match rows.as_slice() {
            [] => Err(format!("no user has email {email:?}; users are created on their first OIDC login")),
            [r] => Ok((r.try_get::<Vec<u8>, _>("guid").unwrap_or_default(), field(r, "name"))),
            many => Err(format!(
                "{email:?} belongs to {} users; fix it at the IdP or in the console:\n{}",
                many.len(),
                many.iter()
                    .map(|r| format!("  name={} sub={}", field(r, "name"), field(r, "oidc_sub")))
                    .collect::<Vec<_>>()
                    .join("\n")
            )),
        }
    }

    /// Promotes (active admin) or demotes the user with email `email` (see
    /// `resolve_user`) and returns its display name. Promoting also hands over shared
    /// address books whose owner was deleted.
    pub async fn set_admin(&self, email: &str, admin: bool) -> Result<String, String> {
        let (guid, name) = self.resolve_user(email).await?;
        let sql = if admin {
            "UPDATE \"user\" SET role = 1, status = 1 WHERE guid = $1"
        } else {
            "UPDATE \"user\" SET role = 0 WHERE guid = $1"
        };
        sqlx::query(sql)
            .bind(&guid)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("database error: {e}"))?;
        if admin {
            // Shared address books left ownerless by migration 0002.
            sqlx::query(
                "UPDATE ab SET owner = $1 WHERE personal = 0 AND owner NOT IN (SELECT guid FROM \"user\")",
            )
            .bind(&guid)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("database error while adopting shared address books: {e}"))?;
        }
        Ok(name)
    }

    pub async fn get_personal_address_book(&self, user_id: UserId) {
        let _res = sqlx::query(
            "SELECT guid FROM ab WHERE owner = $1 AND personal = 1",
        )
        .bind(&user_id)
        .fetch_one(&self.pool)
        .await
        .ok();
    }

    pub async fn get_ab_personal_guid(&self, user_id: UserId) -> Option<String> {
        let res = sqlx::query(
            r#"SELECT a.guid FROM ab as a, "user" as u
               WHERE u.guid = $1 AND a.personal = 1 AND a.owner = u.guid AND u.status = 1"#,
        )
        .bind(&user_id)
        .fetch_one(&self.pool)
        .await;
        if res.is_err() {
            log::error!("get_ab_personal_guid error: {:?}", res.as_ref().err());
            return None;
        }

        let res = res.unwrap();
        let guid_bytes: Vec<u8> = res.try_get::<Vec<u8>, _>("guid").unwrap();
        let guid_u8: Result<[u8; 16], _> = guid_bytes.try_into();
        if guid_u8.is_err() {
            log::error!("get_ab_personal_guid error: {:?}", guid_u8);
            return None;
        }
        let guid_u8: [u8; 16] = guid_u8.unwrap();
        let guid = Uuid::from_bytes(guid_u8).to_string();
        Some(guid)
    }

    /// Share rule `user_id` holds on address book `ab`: 3 (full control) for
    /// the owner, for admins on shared books, else the highest `ab_rule` granted
    /// to the user or their group. Other users' personal books are always 0.
    /// None if the book does not exist.
    pub async fn get_ab_rule_for_user(&self, ab: &str, user_id: &UserId, is_admin: bool) -> Option<u32> {
        let ab_guid = Uuid::parse_str(ab).ok()?.as_bytes().to_vec();
        let row = sqlx::query(
            r#"SELECT a.owner = $2 AS is_owner, a.personal,
                  (SELECT MAX(r.rule) FROM ab_rule r
                   WHERE r.ab = a.guid
                     AND (r."user" = $2 OR r.grp IN (SELECT grp FROM "user" WHERE guid = $2))) AS rule
               FROM ab a WHERE a.guid = $1"#,
        )
        .bind(&ab_guid)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .ok()??;
        if row.try_get::<bool, _>("is_owner").unwrap_or(false) {
            return Some(3);
        }
        if row.try_get::<i16, _>("personal").unwrap_or(1) != 0 {
            return Some(0);
        }
        if is_admin {
            return Some(3);
        }
        let rule = row.try_get::<Option<i16>, _>("rule").ok().flatten().unwrap_or(0);
        Some(rule.max(0) as u32)
    }

    pub async fn add_peer_to_ab(&self, ab: &str, ab_peer: AbPeer) -> Option<()> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("add_peer_to_ab error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let ab_peer_guid = Uuid::new_v4().as_bytes().to_vec();
        let ab_peer_json = rocket::serde::json::to_string(&ab_peer).unwrap();

        // Delete existing peer with same ab+id first
        let res = sqlx::query("DELETE FROM ab_peer WHERE ab = $1 AND id = $2")
            .bind(&ab_guid)
            .bind(&ab_peer.id)
            .execute(&self.pool)
            .await;
        if res.is_err() {
            log::error!("add_peer_to_ab delete error: {:?}", res.as_ref().err());
        }

        let res = sqlx::query(
            "INSERT INTO ab_peer (guid, ab, peer, id, note, created_at, info) \
             VALUES ($1, $2, (SELECT guid FROM peer WHERE id = $3), $3, $4, current_timestamp, $5) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&ab_peer_guid)
        .bind(&ab_guid)
        .bind(&ab_peer.id)
        .bind("")
        .bind(&ab_peer_json)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("add_peer_to_ab error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn get_peers_from_ab(&self, ab: &str) -> Option<Vec<AbPeer>> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("get_peers_from_ab error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let res = sqlx::query(
            "SELECT info FROM ab_peer WHERE ab_peer.ab = $1",
        )
        .bind(&ab_guid)
        .fetch_all(&self.pool)
        .await;
        if res.is_err() {
            log::error!("get_peers_from_ab error: {:?}", res.as_ref().err());
            return None;
        }
        let res = res.unwrap();
        let mut ab_peers = Vec::new();
        for row in res {
            let info: String = row.try_get::<String, _>("info").unwrap_or_default();
            let ab_peer: AbPeer = rocket::serde::json::from_str(&info).unwrap();
            log::debug!("ab_peer: {:?}", ab_peer);
            ab_peers.push(ab_peer);
        }
        Some(ab_peers)
    }

    pub async fn delete_peer_from_ab(&self, ab: &str, id: &str) -> Option<()> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("delete_peer_from_ab error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let res = sqlx::query("DELETE FROM ab_peer WHERE ab = $1 AND id = $2")
            .bind(&ab_guid)
            .bind(id)
            .execute(&self.pool)
            .await;
        if res.is_err() {
            log::error!("delete_peer_from_ab error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn get_ab_peer(&self, ab: &str, id: &str) -> Option<AbPeer> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("get_ab_peer error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let res = sqlx::query(
            "SELECT info FROM ab_peer WHERE ab_peer.ab = $1 AND ab_peer.id = $2",
        )
        .bind(&ab_guid)
        .bind(id)
        .fetch_one(&self.pool)
        .await;
        if res.is_err() {
            log::error!("get_ab_peer error: {:?}", res.as_ref().err());
            return None;
        }
        let res = res.unwrap();
        let info: String = res.try_get::<String, _>("info").unwrap_or_default();
        let ab_peer: AbPeer = rocket::serde::json::from_str(&info).unwrap();
        Some(ab_peer)
    }

    pub async fn add_tag_to_ab(&self, ab: &str, tag: AbTag) -> Option<()> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("add_tag_to_ab error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();

        // Delete existing tag first, then insert
        let res = sqlx::query("DELETE FROM ab_tag WHERE ab = $1 AND name = $2")
            .bind(&ab_guid)
            .bind(&tag.name)
            .execute(&self.pool)
            .await;
        if res.is_err() {
            log::error!("add_tag_to_ab delete error: {:?}", res.as_ref().err());
        }

        let color_val = tag.color as i64;
        let res = sqlx::query(
            "INSERT INTO ab_tag (ab, name, color) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(&ab_guid)
        .bind(&tag.name)
        .bind(color_val)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("add_tag_to_ab error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn get_ab_tags(&self, ab: &str) -> Option<Vec<AbTag>> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("get_ab_tags error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let res = sqlx::query("SELECT name, color FROM ab_tag WHERE ab = $1")
            .bind(&ab_guid)
            .fetch_all(&self.pool)
            .await;
        if res.is_err() {
            log::error!("get_ab_tags error: {:?}", res.as_ref().err());
            return None;
        }
        let res = res.unwrap();
        let mut ab_tags = Vec::new();
        for row in res {
            let ab_tag = AbTag {
                name: row.try_get::<String, _>("name").unwrap_or_default(),
                color: row.try_get::<i64, _>("color").unwrap_or(0) as u32,
            };
            ab_tags.push(ab_tag);
        }
        Some(ab_tags)
    }

    pub async fn get_ab_tag(&self, ab: &str, tag: &str) -> Option<AbTag> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("get_ab_tag error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let res = sqlx::query("SELECT name, color FROM ab_tag WHERE ab = $1 AND name = $2")
            .bind(&ab_guid)
            .bind(tag)
            .fetch_all(&self.pool)
            .await;
        if res.is_err() {
            log::error!("get_ab_tags error: {:?}", res.as_ref().err());
            return None;
        }
        let res = res.unwrap();
        if res.is_empty() {
            return None;
        }
        let ab_tag = AbTag {
            name: res[0].try_get::<String, _>("name").unwrap_or_default(),
            color: res[0].try_get::<i64, _>("color").unwrap_or(0) as u32,
        };
        Some(ab_tag)
    }

    pub async fn rename_ab_tag(&self, ab: &str, old_name: &str, tag: AbTag) -> Option<()> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("rename_ab_tag error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let color_val = tag.color as i64;
        let res = sqlx::query(
            "UPDATE ab_tag SET name = $1, color = $2 WHERE ab = $3 AND name = $4",
        )
        .bind(&tag.name)
        .bind(color_val)
        .bind(&ab_guid)
        .bind(old_name)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("rename_ab_tag error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn delete_tag_from_ab(&self, ab: &str, tag: &str) -> Option<()> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("delete_tag_from_ab error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let res = sqlx::query("DELETE FROM ab_tag WHERE ab = $1 AND name = $2")
            .bind(&ab_guid)
            .bind(tag)
            .execute(&self.pool)
            .await;
        if res.is_err() {
            log::error!("delete_tag_from_ab error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn add_user(
        &self,
        name: String,
        email: String,
        is_admin: bool,
        group_name: String,
    ) -> Option<()> {
        let user_guid = Uuid::new_v4().as_bytes().to_vec();
        let ab_name = format!("{}'s Personal Address Book", name);
        let res = sqlx::query("SELECT guid FROM grp WHERE name = $1")
            .bind(&group_name)
            .fetch_all(&self.pool)
            .await;
        if res.is_err() {
            log::error!("add_user error: {:?}", res.as_ref().err());
            return None;
        }
        let res = res.unwrap();
        if res.is_empty() {
            return None;
        }
        let group_guid: Vec<u8> = res[0].try_get::<Vec<u8>, _>("guid").unwrap();
        let ab_guid = Uuid::new_v4().as_bytes().to_vec();
        let role: i16 = if is_admin { 1 } else { 0 };

        let res = sqlx::query(
            "INSERT INTO \"user\"(guid, grp, team, status, role, name, email) \
             VALUES ($1, $2, (SELECT guid FROM team WHERE name = 'Default'), 1, $3, $4, $5) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&user_guid)
        .bind(&group_guid)
        .bind(role)
        .bind(&name)
        .bind(&email)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("add_user error: {:?}", res.as_ref().err());
            return None;
        }

        let res = sqlx::query(
            "INSERT INTO ab(guid, name, owner, personal, info) \
             VALUES ($1, $2, $3, 1, '{}') ON CONFLICT DO NOTHING",
        )
        .bind(&ab_guid)
        .bind(&ab_name)
        .bind(&user_guid)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("add_user ab error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn user_change_status(&self, uuid: &str, status: u32) -> Option<()> {
        let guid = Uuid::parse_str(uuid);
        if guid.is_err() {
            log::error!("change_user_status error: {:?}", guid);
            return None;
        }
        let guid = guid.unwrap().as_bytes().to_vec();
        let status_val = status as i16;
        let res = sqlx::query("UPDATE \"user\" SET status = $1 WHERE guid = $2")
            .bind(status_val)
            .bind(&guid)
            .execute(&self.pool)
            .await;
        if res.is_err() {
            log::error!("change_user_status error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn get_all_users(
        &self,
        name: Option<&str>,
        email: Option<&str>,
        current: u32,
        page_size: u32,
    ) -> Option<Vec<UserListResponse>> {
        let email_filter = email.unwrap_or("%").to_string();
        let name_filter = name.unwrap_or("%").to_string();
        let current = if current < 1 { 1 } else { current };
        let offset = ((current - 1) * page_size) as i32;
        let page_size = page_size as i32;

        let res = sqlx::query(
            r#"SELECT
                "user".guid as id,
                "user".status,
                "user".role,
                "user".name as username,
                "user".email as email,
                "user".note as note,
                grp.name as group_name
            FROM
                "user"
                LEFT JOIN grp
                    ON "user".grp = grp.guid
            WHERE
                "user".name LIKE $1
                AND "user".email LIKE $2
            LIMIT $3
            OFFSET $4"#,
        )
        .bind(&name_filter)
        .bind(&email_filter)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await;
        if res.is_err() {
            log::error!("get_all_users error: {:?}", res.as_ref().err());
            return None;
        }
        let res = res.unwrap();
        let mut users: Vec<UserListResponse> = Vec::new();
        for row in res {
            let id_bytes: Vec<u8> = row.try_get::<Vec<u8>, _>("id").unwrap_or_default();
            let guid_u8: Result<[u8; 16], _> = id_bytes.try_into();
            if guid_u8.is_err() {
                log::error!("get_all_users guid error: {:?}", guid_u8);
                return None;
            }
            let guid_u8: [u8; 16] = guid_u8.unwrap();
            let guid = Uuid::from_bytes(guid_u8).to_string();
            let user = UserListResponse {
                guid,
                name: row.try_get::<String, _>("username").unwrap_or_default(),
                email: row
                    .try_get::<Option<String>, _>("email")
                    .unwrap_or(None)
                    .unwrap_or_default(),
                note: row.try_get::<Option<String>, _>("note").unwrap_or(None),
                status: row.try_get::<i16, _>("status").unwrap_or(0) as i32,
                is_admin: row.try_get::<i16, _>("role").unwrap_or(0) != 0,
                group_name: row
                    .try_get::<Option<String>, _>("group_name")
                    .unwrap_or(None)
                    .unwrap_or_else(|| "Defaut".to_string()),
            };
            users.push(user);
        }
        Some(users)
    }

    pub async fn user_update(
        &self,
        user_id: UserId,
        user_parameters: UpdateUserRequest,
    ) -> Option<()> {
        let mut set_clauses = Vec::new();
        let mut query_params: Vec<String> = Vec::new();
        let mut param_idx = 1u32;

        if user_parameters.name.is_some() && !user_parameters.name.as_ref().unwrap().is_empty() {
            set_clauses.push(format!("name = ${}", param_idx));
            query_params.push(user_parameters.name.unwrap());
            param_idx += 1;
        }
        if user_parameters.email.is_some() && !user_parameters.email.as_ref().unwrap().is_empty() {
            set_clauses.push(format!("email = ${}", param_idx));
            query_params.push(user_parameters.email.unwrap());
            param_idx += 1;
        }
        if user_parameters.note.is_some() && !user_parameters.note.as_ref().unwrap().is_empty() {
            set_clauses.push(format!("note = ${}", param_idx));
            query_params.push(user_parameters.note.unwrap());
            param_idx += 1;
        }
        if let Some(status) = user_parameters.status {
            set_clauses.push(format!("status = CAST(${} AS integer)", param_idx));
            query_params.push(status.to_string());
            param_idx += 1;
        }
        if let Some(is_admin) = user_parameters.is_admin {
            set_clauses.push(format!("role = CAST(${} AS integer)", param_idx));
            query_params.push(if is_admin { "1" } else { "0" }.to_string());
            param_idx += 1;
        }

        if set_clauses.is_empty() {
            return Some(());
        }

        let query = format!(
            "UPDATE \"user\" SET {} WHERE guid = ${}",
            set_clauses.join(", "),
            param_idx
        );

        log::debug!("query: {:?}", query);
        let mut res = sqlx::query(&query);
        for param in query_params {
            res = res.bind(param);
        }
        let res = res.bind(user_id).execute(&self.pool).await;
        if res.is_err() {
            log::error!("user_update error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn get_all_peers(&self) -> Option<Vec<Peer>> {
        let res = sqlx::query(
            "SELECT guid, id, uuid, status, info, last_online FROM peer",
        )
        .fetch_all(&self.pool)
        .await
        .ok()?;

        let mut peers: Vec<Peer> = Vec::new();
        for row in res {
            let guid_bytes: Vec<u8> = row.try_get::<Vec<u8>, _>("guid").unwrap_or_default();
            let uuid = guid_into_uuid(guid_bytes).unwrap_or("".to_string());
            let info_str: String = row.try_get::<String, _>("info").unwrap_or("{}".to_string());
            let peer_info = serde_json::from_str::<utils::PeerInfo>(&info_str);
            if peer_info.is_err() {
                log::error!("get_all_peers error: {:?}", peer_info);
                return None;
            }
            let peer_info = peer_info.unwrap();
            let last_online: String = row
                .try_get::<String, _>("last_online")
                .unwrap_or_default();
            let status: i16 = row.try_get::<i16, _>("status").unwrap_or(0);
            peers.push(Peer {
                id: row.try_get::<String, _>("id").unwrap_or_default(),
                guid: uuid,
                info: peer_info,
                last_online: last_online.into(),
                status: status as i32,
                strategy_name: "-".to_string(),
            });
        }
        Some(peers)
    }

    pub async fn get_groups(&self, offset: u32, page_size: u32) -> Option<Vec<Group>> {
        let res = sqlx::query(
            "SELECT guid, team, name, note, created_at, info FROM grp ORDER BY created_at, guid LIMIT $1 OFFSET $2",
        )
        .bind(page_size as i32)
        .bind(offset as i32)
        .fetch_all(&self.pool)
        .await;
        if res.is_err() {
            log::error!("get_groups error: {:?}", res.as_ref().err());
            return None;
        }
        let res = res.unwrap();
        let mut groups: Vec<Group> = Vec::new();
        for row in &res {
            let guid_bytes: Vec<u8> = row.try_get::<Vec<u8>, _>("guid").unwrap_or_default();
            let team_bytes: Vec<u8> = row.try_get::<Vec<u8>, _>("team").unwrap_or_default();
            let guid = guid_into_uuid(guid_bytes).unwrap_or("".to_string());
            let team = guid_into_uuid(team_bytes).unwrap_or("".to_string());
            groups.push(Group {
                guid,
                name: row.try_get::<String, _>("name").unwrap_or_default(),
                team,
                note: row.try_get::<Option<String>, _>("note").unwrap_or(None),
                created_at: row
                    .try_get::<String, _>("created_at")
                    .unwrap_or_default()
                    .into(),
                access_to: Vec::<String>::new(),
                accessed_from: Vec::<String>::new(),
                info: row.try_get::<String, _>("info").unwrap_or("{}".to_string()),
            });
        }
        Some(groups)
    }

    pub async fn delete_shared_address_book(&self, guid: &str) -> Option<()> {
        let ab_guid = Uuid::parse_str(guid);
        if ab_guid.is_err() {
            log::error!("delete_ab error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();

        sqlx::query("DELETE FROM ab_peer WHERE ab = $1")
            .bind(&ab_guid)
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("DELETE FROM ab_rule WHERE ab = $1")
            .bind(&ab_guid)
            .execute(&self.pool)
            .await
            .ok();
        let res = sqlx::query("DELETE FROM ab WHERE guid = $1")
            .bind(&ab_guid)
            .execute(&self.pool)
            .await;
        if res.is_err() {
            log::error!("delete_ab error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn get_shared_address_books(&self, user_id: UserId) -> Option<Vec<AddressBook>> {
        let res = sqlx::query(
            r#"SELECT
                ab.guid,
                ab.name,
                ab.owner,
                COALESCE(MaxRule.rule, 0) as rule
            FROM
                ab
            JOIN
                (SELECT ab, MAX(rule) as rule
                FROM ab_rule
                WHERE "user" = $1 OR grp IN (SELECT grp FROM "user" WHERE guid = $1)
                GROUP BY ab) as MaxRule
            ON ab.guid = MaxRule.ab
            WHERE
                personal = 0"#,
        )
        .bind(&user_id)
        .fetch_all(&self.pool)
        .await
        .ok()?;
        let mut address_books: Vec<AddressBook> = Vec::new();
        for row in res {
            let guid_bytes: Vec<u8> = row.try_get::<Vec<u8>, _>("guid").unwrap_or_default();
            let owner_bytes: Vec<u8> = row.try_get::<Vec<u8>, _>("owner").unwrap_or_default();
            let access_level = row.try_get::<i32, _>("rule").unwrap_or(0) as u32;
            address_books.push(AddressBook {
                ab: guid_into_uuid(guid_bytes).unwrap_or("".to_string()),
                name: Some(row.try_get::<String, _>("name").unwrap_or_default()),
                owner: Some(owner_bytes),
                rule: Some(access_level),
                ..Default::default()
            });
        }
        Some(address_books)
    }

    pub async fn get_ab_rules(
        &self,
        _offset: u32,
        _page_size: u32,
        ab: &str,
    ) -> Option<Vec<AbRule>> {
        let ab_guid = Uuid::parse_str(ab);
        if ab_guid.is_err() {
            log::error!("get_ab_rules error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let res = sqlx::query(
            r#"SELECT
                r.guid,
                u.name as username,
                g.name as groupname,
                r.rule
            FROM
                ab_rule r
            LEFT JOIN
                "user" u ON u.guid = r."user"
            LEFT JOIN
                grp g ON g.guid = r.grp
            WHERE
                ab = $1"#,
        )
        .bind(&ab_guid)
        .fetch_all(&self.pool)
        .await;
        if res.is_err() {
            log::error!("get_ab_rules error: {:?}", res.as_ref().err());
            return None;
        }
        let res = res.unwrap();
        let mut ab_rules = Vec::new();
        for row in res {
            let guid_bytes: Vec<u8> = row.try_get::<Vec<u8>, _>("guid").unwrap_or_default();
            let uuid = guid_into_uuid(guid_bytes).unwrap_or("".to_string());
            let user: Option<String> = row.try_get::<Option<String>, _>("username").unwrap_or(None);
            let group: Option<String> =
                row.try_get::<Option<String>, _>("groupname").unwrap_or(None);
            let ab_rule = AbRule {
                user,
                group,
                rule: row.try_get::<i16, _>("rule").unwrap_or(0) as u32,
                guid: uuid,
            };
            ab_rules.push(ab_rule);
        }
        Some(ab_rules)
    }

    pub async fn delete_ab_rule(&self, rule: &str) -> Option<()> {
        let rule_guid = Uuid::parse_str(rule);
        if rule_guid.is_err() {
            log::error!("delete_ab_rule error: {:?}", rule_guid);
            return None;
        }
        let rule_guid = rule_guid.unwrap().as_bytes().to_vec();
        let res = sqlx::query("DELETE FROM ab_rule WHERE guid = $1")
            .bind(&rule_guid)
            .execute(&self.pool)
            .await;
        if res.is_err() {
            log::error!("delete_ab_rule error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn add_ab_rule(&self, rule: AbRule) -> Option<()> {
        let rule_guid = Uuid::new_v4().as_bytes().to_vec();
        let ab_guid = Uuid::parse_str(&rule.guid);
        if ab_guid.is_err() {
            log::error!("add_ab_rule error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();
        let user_guid = if rule.user.is_some() {
            let uuid = Uuid::parse_str(&rule.user.unwrap());
            if uuid.is_err() {
                None
            } else {
                Some(uuid.unwrap().as_bytes().to_vec())
            }
        } else {
            None
        };

        let group_guid = if rule.group.is_some() {
            let uuid = Uuid::parse_str(&rule.group.unwrap());
            if uuid.is_err() {
                None
            } else {
                Some(uuid.unwrap().as_bytes().to_vec())
            }
        } else {
            None
        };

        let rule_val = rule.rule as i16;
        let res = sqlx::query(
            "INSERT INTO ab_rule (guid, ab, \"user\", grp, rule) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(&rule_guid)
        .bind(&ab_guid)
        .bind(&user_guid)
        .bind(&group_guid)
        .bind(rule_val)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("add_ab_rule error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn get_peers_count(&self, platform: Platform) -> u32 {
        let filter = match platform {
            Platform::Windows => "windows%",
            // "<distro> / Linux <version>": the distro id varies, so match
            // the long OS version after the separator.
            Platform::Linux => "% / linux%",
            Platform::MacOS => "macos%",
            Platform::Android => "android%",
            Platform::All => "%",
            _ => "unknown%",
        };

        let sql = "SELECT COUNT(*) as count FROM peer WHERE info::json->>'os' ILIKE $1";

        let res = sqlx::query(sql)
            .bind(filter)
            .fetch_one(&self.pool)
            .await
            .ok();
        if res.is_none() {
            return 0;
        }
        let res = res.unwrap();
        res.try_get::<i64, _>("count").unwrap_or(0) as u32
    }

    pub async fn get_cpus_count(&self) -> Vec<CpuCount> {
        let sql = "SELECT COALESCE(trim(info::json->>'cpu'),'unknown') as cpu, \
             COUNT(*) AS machine_count FROM peer GROUP BY cpu";

        let res = sqlx::query(sql).fetch_all(&self.pool).await.ok();
        if res.is_none() {
            return Vec::new();
        }
        let res = res.unwrap();
        let mut cpu_counts = Vec::new();
        for row in res {
            let cpu = row
                .try_get::<String, _>("cpu")
                .unwrap_or_else(|_| "unknown".to_string());
            let total = row.try_get::<i64, _>("machine_count").unwrap_or(0) as u32;
            cpu_counts.push(CpuCount { cpu, total });
        }
        cpu_counts
    }

    pub async fn get_group(&self, guid: &str) -> Option<Group> {
        let group_guid = Uuid::parse_str(guid);
        if group_guid.is_err() {
            log::error!("get_group error: {:?}", group_guid);
            return None;
        }
        let group_guid = group_guid.unwrap().as_bytes().to_vec();
        let res = sqlx::query(
            "SELECT guid, team, name, note, created_at, info FROM grp WHERE guid = $1",
        )
        .bind(&group_guid)
        .fetch_one(&self.pool)
        .await;
        if res.is_err() {
            log::error!("get_group error: {:?}", res.as_ref().err());
            return None;
        }
        let res = res.unwrap();
        let guid_bytes: Vec<u8> = res.try_get::<Vec<u8>, _>("guid").unwrap_or_default();
        let team_bytes: Vec<u8> = res.try_get::<Vec<u8>, _>("team").unwrap_or_default();
        let guid = guid_into_uuid(guid_bytes).unwrap_or("".to_string());
        let team = guid_into_uuid(team_bytes).unwrap_or("".to_string());
        Some(Group {
            guid,
            name: res.try_get::<String, _>("name").unwrap_or_default(),
            team,
            note: res.try_get::<Option<String>, _>("note").unwrap_or(None),
            created_at: res
                .try_get::<String, _>("created_at")
                .unwrap_or_default()
                .into(),
            access_to: Vec::<String>::new(),
            accessed_from: Vec::<String>::new(),
            info: res
                .try_get::<String, _>("info")
                .unwrap_or("{}".to_string()),
        })
    }

    pub async fn create_group(&self, name: &str, team: &str, note: &str) -> Option<()> {
        let group_guid = Uuid::new_v4().as_bytes().to_vec();

        let res = sqlx::query(
            "INSERT INTO grp(guid, team, name, note, created_at, info) \
             VALUES ($1, (SELECT guid FROM team WHERE name = $2), $3, $4, current_timestamp, '{}') \
             ON CONFLICT DO NOTHING",
        )
        .bind(&group_guid)
        .bind(team)
        .bind(name)
        .bind(note)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("create_group error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn update_group(
        &self,
        guid: &str,
        name: &str,
        team: &str,
        note: &str,
    ) -> Option<()> {
        let group_guid = Uuid::parse_str(guid);
        if group_guid.is_err() {
            log::error!("update_group error: {:?}", group_guid);
            return None;
        }
        let group_guid = group_guid.unwrap().as_bytes().to_vec();

        let res = sqlx::query(
            "UPDATE grp SET team = (SELECT guid FROM team WHERE name = $1), \
             name = $2, note = $3, created_at = current_timestamp WHERE guid = $4",
        )
        .bind(team)
        .bind(name)
        .bind(note)
        .bind(&group_guid)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("update_group error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn delete_group(&self, guid: &str) -> Option<()> {
        let group_guid = Uuid::parse_str(guid);
        if group_guid.is_err() {
            log::error!("delete_group error: {:?}", group_guid);
            return None;
        }
        let group_guid = group_guid.unwrap().as_bytes().to_vec();

        let res = sqlx::query("DELETE FROM grp WHERE guid = $1")
            .bind(&group_guid)
            .execute(&self.pool)
            .await;
        if res.is_err() {
            log::error!("delete_group error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn list_strategies(&self) -> Option<Vec<StrategySummary>> {
        let rows = sqlx::query("SELECT guid, name, modified_at FROM strategy ORDER BY created_at, guid")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| log::error!("list_strategies error: {e:?}"))
            .ok()?;
        rows.iter()
            .map(|row| {
                Some(StrategySummary {
                    guid: guid_into_uuid(row.get("guid"))?,
                    name: row.get("name"),
                    modified_at: row.get("modified_at"),
                })
            })
            .collect()
    }

    pub async fn get_strategy(&self, guid: &str) -> Option<(StrategySummary, BTreeMap<String, String>)> {
        let guid_bytes = Uuid::parse_str(guid).ok()?.as_bytes().to_vec();
        let row = sqlx::query("SELECT name, modified_at, options FROM strategy WHERE guid = $1")
            .bind(&guid_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| log::error!("get_strategy error: {e:?}"))
            .ok()??;
        let options: String = row.get("options");
        let options = serde_json::from_str(&options)
            .map_err(|e| log::error!("strategy {guid} has invalid options: {e}"))
            .unwrap_or_default();
        let summary = StrategySummary {
            guid: guid.to_string(),
            name: row.get("name"),
            modified_at: row.get("modified_at"),
        };
        Some((summary, options))
    }

    /// Saves `options` and bumps `modified_at` so every device receives them on its next heartbeat.
    pub async fn set_strategy_options(&self, guid: &str, options: &BTreeMap<String, String>) -> Option<i64> {
        let json = serde_json::to_string(options).ok()?;
        self.touch_strategy(guid, Some(json)).await
    }

    /// Bumps `modified_at` only: devices receive the policy again, reverting local changes.
    pub async fn bump_strategy(&self, guid: &str) -> Option<i64> {
        self.touch_strategy(guid, None).await
    }

    async fn touch_strategy(&self, guid: &str, options: Option<String>) -> Option<i64> {
        let guid_bytes = Uuid::parse_str(guid).ok()?.as_bytes().to_vec();
        // Strictly increasing, so two saves in the same millisecond still differ.
        sqlx::query_scalar(
            "UPDATE strategy SET options = COALESCE($1, options), \
             modified_at = GREATEST((extract(epoch FROM clock_timestamp()) * 1000)::bigint, modified_at + 1) \
             WHERE guid = $2 RETURNING modified_at",
        )
        .bind(options)
        .bind(&guid_bytes)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| log::error!("touch_strategy error: {e:?}"))
        .ok()
        .flatten()
    }

    pub async fn add_shared_address_book(&self, name: &str, owner: &str) -> Option<String> {
        let ab_guid = Uuid::new_v4().as_bytes().to_vec();
        let rule_guid = Uuid::new_v4().as_bytes().to_vec();
        let owner_guid = Uuid::parse_str(owner);
        if owner_guid.is_err() {
            log::error!("add_shared_address_book error: {:?}", owner_guid);
            return None;
        }
        let owner_guid = owner_guid.unwrap().as_bytes().to_vec();

        let res = sqlx::query(
            "INSERT INTO ab(guid, name, owner, personal, info) \
             VALUES ($1, $2, $3, 0, '{}') ON CONFLICT DO NOTHING",
        )
        .bind(&ab_guid)
        .bind(name)
        .bind(&owner_guid)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("add_shared_address_book ab error: {:?}", res.as_ref().err());
            return None;
        }

        let res = sqlx::query(
            "INSERT INTO ab_rule(guid, ab, \"user\", grp, rule) \
             VALUES ($1, $2, $3, NULL, 3) ON CONFLICT DO NOTHING",
        )
        .bind(&rule_guid)
        .bind(&ab_guid)
        .bind(&owner_guid)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!("add_shared_address_book rule error: {:?}", res.as_ref().err());
            return None;
        }

        Some(guid_into_uuid(ab_guid)?)
    }

    pub async fn insert_session(&self, token_id: &str, user_id: &[u8], ttl_secs: i64) -> Option<()> {
        // Logins are the only source of rows, so pruning here keeps the table to live sessions.
        if let Err(e) = sqlx::query("DELETE FROM session WHERE expiry_at <= NOW()::text")
            .execute(&self.pool)
            .await
        {
            log::warn!("removing expired sessions failed: {e}");
        }
        let expiry_expr = format!("NOW() + INTERVAL '{} seconds'", ttl_secs);
        let query = format!(
            "INSERT INTO session (id, ttl_secs, \"user\", expiry_at, created_at) \
             VALUES ($1, $2, $3, {}, current_timestamp)",
            expiry_expr
        );
        sqlx::query(&query)
            .bind(token_id)
            .bind(ttl_secs as i32)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .ok()?;
        Some(())
    }

    pub async fn find_session_user(&self, token_id: &str) -> Option<Vec<u8>> {
        let now_expr = "NOW()::text";
        let query = format!(
            "SELECT \"user\" FROM session WHERE id = $1 AND expiry_at > {}",
            now_expr
        );
        let row = sqlx::query(&query)
            .bind(token_id)
            .fetch_optional(&self.pool)
            .await
            .ok()?;
        row.map(|r| r.try_get::<Vec<u8>, _>("user").unwrap())
    }

    pub async fn delete_session(&self, token_id: &str) -> Option<()> {
        sqlx::query("DELETE FROM session WHERE id = $1")
            .bind(token_id)
            .execute(&self.pool)
            .await
            .ok()?;
        Some(())
    }

    pub async fn count_user_sessions(&self, user_id: &[u8]) -> i64 {
        let now_expr = "NOW()::text";
        let query = format!(
            "SELECT COUNT(*) as count FROM session WHERE \"user\" = $1 AND expiry_at > {}",
            now_expr
        );
        let row = sqlx::query(&query)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .ok();
        match row {
            Some(r) => r.try_get::<i64, _>("count").unwrap_or(0),
            None => 0,
        }
    }

    pub async fn get_user_info_by_id(&self, user_id: &[u8]) -> Option<(String, bool)> {
        let row = sqlx::query(
            "SELECT name, role FROM \"user\" WHERE guid = $1 AND status = 1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .ok()?;
        row.map(|r| {
            let name: String = r.try_get::<String, _>("name").unwrap_or_default();
            let admin: bool = r.try_get::<i16, _>("role").unwrap_or(0) == 1;
            (name, admin)
        })
    }

    pub async fn update_shared_address_book(&self, guid: &str, name: &str) -> Option<()> {
        let ab_guid = Uuid::parse_str(guid);
        if ab_guid.is_err() {
            log::error!("update_shared_address_book error: {:?}", ab_guid);
            return None;
        }
        let ab_guid = ab_guid.unwrap().as_bytes().to_vec();

        let res = sqlx::query("UPDATE ab SET name = $1 WHERE guid = $2")
            .bind(name)
            .bind(&ab_guid)
            .execute(&self.pool)
            .await;
        if res.is_err() {
            log::error!("update_shared_address_book error: {:?}", res.as_ref().err());
            return None;
        }
        Some(())
    }

    pub async fn insert_audit_conn(
        &self,
        guid: &[u8],
        conn_type: Option<i8>,
        remote: &[u8],
        local: Option<&[u8]>,
        note: Option<&str>,
        info: &str,
    ) -> Option<()> {
        sqlx::query(
            "INSERT INTO audit_conn (guid, type, remote, local, note, info) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(guid)
        .bind(conn_type.map(|t| t as i16))
        .bind(remote)
        .bind(local)
        .bind(note)
        .bind(info)
        .execute(&self.pool)
        .await
        .ok()?;
        Some(())
    }

    #[cfg(any(test, feature = "test-util"))]
    pub(crate) async fn audit_conn_rows(&self, remote: &str) -> Vec<AuditConnRow> {
        sqlx::query("SELECT type, local, end_time, info, note FROM audit_conn WHERE remote = $1 ORDER BY created_at")
            .bind(remote.as_bytes())
            .fetch_all(&self.pool)
            .await
            .unwrap()
            .iter()
            .map(|r| AuditConnRow {
                conn_type: r.get("type"),
                local: r.get("local"),
                end_time: r.get("end_time"),
                info: r.get("info"),
                note: r.get("note"),
            })
            .collect()
    }

    pub async fn update_audit_conn_end_time(&self, guid: &[u8]) -> Option<()> {
        let now_expr = "to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS.MS')";
        let sql = format!(
            "UPDATE audit_conn SET end_time = {} WHERE guid = $1",
            now_expr
        );
        sqlx::query(&sql)
            .bind(guid)
            .execute(&self.pool)
            .await
            .ok()?;
        Some(())
    }

    /// Spec §4: the random session id is the viewer's only proof of participation.
    pub async fn set_audit_conn_note_by_session(&self, id: &str, session_id: u64, note: &str) -> Option<()> {
        let res = sqlx::query(
            "UPDATE audit_conn SET note = $3 WHERE guid = (SELECT guid FROM audit_conn \
             WHERE remote = $1 AND info::jsonb->>'session_id' = $2 ORDER BY created_at DESC LIMIT 1)",
        )
        .bind(id.as_bytes())
        .bind(session_id.to_string())
        .bind(note)
        .execute(&self.pool)
        .await
        .map_err(|e| log::error!("set_audit_conn_note_by_session error: {e:?}"))
        .ok()?;
        (res.rows_affected() > 0).then_some(())
    }

    /// Owner check for §7/§8: rows without a resolved viewer user are open to any logged-in caller.
    pub async fn find_active_audit_conn(
        &self,
        id: &str,
        session_id: &str,
        conn_type: i16,
        caller: &[u8],
    ) -> Option<Vec<u8>> {
        sqlx::query(
            "SELECT guid FROM audit_conn WHERE remote = $1 AND type = $2 AND end_time IS NULL \
             AND info::jsonb->>'session_id' = $3 AND (\"user\" IS NULL OR \"user\" = $4) \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(id.as_bytes())
        .bind(conn_type)
        .bind(session_id)
        .bind(caller)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| log::error!("find_active_audit_conn error: {e:?}"))
        .ok()??
        .try_get("guid")
        .ok()
    }

    pub async fn set_audit_conn_note_by_guid(&self, guid: &[u8], note: &str, caller: &[u8]) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("UPDATE audit_conn SET note = $2 WHERE guid = $1 AND (\"user\" IS NULL OR \"user\" = $3)")
            .bind(guid)
            .bind(note)
            .bind(caller)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_audit_conn_by_nonce(&self, nonce: &str) -> Option<Vec<u8>> {
        sqlx::query("SELECT guid FROM audit_conn WHERE info::jsonb->>'nonce' = $1 LIMIT 1")
            .bind(nonce)
            .fetch_optional(&self.pool)
            .await
            .ok()??
            .try_get("guid")
            .ok()
    }

    /// The most recent open row of one connection; `conn_id` alone repeats after the client restarts.
    pub async fn find_open_audit_conn(&self, id: &str, uuid: &str, conn_id: i64) -> Option<Vec<u8>> {
        sqlx::query(
            "SELECT guid FROM audit_conn WHERE remote = $1 AND end_time IS NULL \
             AND info::jsonb->>'uuid' = $2 AND (info::jsonb->>'conn_id')::bigint = $3 \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(id.as_bytes())
        .bind(uuid)
        .bind(conn_id)
        .fetch_optional(&self.pool)
        .await
        .ok()??
        .try_get("guid")
        .ok()
    }

    pub async fn end_open_audit_conns(&self, id: &str, uuid: &str, conn_id: i64) -> Option<()> {
        sqlx::query(
            "UPDATE audit_conn SET end_time = to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS.MS') \
             WHERE remote = $1 AND end_time IS NULL \
             AND info::jsonb->>'uuid' = $2 AND (info::jsonb->>'conn_id')::bigint = $3",
        )
        .bind(id.as_bytes())
        .bind(uuid)
        .bind(conn_id)
        .execute(&self.pool)
        .await
        .ok()?;
        Some(())
    }

    /// Ends the device's open rows whose connection is not in its heartbeat's `alive` list
    /// (spec §10); rows younger than `grace_secs` may predate the heartbeat's snapshot.
    pub async fn end_audit_conns_not_alive(&self, id: &str, uuid: &str, alive: &[i64], grace_secs: i64) -> Option<()> {
        sqlx::query(
            "UPDATE audit_conn SET end_time = to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS.MS') \
             WHERE remote = $1 AND end_time IS NULL AND info::jsonb->>'uuid' = $2 \
             AND NOT ((info::jsonb->>'conn_id')::bigint = ANY($3)) \
             AND created_at::timestamptz < NOW() - make_interval(secs => $4)",
        )
        .bind(id.as_bytes())
        .bind(uuid)
        .bind(alive)
        .bind(grace_secs as f64)
        .execute(&self.pool)
        .await
        .map_err(|e| log::error!("end_audit_conns_not_alive error: {e:?}"))
        .ok()?;
        Some(())
    }

    /// Stores the `authorized` record: connection type, controller id, and `patch` merged into `info`.
    pub async fn set_audit_conn_authorized(
        &self,
        guid: &[u8],
        conn_type: Option<i16>,
        controller_id: Option<&str>,
        patch: &str,
    ) -> Option<()> {
        sqlx::query(
            "UPDATE audit_conn SET type = $2, local = $3, info = (info::jsonb || $4::jsonb)::text WHERE guid = $1",
        )
        .bind(guid)
        .bind(conn_type)
        .bind(controller_id.map(str::as_bytes))
        .bind(patch)
        .execute(&self.pool)
        .await
        .ok()?;
        Some(())
    }

    pub async fn find_audit_file_by_nonce(&self, nonce: &str) -> bool {
        sqlx::query("SELECT 1 FROM audit_file WHERE info::jsonb->>'nonce' = $1 LIMIT 1")
            .bind(nonce)
            .fetch_optional(&self.pool)
            .await
            .map_or(false, |row| row.is_some())
    }

    pub async fn find_audit_alarm_by_nonce(&self, nonce: &str) -> bool {
        sqlx::query("SELECT 1 FROM audit_alarm WHERE info::jsonb->>'nonce' = $1 LIMIT 1")
            .bind(nonce)
            .fetch_optional(&self.pool)
            .await
            .map_or(false, |row| row.is_some())
    }

    pub async fn insert_audit_file(
        &self,
        guid: &[u8],
        remote: &[u8],
        local: Option<&[u8]>,
        file_type: i8,
        path: &str,
        is_file: bool,
        info: &str,
        user: Option<&[u8]>,
    ) -> Option<()> {
        let is_file_i: i8 = if is_file { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO audit_file (guid, remote, local, type, path, is_file, info, \"user\") VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(guid)
        .bind(remote)
        .bind(local)
        .bind(file_type as i16)
        .bind(path)
        .bind(is_file_i as i16)
        .bind(info)
        .bind(user)
        .execute(&self.pool)
        .await
        .ok()?;
        Some(())
    }

    #[cfg(test)]
    pub(crate) async fn audit_file_row_for_test(&self, nonce: &str) -> AuditFileRow {
        let r = sqlx::query(
            "SELECT remote, local, \"user\", info FROM audit_file WHERE info::jsonb->>'nonce' = $1 LIMIT 1",
        )
        .bind(nonce)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        AuditFileRow {
            remote: r.get("remote"),
            local: r.get("local"),
            user: r.get("user"),
            info: r.get("info"),
        }
    }

    #[cfg(test)]
    pub(crate) async fn audit_alarm_row_for_test(&self, nonce: &str) -> AuditAlarmRow {
        let r = sqlx::query(
            "SELECT \"user\", info FROM audit_alarm WHERE info::jsonb->>'nonce' = $1 LIMIT 1",
        )
        .bind(nonce)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        AuditAlarmRow { user: r.get("user"), info: r.get("info") }
    }

    /// User of a connection's most recent row; file and alarm records carry no ref of their own.
    pub async fn audit_conn_user(&self, id: &str, uuid: &str, conn_id: i64) -> Option<Vec<u8>> {
        sqlx::query(
            "SELECT \"user\" FROM audit_conn WHERE remote = $1 \
             AND info::jsonb->>'uuid' = $2 AND (info::jsonb->>'conn_id')::bigint = $3 \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(id.as_bytes())
        .bind(uuid)
        .bind(conn_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| log::error!("audit_conn_user error: {e:?}"))
        .ok()??
        .try_get("user")
        .ok()
    }

    pub async fn set_audit_conn_user(&self, guid: &[u8], user: &[u8]) -> Option<()> {
        sqlx::query("UPDATE audit_conn SET \"user\" = $2 WHERE guid = $1")
            .bind(guid)
            .bind(user)
            .execute(&self.pool)
            .await
            .map_err(|e| log::error!("set_audit_conn_user error: {e:?}"))
            .ok()?;
        Some(())
    }

    pub async fn insert_audit_alarm(
        &self,
        guid: &[u8],
        alarm_type: i8,
        info: &str,
        user: Option<&[u8]>,
        device: Option<&[u8]>,
    ) -> Option<()> {
        sqlx::query(
            "INSERT INTO audit_alarm (guid, type, info, \"user\", device) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(guid)
        .bind(alarm_type as i16)
        .bind(info)
        .bind(user)
        .bind(device)
        .execute(&self.pool)
        .await
        .ok()?;
        Some(())
    }

    /// Whether `(id, uuid)` is a device hbbs registered; `uuid` is base64 as in device records.
    pub async fn is_registered_device(&self, id: &str, uuid: &str) -> bool {
        let Ok(uuid) = BASE64_STANDARD.decode(uuid) else { return false };
        sqlx::query_scalar::<_, i32>("SELECT 1 FROM peer WHERE id = $1 AND uuid = $2")
            .bind(id)
            .bind(uuid)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| log::error!("is_registered_device error: {e:?}"))
            .ok()
            .flatten()
            .is_some()
    }

    /// Stores a ref minted for `user`; refs a day old are dropped, a connection uses its ref within seconds.
    pub async fn insert_audit_conn_ref(&self, conn_ref: &str, user: &[u8], target: &str) -> Option<()> {
        sqlx::query("DELETE FROM audit_conn_ref WHERE created_at < now() - interval '1 day'")
            .execute(&self.pool)
            .await
            .map_err(|e| log::error!("insert_audit_conn_ref purge error: {e:?}"))
            .ok()?;
        sqlx::query("INSERT INTO audit_conn_ref (ref, \"user\", target) VALUES ($1, $2, $3)")
            .bind(conn_ref)
            .bind(user)
            .bind(target)
            .execute(&self.pool)
            .await
            .map_err(|e| log::error!("insert_audit_conn_ref error: {e:?}"))
            .ok()?;
        Some(())
    }

    /// The viewer behind `conn_ref`, when it was minted for a connection to `target`.
    pub async fn resolve_audit_conn_ref(&self, conn_ref: &str, target: &str) -> Option<Vec<u8>> {
        sqlx::query("SELECT \"user\" FROM audit_conn_ref WHERE ref = $1 AND target = $2")
            .bind(conn_ref)
            .bind(target)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| log::error!("resolve_audit_conn_ref error: {e:?}"))
            .ok()??
            .try_get("user")
            .map_err(|e| log::error!("resolve_audit_conn_ref decode error: {e:?}"))
            .ok()
    }

    /// Records a native client's OIDC login: the machine, its user, and the login time.
    /// Last login wins: an existing row moves to whoever signed in on the machine most recently.
    pub async fn upsert_viewer_device(&self, id: &str, uuid: &str, hostname: &str, os: &str, login_ip: &str, user: &[u8]) -> Option<()> {
        sqlx::query(
            "INSERT INTO viewer_device (id, uuid, hostname, os, login_ip, \"user\") VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id, uuid, \"user\") DO UPDATE SET hostname = EXCLUDED.hostname, os = EXCLUDED.os, \
             login_ip = EXCLUDED.login_ip, last_login = now(), last_seen = now()",
        )
        .bind(id)
        .bind(uuid)
        .bind(hostname)
        .bind(os)
        .bind(login_ip)
        .bind(user)
        .execute(&self.pool)
        .await
        .map_err(|e| log::error!("upsert_viewer_device error: {e:?}"))
        .ok()?;
        Some(())
    }

    pub async fn viewer_machine(&self, id: &str, user: &[u8]) -> Option<(String, String, String)> {
        sqlx::query_as(
            "SELECT hostname, os, login_ip FROM viewer_device WHERE id = $1 AND \"user\" = $2 ORDER BY last_login DESC LIMIT 1",
        )
        .bind(id)
        .bind(user)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| log::error!("viewer_machine error: {e:?}"))
        .ok()?
    }

    pub async fn insert_audit_login(&self, r: &utils::LoginRecord) -> Option<()> {
        sqlx::query(
            "INSERT INTO audit_login (outcome, detail, client, \"user\", user_name, rustdesk_id, hostname, os, ip) \
             VALUES ($1, $2, $3, (SELECT guid FROM \"user\" WHERE oidc_sub = $4), $5, $6, $7, $8, $9)",
        )
        .bind(r.outcome)
        .bind(&r.detail)
        .bind(r.client)
        .bind(&r.sub)
        .bind(&r.user_name)
        .bind(&r.rustdesk_id)
        .bind(&r.hostname)
        .bind(&r.os)
        .bind(&r.ip)
        .execute(&self.pool)
        .await
        .map_err(|e| log::error!("insert_audit_login error: {e:?}"))
        .ok()?;
        Some(())
    }

    /// A device's stored info JSON. Test-only.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_peer_info(&self, id: &str) -> String {
        sqlx::query_scalar("SELECT info FROM peer WHERE id = $1").bind(id).fetch_one(&self.pool).await.expect("peer info")
    }

    /// Registers a device as hbbs would; `uuid` is base64 as in device records. Test-only.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_register_device(&self, id: &str, uuid: &str) {
        let uuid = BASE64_STANDARD.decode(uuid).expect("base64 uuid");
        sqlx::query("INSERT INTO peer (guid, id, uuid, pk, info) VALUES ($1, $2, $3, $4, '{}')")
            .bind(Uuid::new_v4().as_bytes().to_vec())
            .bind(id)
            .bind(uuid)
            .bind(vec![0u8; 32])
            .execute(&self.pool)
            .await
            .expect("insert peer");
    }

    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_age_viewer_device(&self, id: &str, secs: i64) {
        sqlx::query(
            "UPDATE viewer_device SET first_seen = first_seen - make_interval(secs => $2), \
             last_login = last_login - make_interval(secs => $2), last_seen = last_seen - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(id)
        .bind(secs as f64)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    /// Bumps `last_seen` of a machine `user` logged in on; returns whether a row matched.
    pub async fn touch_viewer_device(&self, id: &str, uuid: &str, user: &[u8]) -> Option<bool> {
        let res = sqlx::query("UPDATE viewer_device SET last_seen = now() WHERE id = $1 AND uuid = $2 AND \"user\" = $3")
            .bind(id)
            .bind(uuid)
            .bind(user)
            .execute(&self.pool)
            .await
            .map_err(|e| log::error!("touch_viewer_device error: {e:?}"))
            .ok()?;
        Some(res.rows_affected() > 0)
    }

    /// Viewer machines, most recently seen first; IDs that registered with hbbs are devices, not viewers.
    pub async fn list_viewer_devices(&self, offset: i64, limit: i64) -> Option<(i64, Vec<utils::ViewerDevice>)> {
        const WHERE: &str = "WHERE NOT EXISTS (SELECT 1 FROM peer p WHERE p.id = v.id)";
        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM viewer_device v {WHERE}"))
            .fetch_one(&self.pool)
            .await
            .map_err(|e| log::error!("list_viewer_devices count error: {e:?}"))
            .ok()?;
        let rows = sqlx::query(&format!(
            "SELECT v.id, v.hostname, v.os, v.login_ip, u.name AS user_name, \
               extract(epoch FROM v.first_seen)::bigint AS first_seen, \
               extract(epoch FROM v.last_login)::bigint AS last_login, \
               extract(epoch FROM v.last_seen)::bigint AS last_seen \
             FROM viewer_device v LEFT JOIN \"user\" u ON u.guid = v.\"user\" {WHERE} \
             ORDER BY v.last_seen DESC, v.id, v.uuid, v.\"user\" LIMIT $1 OFFSET $2"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| log::error!("list_viewer_devices query error: {e:?}"))
        .ok()?;
        let mut data = Vec::with_capacity(rows.len());
        for row in &rows {
            data.push(utils::ViewerDevice {
                id: row.try_get("id").ok()?,
                hostname: row.try_get("hostname").ok()?,
                os: row.try_get("os").ok()?,
                login_ip: row.try_get("login_ip").ok()?,
                user: row.try_get("user_name").ok()?,
                first_seen: row.try_get("first_seen").ok()?,
                last_login: row.try_get("last_login").ok()?,
                last_seen: row.try_get("last_seen").ok()?,
            });
        }
        Some((total, data))
    }

    /// Admin read API (audit-api-spec.md §9): newest first, `created_at` filters at/after (UTC).
    pub async fn list_audit_conns(&self, q: &utils::AuditQuery) -> Option<(i64, Vec<utils::AuditConnLog>)> {
        const WHERE: &str = "WHERE ($1::text IS NULL OR a.created_at::timestamptz >= ($1::timestamp AT TIME ZONE 'UTC')) \
             AND ($2::text IS NULL OR convert_from(a.remote, 'UTF8') LIKE $2) \
             AND ($3::smallint IS NULL OR a.type = $3)";

        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM audit_conn a {WHERE}"))
            .bind(&q.created_at)
            .bind(&q.pattern)
            .bind(q.conn_type)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| log::error!("list_audit_conns count error: {e:?}"))
            .ok()?;

        let rows = sqlx::query(&format!(
            "SELECT a.guid, convert_from(a.remote, 'UTF8') AS remote, \
               (SELECT COALESCE(NULLIF(p.info, ''), '{{}}')::jsonb->>'hostname' FROM peer p WHERE p.id = convert_from(a.remote, 'UTF8')) AS remote_name, \
               convert_from(a.local, 'UTF8') AS peer_id, i->>'peer_name' AS peer_name, \
               i->>'peer_hostname' AS peer_hostname, i->>'peer_os' AS peer_os, i->>'peer_login_ip' AS peer_login_ip, u.name AS user_name, \
               i->>'ip' AS ip, a.type, (i->>'primary_auth')::int AS primary_auth, (i->>'two_factor')::int AS two_factor, \
               i->>'session_id' AS session_id, (i->>'conn_id')::bigint AS conn_id, \
               extract(epoch FROM a.created_at::timestamptz)::bigint AS created_at, \
               extract(epoch FROM a.end_time::timestamptz)::bigint AS end_time, a.note \
             FROM audit_conn a CROSS JOIN LATERAL (SELECT a.info::jsonb AS i) j \
             LEFT JOIN \"user\" u ON u.guid = a.\"user\" {WHERE} \
             ORDER BY a.created_at::timestamptz DESC LIMIT $4 OFFSET $5"
        ))
        .bind(&q.created_at)
        .bind(&q.pattern)
        .bind(q.conn_type)
        .bind(q.limit)
        .bind(q.offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| log::error!("list_audit_conns query error: {e:?}"))
        .ok()?;

        let mut data = Vec::with_capacity(rows.len());
        for row in &rows {
            data.push(audit_conn_log_from_row(row)?);
        }
        Some((total, data))
    }

    /// Admin read API (audit-api-spec.md §9): file transfer / clipboard-file rows.
    ///
    /// `info.info` is read as plain jsonb (`j.i->'info'`, never cast from text) because a
    /// client-controlled `POST /api/audit/file` can store a non-JSON string there (§12.1 is
    /// unauthenticated); casting that string to jsonb in SQL would 500 every page. Parsing
    /// happens in Rust instead, in `audit_file_log_from_row`.
    pub async fn list_audit_files(&self, q: &utils::AuditQuery) -> Option<(i64, Vec<utils::AuditFileLog>)> {
        const WHERE: &str = "WHERE ($1::text IS NULL OR a.created_at::timestamptz >= ($1::timestamp AT TIME ZONE 'UTC')) \
             AND ($2::text IS NULL OR convert_from(a.remote, 'UTF8') LIKE $2)";

        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM audit_file a {WHERE}"))
            .bind(&q.created_at)
            .bind(&q.pattern)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| log::error!("list_audit_files count error: {e:?}"))
            .ok()?;

        let rows = sqlx::query(&format!(
            "SELECT a.guid, convert_from(a.remote, 'UTF8') AS remote, convert_from(a.local, 'UTF8') AS peer_id, \
               u.name AS user_name, a.type, a.path, a.is_file, \
               extract(epoch FROM a.created_at::timestamptz)::bigint AS created_at, \
               j.i->'info' AS raw_info \
             FROM audit_file a CROSS JOIN LATERAL (SELECT a.info::jsonb AS i) j \
             LEFT JOIN \"user\" u ON u.guid = a.\"user\" {WHERE} \
             ORDER BY a.created_at::timestamptz DESC LIMIT $3 OFFSET $4"
        ))
        .bind(&q.created_at)
        .bind(&q.pattern)
        .bind(q.limit)
        .bind(q.offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| log::error!("list_audit_files query error: {e:?}"))
        .ok()?;

        let mut data = Vec::with_capacity(rows.len());
        for row in &rows {
            data.push(audit_file_log_from_row(row)?);
        }
        Some((total, data))
    }

    /// Admin read API (audit-api-spec.md §9): security alarm rows.
    ///
    /// Same reasoning as `list_audit_files`: `info.info` is read as plain jsonb and parsed in
    /// Rust (`audit_alarm_log_from_row`), never cast from text in SQL.
    pub async fn list_audit_alarms(&self, q: &utils::AuditQuery) -> Option<(i64, Vec<utils::AuditAlarmLog>)> {
        const WHERE: &str = "WHERE ($1::text IS NULL OR a.created_at::timestamptz >= ($1::timestamp AT TIME ZONE 'UTC')) \
             AND ($2::text IS NULL OR convert_from(a.device, 'UTF8') LIKE $2)";

        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM audit_alarm a {WHERE}"))
            .bind(&q.created_at)
            .bind(&q.pattern)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| log::error!("list_audit_alarms count error: {e:?}"))
            .ok()?;

        let rows = sqlx::query(&format!(
            "SELECT a.guid, a.type, convert_from(a.device, 'UTF8') AS device, u.name AS user_name, \
               j.i->'info' AS raw_info, \
               extract(epoch FROM a.created_at::timestamptz)::bigint AS created_at \
             FROM audit_alarm a CROSS JOIN LATERAL (SELECT a.info::jsonb AS i) j \
             LEFT JOIN \"user\" u ON u.guid = a.\"user\" {WHERE} \
             ORDER BY a.created_at::timestamptz DESC LIMIT $3 OFFSET $4"
        ))
        .bind(&q.created_at)
        .bind(&q.pattern)
        .bind(q.limit)
        .bind(q.offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| log::error!("list_audit_alarms query error: {e:?}"))
        .ok()?;

        let mut data = Vec::with_capacity(rows.len());
        for row in &rows {
            data.push(audit_alarm_log_from_row(row)?);
        }
        Some((total, data))
    }

    /// Admin read API: login rows, newest first; `q.pattern` is a LIKE pattern on the user name.
    pub async fn list_audit_logins(&self, q: &utils::AuditQuery, outcome: Option<&str>) -> Option<(i64, Vec<utils::AuditLoginLog>)> {
        const WHERE: &str = "WHERE ($1::text IS NULL OR created_at >= ($1::timestamp AT TIME ZONE 'UTC')) \
             AND ($2::text IS NULL OR user_name LIKE $2) AND ($3::text IS NULL OR outcome = $3)";

        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM audit_login {WHERE}"))
            .bind(&q.created_at)
            .bind(&q.pattern)
            .bind(outcome)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| log::error!("list_audit_logins count error: {e:?}"))
            .ok()?;

        let rows: Vec<(String, i64, String, String, String, String, String, String, String, String)> = sqlx::query_as(&format!(
            "SELECT guid::text, extract(epoch FROM created_at)::bigint, outcome, detail, client, user_name, \
               rustdesk_id, hostname, os, ip FROM audit_login {WHERE} \
             ORDER BY created_at DESC LIMIT $4 OFFSET $5"
        ))
        .bind(&q.created_at)
        .bind(&q.pattern)
        .bind(outcome)
        .bind(q.limit)
        .bind(q.offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| log::error!("list_audit_logins query error: {e:?}"))
        .ok()?;

        let data = rows
            .into_iter()
            .map(|(guid, created_at, outcome, detail, client, user, rustdesk_id, hostname, os, ip)| utils::AuditLoginLog {
                guid, created_at, outcome, detail, client, user, rustdesk_id, hostname, os, ip,
            })
            .collect();
        Some((total, data))
    }
}

/// Rows written before this branch double-encoded `info.info` as a JSON string, and an
/// unauthenticated client can store an arbitrary non-JSON string there (§12.1). Parse a JSON
/// string's content when it is itself valid JSON; otherwise keep it as the plain string value.
fn normalise_audit_info(raw: Option<serde_json::Value>) -> serde_json::Value {
    match raw {
        Some(serde_json::Value::String(s)) => {
            serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s))
        }
        Some(v) => v,
        None => serde_json::Value::Null,
    }
}

/// `try_get` one column, logging and returning `None` on a mapping error (database.rs audit reads).
fn audit_try_get<'r, T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>>(
    row: &'r sqlx::postgres::PgRow,
    column: &'static str,
) -> Option<T> {
    row.try_get(column)
        .map_err(|e| log::error!("audit read: column {column} error: {e:?}"))
        .ok()
}

fn audit_conn_log_from_row(row: &sqlx::postgres::PgRow) -> Option<utils::AuditConnLog> {
    let guid: Vec<u8> = audit_try_get(row, "guid")?;
    let end_time: Option<i64> = audit_try_get(row, "end_time")?;
    Some(utils::AuditConnLog {
        guid: guid_into_uuid(guid)?,
        remote: audit_try_get(row, "remote")?,
        remote_name: audit_try_get(row, "remote_name")?,
        peer_id: audit_try_get(row, "peer_id")?,
        peer_name: audit_try_get(row, "peer_name")?,
        peer_hostname: audit_try_get(row, "peer_hostname")?,
        peer_os: audit_try_get(row, "peer_os")?,
        peer_login_ip: audit_try_get(row, "peer_login_ip")?,
        user: audit_try_get(row, "user_name")?,
        ip: audit_try_get(row, "ip")?,
        conn_type: audit_try_get(row, "type")?,
        primary_auth: audit_try_get(row, "primary_auth")?,
        two_factor: audit_try_get(row, "two_factor")?,
        session_id: audit_try_get(row, "session_id")?,
        conn_id: audit_try_get(row, "conn_id")?,
        created_at: audit_try_get(row, "created_at")?,
        end_time,
        note: audit_try_get(row, "note")?,
        active: end_time.is_none(),
    })
}

fn audit_file_log_from_row(row: &sqlx::postgres::PgRow) -> Option<utils::AuditFileLog> {
    let guid: Vec<u8> = audit_try_get(row, "guid")?;
    let is_file: i16 = audit_try_get(row, "is_file")?;
    let raw_info: Option<serde_json::Value> = audit_try_get(row, "raw_info")?;
    let info = normalise_audit_info(raw_info);
    Some(utils::AuditFileLog {
        guid: guid_into_uuid(guid)?,
        remote: audit_try_get(row, "remote")?,
        peer_id: audit_try_get(row, "peer_id")?,
        user: audit_try_get(row, "user_name")?,
        direction: audit_try_get(row, "type")?,
        path: audit_try_get(row, "path")?,
        is_file: is_file != 0,
        num: info.get("num").and_then(serde_json::Value::as_i64),
        files: info.get("files").cloned(),
        ip: info.get("ip").and_then(serde_json::Value::as_str).map(str::to_owned),
        created_at: audit_try_get(row, "created_at")?,
    })
}

fn audit_alarm_log_from_row(row: &sqlx::postgres::PgRow) -> Option<utils::AuditAlarmLog> {
    let guid: Vec<u8> = audit_try_get(row, "guid")?;
    let raw_info: Option<serde_json::Value> = audit_try_get(row, "raw_info")?;
    Some(utils::AuditAlarmLog {
        guid: guid_into_uuid(guid)?,
        typ: audit_try_get(row, "type")?,
        device: audit_try_get(row, "device")?,
        user: audit_try_get(row, "user_name")?,
        info: normalise_audit_info(raw_info),
        created_at: audit_try_get(row, "created_at")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::AbTag;

    async fn bare_db() -> Database {
        Database::new(&crate::testing::fresh_database_url().await)
            .await
            .unwrap()
    }

    /// A database with an OIDC user `admin` promoted to admin, as most tests expect.
    async fn test_db() -> Database {
        let db = bare_db().await;
        db.get_user_for_oauth2("admin", "admin", Some("admin@example.org"))
            .await
            .unwrap();
        db.set_admin("admin@example.org", true).await.unwrap();
        db
    }

    macro_rules! db_test {
        ($name:ident, |$db:ident| $body:block) => {
            #[tokio::test]
            async fn $name() {
                let $db = test_db().await;
                $body
            }
        };
    }

    #[tokio::test]
    async fn new_fails_fast_on_unreachable_database() {
        // Port 1 refuses connections; a single attempt must return an error, not hang or panic,
        // and the error must carry the real cause rather than sqlx's internal pool-timeout wrapper.
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Database::new("postgres://postgres:postgres@127.0.0.1:1/none"),
        )
        .await
        .expect("Database::new did not return");
        let msg = match res {
            Ok(_) => panic!("connecting to a port that refuses connections must fail"),
            Err(e) => e.to_string(),
        };
        assert!(
            !msg.to_lowercase().contains("pool timed out"),
            "error should surface the underlying cause, not sqlx's pool-timeout wrapper: {msg}"
        );
    }

    #[test]
    fn is_migrate_error_distinguishes_permanent_migration_failures_from_connection_errors() {
        let migrate: DbError = Box::new(sqlx::migrate::MigrateError::VersionMissing(1));
        assert!(is_migrate_error(&migrate));

        let connection: DbError = Box::new(std::io::Error::other("connection refused"));
        assert!(!is_migrate_error(&connection));
    }

    #[tokio::test]
    async fn connect_with_retry_returns_once_database_is_reachable() {
        let url = crate::testing::fresh_database_url().await;
        let db = Database::connect_with_retry(&url).await;
        let (groups,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM grp WHERE name = 'Default'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(groups, 1, "migrations ran");
    }

    #[tokio::test]
    async fn migrations_are_applied_and_idempotent() {
        let url = crate::testing::fresh_database_url().await;
        let first = Database::new(&url).await.unwrap();
        let applied: Vec<(i64, bool)> =
            sqlx::query_as("SELECT version, success FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&first.pool)
                .await
                .unwrap();
        assert_eq!(applied, (1..=11).map(|v| (v, true)).collect::<Vec<_>>());
        first.pool.close().await;

        // Second start on the same database must not fail or duplicate rows.
        let second = Database::new(&url).await.unwrap();
        let (groups,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM grp WHERE name = 'Default'")
            .fetch_one(&second.pool)
            .await
            .unwrap();
        assert_eq!(groups, 1);
    }

    #[tokio::test]
    async fn migrations_create_the_unlogged_presence_tables() {
        let db = bare_db().await;
        let tables: Vec<(String, String)> = sqlx::query_as(
            "SELECT relname::text, relpersistence::text FROM pg_class \
             WHERE relname IN ('hbbs_pod', 'peer_presence') ORDER BY relname",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        assert_eq!(tables, vec![("hbbs_pod".into(), "u".into()), ("peer_presence".into(), "u".into())]);
        let index: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_indexes WHERE indexname = 'peer_presence_pod'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(index, 1);
    }

    db_test!(find_default_admin_user, |db| {
        let (_, result) = db.find_user_by_name("admin").await;
        assert!(result.is_some());
        let (user_id, email, info) = result.unwrap();
        assert!(!user_id.is_empty());
        assert_eq!(email, Some("admin@example.org".to_string()));
        assert!(info.admin);
        assert!(info.active);
    });

    db_test!(find_nonexistent_user, |db| {
        let (_, result) = db.find_user_by_name("nonexistent").await;
        assert!(result.is_none());
    });

    #[tokio::test]
    async fn migrations_remove_the_seeded_admin() {
        let db = bare_db().await;
        assert!(db.find_user_by_name("admin").await.1.is_none());
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM \"user\"")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(users, 0);
        let personal: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ab WHERE personal = 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(personal, 0, "the seeded admin's personal address book goes with it");
    }

    #[tokio::test]
    async fn migrations_drop_the_password_column() {
        let db = bare_db().await;
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'user' AND column_name = 'password'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn oauth2_login_never_promotes() {
        let db = bare_db().await;
        let (_, _, info) = db
            .get_user_for_oauth2("first", "first", Some("first@example.org"))
            .await
            .unwrap();
        assert!(!info.admin, "admins are promoted manually, never by logging in");
    }

    #[tokio::test]
    async fn promote_makes_an_active_admin_and_adopts_ownerless_shared_books() {
        let db = bare_db().await;
        let (user_id, _, _) = db
            .get_user_for_oauth2("first", "first", Some("first@example.org"))
            .await
            .unwrap();
        assert_eq!(db.set_admin("first@example.org", true).await.unwrap(), "first");
        let (_, found) = db.find_user_by_name("first").await;
        let (_, _, info) = found.unwrap();
        assert!(info.admin && info.active);

        let owners: Vec<Vec<u8>> = sqlx::query_scalar("SELECT owner FROM ab WHERE personal = 0")
            .fetch_all(&db.pool)
            .await
            .unwrap();
        assert!(!owners.is_empty(), "the seeded shared address book is kept");
        assert!(owners.iter().all(|o| *o == user_id));
    }

    db_test!(demote_removes_admin, |db| {
        assert!(db.set_admin("admin@example.org", false).await.is_ok());
        let (_, found) = db.find_user_by_name("admin").await;
        assert!(!found.unwrap().2.admin);
    });

    db_test!(set_admin_on_unknown_user_fails, |db| {
        assert!(db.set_admin("nobody@example.org", true).await.is_err());
    });

    db_test!(same_display_name_different_people_get_different_accounts, |db| {
        let (a, _, _) = db.get_user_for_oauth2("sub-a", "John Smith", Some("john.a@example.org")).await.unwrap();
        let (b, _, _) = db.get_user_for_oauth2("sub-b", "John Smith", Some("john.b@example.org")).await.unwrap();
        assert_ne!(a, b, "a second John Smith must not get the first one's account");
        let books: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ab WHERE personal = 1 AND owner IN ($1, $2)")
            .bind(&a)
            .bind(&b)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(books, 2, "each gets a personal address book");
    });

    db_test!(same_subject_is_the_same_account_even_after_a_rename, |db| {
        let (a, _, _) = db.get_user_for_oauth2("sub-x", "Old Name", Some("x@example.org")).await.unwrap();
        let (b, name, _) = db.get_user_for_oauth2("sub-x", "New Name", Some("x@example.org")).await.unwrap();
        assert_eq!(a, b);
        assert_eq!(name, "New Name", "display name follows the IdP");
    });

    db_test!(users_without_email_do_not_collide, |db| {
        let (a, _, _) = db.get_user_for_oauth2("sub-1", "One", None).await.unwrap();
        let (b, _, _) = db.get_user_for_oauth2("sub-2", "Two", None).await.unwrap();
        assert_ne!(a, b);
    });

    db_test!(an_account_without_subject_is_adopted_by_email, |db| {
        db.add_user("pre".to_string(), "pre@example.org".to_string(), false, "Default".to_string()).await.unwrap();
        let (_, found) = db.find_user_by_name("pre").await;
        let (pre_id, _, _) = found.unwrap();
        let (id, name, _) = db.get_user_for_oauth2("sub-pre", "Pre Provisioned", Some("pre@example.org")).await.unwrap();
        assert_eq!(id, pre_id, "the pre-created account is linked, not duplicated");
        assert_eq!(name, "Pre Provisioned");
    });

    db_test!(set_admin_matches_the_email_only, |db| {
        db.get_user_for_oauth2("sub-a", "John Smith", Some("John.Smith@example.org")).await.unwrap();
        assert!(db.set_admin("John Smith", true).await.is_err(), "a name is not an email");
        assert!(db.set_admin("sub-a", true).await.is_err(), "a subject is not an email");
        assert_eq!(db.set_admin("john.smith@example.org", true).await.unwrap(), "John Smith", "case-insensitive");
    });

    db_test!(set_admin_refuses_an_email_shared_by_several_users, |db| {
        db.get_user_for_oauth2("sub-a", "John A", Some("shared@example.org")).await.unwrap();
        db.get_user_for_oauth2("sub-b", "John B", Some("shared@example.org")).await.unwrap();
        let err = db.set_admin("shared@example.org", true).await.unwrap_err();
        assert!(err.contains("2 users") && err.contains("John A") && err.contains("John B"), "{err}");
    });

    db_test!(get_user_for_oauth2_creates_inactive_non_admin_user, |db| {
        // OAUTH2_CREATE_USER is unset, so the new user is inactive non-admin.
        assert!(std::env::var("OAUTH2_CREATE_USER").is_err());
        let result = db
            .get_user_for_oauth2("oauth2-test-user", "oauth2-test-user", Some("oauth2-test@example.org"))
            .await;
        assert!(result.is_some());
        let (_, name, info) = result.unwrap();
        assert_eq!(name, "oauth2-test-user");
        assert!(!info.active, "status defaults to inactive without OAUTH2_CREATE_USER=1");
        assert!(!info.admin, "role is always non-admin for oauth2-provisioned users");
    });

    db_test!(add_user_and_find, |db| {
        let result = db
            .add_user(
                "testuser".to_string(),
                "test@example.com".to_string(),
                false,
                "Default".to_string(),
            )
            .await;
        assert!(result.is_some());
        let (_, found) = db.find_user_by_name("testuser").await;
        assert!(found.is_some());
        let (_, _, info) = found.unwrap();
        assert!(info.active);
        assert!(!info.admin);
    });

    db_test!(add_admin_user, |db| {
        db.add_user(
            "superadmin".to_string(),
            "super@example.com".to_string(),
            true,
            "Default".to_string(),
        )
        .await;
        let (_, found) = db.find_user_by_name("superadmin").await;
        let (_, _, info) = found.unwrap();
        assert!(info.admin);
    });

    db_test!(ui_get_all_users_returns_admin, |db| {
        let users = db.ui_get_all_users().await;
        assert!(users.is_some());
        let users = users.unwrap();
        assert!(!users.is_empty());
        assert!(users.iter().any(|u| u.username == "admin"));
    });

    db_test!(ui_get_user_info, |db| {
        let info = db.ui_get_user_info("admin".to_string()).await;
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.username, "admin");
        assert!(info.admin);
        assert!(info.active);
    });

    db_test!(ui_get_user_info_nonexistent, |db| {
        let info = db.ui_get_user_info("nobody".to_string()).await;
        assert!(info.is_none());
    });

    db_test!(delete_user_invalid_uuid, |db| {
        let result = db.delete_user("not-a-uuid").await;
        assert!(result.is_none());
    });

    async fn session_exists(db: &Database, id: &str) -> bool {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM session WHERE id = $1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        n == 1
    }

    db_test!(insert_session_removes_expired_sessions, |db| {
        let user = admin_guid(&db).await;
        db.insert_session("expired", &user, -60).await.unwrap();
        db.insert_session("valid", &user, 3600).await.unwrap();
        db.insert_session("new", &user, 3600).await.unwrap();
        assert!(!session_exists(&db, "expired").await);
        assert!(session_exists(&db, "valid").await);
        assert!(session_exists(&db, "new").await);
    });

    db_test!(delete_user_removes_their_sessions, |db| {
        let (user, _, _) = db.get_user_for_oauth2("bob", "bob", None).await.unwrap();
        let admin = admin_guid(&db).await;
        db.insert_session("bob-session", &user, 3600).await.unwrap();
        db.insert_session("admin-session", &admin, 3600).await.unwrap();
        let guid = Uuid::from_slice(&user).unwrap().to_string();
        db.delete_user(&guid).await.unwrap();
        assert!(!session_exists(&db, "bob-session").await);
        assert!(session_exists(&db, "admin-session").await);
    });

    db_test!(user_change_status, |db| {
        let (_, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let guid = Uuid::from_slice(&user_id).unwrap().to_string();
        let result = db.user_change_status(&guid, 0).await;
        assert!(result.is_some());
        let (_, found) = db.find_user_by_name("admin").await;
        let (_, _, info) = found.unwrap();
        assert!(!info.active);
    });

    db_test!(user_change_status_invalid_uuid, |db| {
        let result = db.user_change_status("invalid", 0).await;
        assert!(result.is_none());
    });

    db_test!(get_all_users_with_pagination, |db| {
        db.add_user(
            "user1".to_string(),
            "u1@e.com".to_string(),
            false,
            "Default".to_string(),
        )
        .await;
        db.add_user(
            "user2".to_string(),
            "u2@e.com".to_string(),
            false,
            "Default".to_string(),
        )
        .await;
        let all = db.get_all_users(None, None, 1, 100).await;
        assert!(all.is_some());
        assert!(all.unwrap().len() >= 3);

        let page = db.get_all_users(None, None, 1, 1).await;
        assert!(page.is_some());
        assert_eq!(page.unwrap().len(), 1);
    });

    db_test!(get_all_users_with_name_filter, |db| {
        let filtered = db.get_all_users(Some("admin"), None, 1, 100).await;
        assert!(filtered.is_some());
        let filtered = filtered.unwrap();
        assert_eq!(filtered.len(), 1);
        // Seeded admin in 0001_initial.sql: status=1 (active), role=1 (admin).
        assert_eq!(filtered[0].status, 1);
        assert!(filtered[0].is_admin);
    });

    db_test!(get_all_users_current_zero_defaults_to_one, |db| {
        let result = db.get_all_users(None, None, 0, 100).await;
        assert!(result.is_some());
    });

    db_test!(get_ab_personal_guid_for_admin, |db| {
        let (_, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let guid = db.get_ab_personal_guid(user_id).await;
        assert!(guid.is_some());
        assert!(Uuid::parse_str(&guid.unwrap()).is_ok());
    });

    db_test!(get_groups_returns_default, |db| {
        let groups = db.get_groups(0, 100).await;
        assert!(groups.is_some());
        let groups = groups.unwrap();
        assert!(!groups.is_empty());
        assert!(groups.iter().any(|g| g.name == "Default"));
    });

    db_test!(create_and_get_group, |db| {
        let result = db.create_group("TestGroup", "Default", "A note").await;
        assert!(result.is_some());
        let groups = db.get_groups(0, 100).await.unwrap();
        let found = groups.iter().find(|g| g.name == "TestGroup");
        assert!(found.is_some());
        assert_eq!(found.unwrap().note, Some("A note".to_string()));
    });

    db_test!(update_group, |db| {
        db.create_group("OldName", "Default", "old").await;
        let groups = db.get_groups(0, 100).await.unwrap();
        let group = groups.iter().find(|g| g.name == "OldName").unwrap();
        let result = db
            .update_group(&group.guid, "NewName", "Default", "new")
            .await;
        assert!(result.is_some());
        let updated = db.get_group(&group.guid).await;
        assert!(updated.is_some());
        assert_eq!(updated.unwrap().name, "NewName");
    });

    db_test!(delete_group, |db| {
        db.create_group("ToDelete", "Default", "").await;
        let groups = db.get_groups(0, 100).await.unwrap();
        let group = groups.iter().find(|g| g.name == "ToDelete").unwrap();
        let result = db.delete_group(&group.guid).await;
        assert!(result.is_some());
        let after = db.get_group(&group.guid).await;
        assert!(after.is_none());
    });

    db_test!(delete_group_invalid_uuid, |db| {
        let result = db.delete_group("bad-uuid").await;
        assert!(result.is_none());
    });

    db_test!(get_group_invalid_uuid, |db| {
        let result = db.get_group("bad-uuid").await;
        assert!(result.is_none());
    });

    db_test!(default_strategy_is_seeded_and_empty, |db| {
        let list = db.list_strategies().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].guid, utils::policy::DEFAULT_STRATEGY_GUID);
        assert_eq!(list[0].name, "Default");
        let (s, options) = db.get_strategy(utils::policy::DEFAULT_STRATEGY_GUID).await.unwrap();
        assert!(s.modified_at > 0);
        assert!(options.is_empty());
    });

    db_test!(set_strategy_options_saves_and_bumps, |db| {
        let guid = utils::policy::DEFAULT_STRATEGY_GUID;
        let before = db.get_strategy(guid).await.unwrap().0.modified_at;
        let opts: std::collections::BTreeMap<String, String> =
            [("enable-clipboard".to_string(), "N".to_string())].into();
        let m1 = db.set_strategy_options(guid, &opts).await.unwrap();
        let m2 = db.set_strategy_options(guid, &opts).await.unwrap();
        assert!(m1 > before && m2 > m1, "{before} {m1} {m2}");
        let (s, saved) = db.get_strategy(guid).await.unwrap();
        assert_eq!((s.modified_at, saved), (m2, opts));
    });

    db_test!(bump_strategy_changes_only_modified_at, |db| {
        let guid = utils::policy::DEFAULT_STRATEGY_GUID;
        let opts: std::collections::BTreeMap<String, String> =
            [("access-mode".to_string(), "view".to_string())].into();
        let m1 = db.set_strategy_options(guid, &opts).await.unwrap();
        let m2 = db.bump_strategy(guid).await.unwrap();
        assert!(m2 > m1);
        assert_eq!(db.get_strategy(guid).await.unwrap().1, opts);
    });

    db_test!(unknown_strategy_is_none, |db| {
        let unknown = "00000000-0000-0000-0000-000000000000";
        assert!(db.get_strategy(unknown).await.is_none());
        assert!(db.get_strategy("not-a-guid").await.is_none());
        assert!(db.set_strategy_options(unknown, &Default::default()).await.is_none());
        assert!(db.bump_strategy(unknown).await.is_none());
    });

    db_test!(add_user_with_group, |db| {
        let result = db
            .add_user(
                "groupuser".to_string(),
                "group@test.com".to_string(),
                false,
                "Default".to_string(),
            )
            .await;
        assert!(result.is_some());
        let (_, found) = db.find_user_by_name("groupuser").await;
        assert!(found.is_some());
    });

    db_test!(add_user_nonexistent_group_fails, |db| {
        let result = db
            .add_user(
                "baduser".to_string(),
                "bad@test.com".to_string(),
                false,
                "NonexistentGroup".to_string(),
            )
            .await;
        assert!(result.is_none());
    });

    db_test!(ab_tag_crud, |db| {
        let (_, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let ab_guid = db.get_ab_personal_guid(user_id).await.unwrap();

        let tag = AbTag {
            name: "important".to_string(),
            color: 0xFF0000,
        };
        let result = db.add_tag_to_ab(&ab_guid, tag).await;
        assert!(result.is_some());

        let tags = db.get_ab_tags(&ab_guid).await;
        assert!(tags.is_some());
        let tags = tags.unwrap();
        assert!(tags.iter().any(|t| t.name == "important"));

        let tag = db.get_ab_tag(&ab_guid, "important").await;
        assert!(tag.is_some());
        assert_eq!(tag.unwrap().color, 0xFF0000);

        let renamed = AbTag {
            name: "critical".to_string(),
            color: 0x00FF00,
        };
        let result = db.rename_ab_tag(&ab_guid, "important", renamed).await;
        assert!(result.is_some());
        let tag = db.get_ab_tag(&ab_guid, "critical").await;
        assert!(tag.is_some());

        let result = db.delete_tag_from_ab(&ab_guid, "critical").await;
        assert!(result.is_some());
        let tag = db.get_ab_tag(&ab_guid, "critical").await;
        assert!(tag.is_none());
    });

    db_test!(ab_tag_invalid_uuid, |db| {
        let tag = AbTag {
            name: "t".to_string(),
            color: 0,
        };
        assert!(db.add_tag_to_ab("bad", tag).await.is_none());
        assert!(db.get_ab_tags("bad").await.is_none());
        assert!(db.get_ab_tag("bad", "t").await.is_none());
        assert!(
            db.rename_ab_tag(
                "bad",
                "t",
                AbTag {
                    name: "x".to_string(),
                    color: 0
                }
            )
            .await
            .is_none()
        );
        assert!(db.delete_tag_from_ab("bad", "t").await.is_none());
    });

    db_test!(get_ab_tag_nonexistent, |db| {
        let (_, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let ab_guid = db.get_ab_personal_guid(user_id).await.unwrap();
        let tag = db.get_ab_tag(&ab_guid, "nonexistent").await;
        assert!(tag.is_none());
    });

    db_test!(shared_address_book_crud, |db| {
        let (_, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let owner_uuid = Uuid::from_slice(&user_id).unwrap().to_string();

        let ab_guid = db
            .add_shared_address_book("Shared AB", &owner_uuid)
            .await;
        assert!(ab_guid.is_some());
        let ab_guid = ab_guid.unwrap();
        assert!(Uuid::parse_str(&ab_guid).is_ok());

        let result = db
            .update_shared_address_book(&ab_guid, "Renamed AB")
            .await;
        assert!(result.is_some());

        let result = db.delete_shared_address_book(&ab_guid).await;
        assert!(result.is_some());
    });

    db_test!(shared_address_book_invalid_owner, |db| {
        let result = db.add_shared_address_book("Test", "bad-uuid").await;
        assert!(result.is_none());
    });

    db_test!(delete_shared_address_book_invalid_uuid, |db| {
        assert!(db.delete_shared_address_book("bad").await.is_none());
    });

    db_test!(update_shared_address_book_invalid_uuid, |db| {
        assert!(db.update_shared_address_book("bad", "n").await.is_none());
    });

    async fn insert_peer_with_os(db: &Database, id: &str, os: &str) {
        sqlx::query("INSERT INTO peer (guid, id, uuid, pk, info) VALUES ($1, $2, $3, $4, $5)")
            .bind(Uuid::new_v4().as_bytes().to_vec())
            .bind(id)
            .bind(id.as_bytes().to_vec())
            .bind(vec![0u8; 32])
            .bind(format!(r#"{{"os":"{os}"}}"#))
            .execute(&db.pool)
            .await
            .unwrap();
    }

    // The client reports os as "<distribution_id> / <long_os_version>"
    // (rustdesk src/common.rs). On Linux distribution_id is the distro name,
    // so Linux cannot be matched by prefix.
    db_test!(get_peers_count_by_platform, |db| {
        insert_peer_with_os(&db, "p-ubuntu", "ubuntu / Linux 26.04 Ubuntu").await;
        insert_peer_with_os(&db, "p-debian", "debian / Linux 12 Debian").await;
        insert_peer_with_os(&db, "p-win", "windows / Windows 10 Pro").await;
        insert_peer_with_os(&db, "p-mac", "macos / macOS 15.0 Sequoia").await;
        insert_peer_with_os(&db, "p-android", "android / Android 14").await;
        assert_eq!(db.get_peers_count(Platform::Linux).await, 2);
        assert_eq!(db.get_peers_count(Platform::Windows).await, 1);
        assert_eq!(db.get_peers_count(Platform::MacOS).await, 1);
        assert_eq!(db.get_peers_count(Platform::Android).await, 1);
        assert_eq!(db.get_peers_count(Platform::All).await, 5);
    });

    db_test!(get_peers_count_empty, |db| {
        let count = db.get_peers_count(Platform::All).await;
        assert_eq!(count, 0);
    });

    db_test!(get_cpus_count_empty, |db| {
        let cpus = db.get_cpus_count().await;
        assert!(cpus.is_empty());
    });

    db_test!(get_all_peers_empty, |db| {
        let peers = db.get_all_peers().await;
        assert!(peers.is_some());
        assert!(peers.unwrap().is_empty());
    });

    db_test!(get_all_peers_returns_status, |db| {
        let guid = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO peer(guid, id, uuid, pk, status, info) \
             VALUES ($1, 'peer-status-test', $1, ''::bytea, 2, '{}')",
        )
        .bind(guid.as_bytes().to_vec())
        .execute(&db.pool)
        .await
        .unwrap();

        let peers = db.get_all_peers().await;
        assert!(peers.is_some());
        let peers = peers.unwrap();
        let peer = peers
            .iter()
            .find(|p| p.id == "peer-status-test")
            .expect("inserted peer should be returned");
        assert_eq!(peer.status, 2, "status must round-trip from the smallint column");
    });

    db_test!(get_shared_address_books_for_admin, |db| {
        let (_, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let abs = db.get_shared_address_books(user_id).await;
        assert!(abs.is_some());
        let abs = abs.unwrap();
        assert!(!abs.is_empty());
        // Seeded in 0001_initial.sql: ab_rule grants the Default group rule=3
        // on the Default shared address book. The rule column is computed
        // via COALESCE(MAX(smallint), 0), which Postgres resolves to
        // integer, not bigint or smallint.
        assert_eq!(abs[0].rule, Some(3));
    });

    db_test!(legacy_address_book_not_found, |db| {
        let result = db.get_legacy_address_book(vec![0, 1, 2]).await;
        assert!(result.is_none());
    });

    db_test!(update_legacy_address_books, |db| {
        let (_, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let ab = AddressBook {
            ab: r#"[{"id":"123"}]"#.to_string(),
            ..Default::default()
        };
        let result = db
            .update_legacy_address_books(vec![(user_id.clone(), ab)])
            .await;
        assert!(result.is_some());
        let fetched = db.get_legacy_address_book(user_id).await;
        assert!(fetched.is_some());
        assert!(fetched.unwrap().ab.contains("123"));
    });

    fn make_ab_peer(id: &str) -> AbPeer {
        AbPeer {
            id: id.to_string(),
            hash: None,
            password: None,
            username: None,
            hostname: None,
            platform: None,
            alias: None,
            tags: None,
            force_always_relay: None,
            rdp_port: None,
            rdp_username: None,
            login_name: None,
            same_server: None,
        }
    }

    db_test!(ab_peer_crud_invalid_uuid, |db| {
        let peer = make_ab_peer("test");
        assert!(db.add_peer_to_ab("bad-uuid", peer).await.is_none());
        assert!(db.get_peers_from_ab("bad-uuid").await.is_none());
        assert!(db.get_ab_peer("bad-uuid", "test").await.is_none());
        assert!(db.delete_peer_from_ab("bad-uuid", "test").await.is_none());
    });

    db_test!(ab_rules_invalid_uuid, |db| {
        assert!(db.get_ab_rules(0, 100, "bad").await.is_none());
        assert!(db.delete_ab_rule("bad").await.is_none());
        let rule = AbRule {
            guid: "bad".to_string(),
            user: None,
            group: None,
            rule: 1,
        };
        assert!(db.add_ab_rule(rule).await.is_none());
    });

    db_test!(user_update_name_and_status, |db| {
        db.add_user(
            "updatable".to_string(),
            "upd@e.com".to_string(),
            false,
            "Default".to_string(),
        )
        .await;
        let (_, user) = db.find_user_by_name("updatable").await;
        let (user_id, _, _) = user.unwrap();

        let params = UpdateUserRequest {
            uuid: String::new(),
            name: Some("renamed".to_string()),
            email: None,
            note: None,
            status: Some(0),
            is_admin: Some(true),
            group_name: None,
        };
        let result = db.user_update(user_id, params).await;
        assert!(result.is_some());
        let (_, found) = db.find_user_by_name("renamed").await;
        assert!(found.is_some());
        let (_, _, info) = found.unwrap();
        assert!(!info.active);
        assert!(info.admin);
    });

    db_test!(insert_audit_conn, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"test1","session_id":100}"#;
        let result = db.insert_audit_conn(guid.as_bytes(), Some(0), b"peer1", None, None, info).await;
        assert!(result.is_some());
    });

    db_test!(audit_conn_end_time, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"test2","session_id":200}"#;
        db.insert_audit_conn(guid.as_bytes(), None, b"peer2", None, None, info).await;
        let result = db.update_audit_conn_end_time(guid.as_bytes()).await;
        assert!(result.is_some());
    });

    db_test!(find_active_audit_conn_match, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"test3","session_id":300}"#;
        db.insert_audit_conn(guid.as_bytes(), Some(0), b"peer3", None, None, info).await;
        let found = db.find_active_audit_conn("peer3", "300", 0, b"caller").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap(), guid.as_bytes().to_vec());
    });

    db_test!(find_active_audit_conn_match_u64_session_id, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"test_u64","session_id":18446744073709551615}"#;
        db.insert_audit_conn(guid.as_bytes(), Some(0), b"peer_u64", None, None, info).await;
        let found = db.find_active_audit_conn("peer_u64", "18446744073709551615", 0, b"caller").await;
        assert_eq!(found, Some(guid.as_bytes().to_vec()));
    });

    db_test!(find_active_audit_conn_closed, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"test4","session_id":400}"#;
        db.insert_audit_conn(guid.as_bytes(), Some(0), b"peer4", None, None, info).await;
        db.update_audit_conn_end_time(guid.as_bytes()).await;
        let found = db.find_active_audit_conn("peer4", "400", 0, b"caller").await;
        assert!(found.is_none());
    });

    db_test!(find_active_audit_conn_other_user_is_hidden, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"test5","session_id":500}"#;
        db.insert_audit_conn(guid.as_bytes(), Some(0), b"peer5", None, None, info).await;
        db.set_audit_conn_user(guid.as_bytes(), b"owner").await;
        assert_eq!(db.find_active_audit_conn("peer5", "500", 0, b"owner").await, Some(guid.as_bytes().to_vec()));
        assert_eq!(db.find_active_audit_conn("peer5", "500", 0, b"someone_else").await, None);
    });

    db_test!(insert_audit_file_basic, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"ftest1"}"#;
        let result = db.insert_audit_file(guid.as_bytes(), b"remote1", Some(b"local1"), 1, "/tmp/f.txt", true, info, None).await;
        assert!(result.is_some());
    });

    db_test!(insert_audit_alarm_basic, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"atest1"}"#;
        let result = db.insert_audit_alarm(guid.as_bytes(), 1, info, None, Some(b"device1")).await;
        assert!(result.is_some());
    });

    db_test!(find_audit_conn_by_nonce_match, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"unique_nonce_1","session_id":500}"#;
        db.insert_audit_conn(guid.as_bytes(), None, b"peer5", None, None, info).await;
        let found = db.find_audit_conn_by_nonce("unique_nonce_1").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap(), guid.as_bytes().to_vec());
    });

    db_test!(find_audit_conn_by_nonce_miss, |db| {
        let found = db.find_audit_conn_by_nonce("nonexistent").await;
        assert!(found.is_none());
    });

    db_test!(heartbeat_no_peer, |db| {
        let hb = utils::HeartbeatRequest {
            id: "test".to_string(),
            uuid: BASE64_STANDARD.encode("nonexistent"),
            modified_at: 0,
            ver: 1,
            conns: vec![],
        };
        let result = db.update_heartbeat(hb).await;
        assert!(result.is_none());
    });

    db_test!(heartbeat_invalid_base64, |db| {
        let hb = utils::HeartbeatRequest {
            id: "test".to_string(),
            uuid: "not-base64!!!".to_string(),
            modified_at: 0,
            ver: 1,
            conns: vec![],
        };
        let result = db.update_heartbeat(hb).await;
        assert!(result.is_none());
    });

    db_test!(smallint_columns_decode_correctly, |db| {
        let (_, admin) = db.find_user_by_name("admin").await;
        let (_, _, info) = admin.expect("admin missing");
        assert!(info.admin, "role smallint decoded wrong");
        assert!(info.active, "status smallint decoded wrong");
        let users = db.ui_get_all_users().await.unwrap();
        assert!(users.iter().any(|u| u.username == "admin" && u.admin));
        let (name, is_admin) = db.get_user_info_by_id(&admin_guid(&db).await).await.unwrap();
        assert_eq!((name.as_str(), is_admin), ("admin", true));
    });

    async fn admin_guid(db: &Database) -> Vec<u8> {
        let (_, u) = db.find_user_by_name("admin").await;
        u.unwrap().0
    }

    async fn insert_peer_with_uuid_info(db: &Database, id: &str, uuid_bytes: &[u8], info: &str) {
        sqlx::query("INSERT INTO peer (guid, id, uuid, pk, info) VALUES ($1, $2, $3, $4, $5)")
            .bind(Uuid::new_v4().as_bytes().to_vec())
            .bind(id)
            .bind(uuid_bytes.to_vec())
            .bind(vec![0u8; 32])
            .bind(info)
            .execute(&db.pool)
            .await
            .unwrap();
    }

    async fn peer_info(db: &Database, id: &str) -> serde_json::Value {
        let info_str: String = sqlx::query("SELECT info FROM peer WHERE id = $1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .try_get("info")
            .unwrap();
        serde_json::from_str(&info_str).unwrap()
    }

    db_test!(update_systeminfo_touches_only_the_reporting_device, |db| {
        let machine_uuid = b"machine-1";
        insert_peer_with_uuid_info(
            &db,
            "dev-old",
            machine_uuid,
            r#"{"ip":"172.18.0.1","hostname":"old"}"#,
        )
        .await;
        insert_peer_with_uuid_info(&db, "dev-new", machine_uuid, r#"{"ip":"203.0.113.5"}"#).await;

        let systeminfo = utils::SystemInfo {
            cpu: None,
            hostname: Some("ws-1".to_string()),
            id: Some("dev-new".to_string()),
            memory: None,
            os: Some("Linux".to_string()),
            username: None,
            uuid: Some(BASE64_STANDARD.encode(machine_uuid)),
            version: None,
            ip: None,
        };
        let result = db.update_systeminfo(systeminfo).await;
        assert!(result.is_some());

        let new_info = peer_info(&db, "dev-new").await;
        assert_eq!(new_info["ip"], "203.0.113.5");
        assert_eq!(new_info["hostname"], "ws-1");
        assert_eq!(new_info["os"], "Linux");

        let old_info = peer_info(&db, "dev-old").await;
        assert_eq!(old_info["ip"], "172.18.0.1");
        assert_eq!(old_info["hostname"], "old");
    });

    db_test!(update_systeminfo_never_writes_ip, |db| {
        let machine_uuid = b"machine-1";
        insert_peer_with_uuid_info(&db, "dev-1", machine_uuid, r#"{"ip":"203.0.113.5"}"#).await;

        let systeminfo = utils::SystemInfo {
            cpu: None,
            hostname: Some("ws-1".to_string()),
            id: Some("dev-1".to_string()),
            memory: None,
            os: None,
            username: None,
            uuid: Some(BASE64_STANDARD.encode(machine_uuid)),
            version: None,
            ip: Some("10.0.0.9".to_string()),
        };
        let result = db.update_systeminfo(systeminfo).await;
        assert!(result.is_some());

        let info = peer_info(&db, "dev-1").await;
        assert_eq!(info["ip"], "203.0.113.5");
    });

    db_test!(update_systeminfo_keeps_fields_the_upload_lacks, |db| {
        let machine_uuid = b"machine-1";
        insert_peer_with_uuid_info(
            &db,
            "dev-1",
            machine_uuid,
            r#"{"cpu":"x","hostname":"ws-1"}"#,
        )
        .await;

        let systeminfo = utils::SystemInfo {
            cpu: None,
            hostname: Some("ws-2".to_string()),
            id: Some("dev-1".to_string()),
            memory: None,
            os: None,
            username: None,
            uuid: Some(BASE64_STANDARD.encode(machine_uuid)),
            version: None,
            ip: None,
        };
        let result = db.update_systeminfo(systeminfo).await;
        assert!(result.is_some());

        let info = peer_info(&db, "dev-1").await;
        assert_eq!(info["cpu"], "x");
        assert_eq!(info["hostname"], "ws-2");
    });

    db_test!(update_systeminfo_requires_matching_id_and_uuid, |db| {
        let machine_uuid = b"machine-1";
        insert_peer_with_uuid_info(&db, "dev-1", machine_uuid, r#"{"hostname":"old"}"#).await;

        let systeminfo = utils::SystemInfo {
            cpu: None,
            hostname: Some("ws-2".to_string()),
            id: Some("dev-1".to_string()),
            memory: None,
            os: None,
            username: None,
            uuid: Some(BASE64_STANDARD.encode(b"machine-2")),
            version: None,
            ip: None,
        };
        let result = db.update_systeminfo(systeminfo).await;
        assert!(result.is_none());
        let info = peer_info(&db, "dev-1").await;
        assert_eq!(info["hostname"], "old");

        let systeminfo_no_id = utils::SystemInfo {
            cpu: None,
            hostname: Some("ws-3".to_string()),
            id: None,
            memory: None,
            os: None,
            username: None,
            uuid: Some(BASE64_STANDARD.encode(machine_uuid)),
            version: None,
            ip: None,
        };
        let result = db.update_systeminfo(systeminfo_no_id).await;
        assert!(result.is_none());
    });

    async fn admin_id(db: &Database) -> Vec<u8> {
        db.get_user_for_oauth2("admin", "admin", None).await.unwrap().0
    }

    async fn age_viewer(db: &Database, id: &str, secs: i64) {
        db.test_age_viewer_device(id, secs).await;
    }

    db_test!(viewer_login_inserts_then_updates, |db| {
        let user = admin_id(&db).await;
        db.upsert_viewer_device("111", "u1", "pc-old", "linux", "192.0.2.1", &user).await.unwrap();
        age_viewer(&db, "111", 3600).await;
        db.upsert_viewer_device("111", "u1", "pc-new", "windows", "192.0.2.2", &user).await.unwrap();
        let (total, rows) = db.list_viewer_devices(0, 10).await.unwrap();
        assert_eq!(total, 1);
        assert_eq!((rows[0].hostname.as_str(), rows[0].os.as_str(), rows[0].login_ip.as_str()), ("pc-new", "windows", "192.0.2.2"));
        assert_eq!(rows[0].user.as_deref(), Some("admin"));
        assert!(rows[0].first_seen < rows[0].last_login);
        assert_eq!(rows[0].last_login, rows[0].last_seen);
    });

    db_test!(viewer_touch_updates_only_existing_rows_of_the_user, |db| {
        let user = admin_id(&db).await;
        assert_eq!(db.touch_viewer_device("222", "u2", &user).await, Some(false));
        assert_eq!(db.list_viewer_devices(0, 10).await.unwrap().0, 0);
        db.upsert_viewer_device("222", "u2", "pc", "linux", "", &user).await.unwrap();
        age_viewer(&db, "222", 3600).await;
        assert_eq!(db.touch_viewer_device("222", "u2", b"someone-else").await, Some(false));
        assert_eq!(db.touch_viewer_device("222", "u2", &user).await, Some(true));
        let rows = db.list_viewer_devices(0, 10).await.unwrap().1;
        assert!(rows[0].last_seen > rows[0].last_login);
    });

    db_test!(viewer_list_skips_registered_peers_and_pages, |db| {
        let user = admin_id(&db).await;
        for id in ["301", "302", "303"] {
            db.upsert_viewer_device(id, "u", id, "linux", "", &user).await.unwrap();
        }
        age_viewer(&db, "301", 60).await;
        insert_peer_with_os(&db, "303", "linux").await;
        let (total, rows) = db.list_viewer_devices(0, 1).await.unwrap();
        assert_eq!((total, rows.len(), rows[0].id.as_str()), (2, 1, "302"));
        let rows = db.list_viewer_devices(1, 1).await.unwrap().1;
        assert_eq!(rows[0].id, "301");
    });

    db_test!(viewer_rows_go_with_their_user, |db| {
        let (user, _, _) = db.get_user_for_oauth2("bob", "bob", None).await.unwrap();
        db.upsert_viewer_device("401", "u", "pc", "linux", "", &user).await.unwrap();
        let guid = guid_into_uuid(user).unwrap();
        db.delete_user(&guid).await.unwrap();
        assert_eq!(db.list_viewer_devices(0, 10).await.unwrap().0, 0);
    });
}
