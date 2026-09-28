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
use utils::UpdateUserRequest;
use utils::UserListResponse;

use base64::prelude::{Engine as _, BASE64_STANDARD};

use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
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

        Some(())
    }

    pub async fn update_systeminfo(&self, systeminfo: utils::SystemInfo) -> Option<()> {
        let mut systeminfo = systeminfo;
        // Peers are keyed by the base64-decoded uuid; without one there is
        // nothing to update.
        let uuid = systeminfo.uuid.clone()?;
        let uuid_decoded = BASE64_STANDARD.decode(uuid).ok();
        if let Some(uuid_decoded) = uuid_decoded {
            log::debug!(
                "uuid_decoded: {:?} {:?}",
                uuid_decoded,
                String::from_utf8(uuid_decoded.clone())
            );
            let res = sqlx::query(
                "SELECT info FROM peer WHERE uuid = $1",
            )
            .bind(&uuid_decoded)
            .fetch_one(&self.pool)
            .await;
            if res.is_err() {
                log::debug!("peer select error: {:?}", res.as_ref().err());
                return None;
            } else {
                let res = res.unwrap();
                let info_str: String = res.try_get::<String, _>("info").unwrap_or_default();
                let old_systeminfo: utils::SystemInfo =
                    rocket::serde::json::from_str(&info_str).unwrap();
                systeminfo.ip = old_systeminfo.ip.clone();
            }
            let systeminfo_string = rocket::serde::json::to_string(&systeminfo).unwrap();
            log::debug!("systeminfo_string: {:?}", systeminfo_string);
            let res = sqlx::query(
                "UPDATE peer SET info = $1 WHERE uuid = $2",
            )
            .bind(&systeminfo_string)
            .bind(&uuid_decoded)
            .execute(&self.pool)
            .await
            .ok()?
            .rows_affected();
            if res == 0 {
                return None;
            } else {
                return Some(());
            }
        }
        None
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

    pub async fn update_audit_conn_note(&self, guid: &[u8], note: &str) -> Option<()> {
        sqlx::query("UPDATE audit_conn SET note = $1 WHERE guid = $2")
            .bind(note)
            .bind(guid)
            .execute(&self.pool)
            .await
            .ok()?;
        Some(())
    }

    pub async fn find_active_audit_conn(
        &self,
        peer_id: &str,
        session_id: &str,
        conn_type: &str,
    ) -> Option<Vec<u8>> {
        let conn_type_i: i16 = conn_type.parse().unwrap_or(0);
        let row = sqlx::query(
            "SELECT guid FROM audit_conn WHERE remote = $1 AND type = $2 AND end_time IS NULL ORDER BY created_at DESC",
        )
        .bind(peer_id.as_bytes())
        .bind(conn_type_i)
        .fetch_all(&self.pool)
        .await
        .ok()?;

        for r in &row {
            let guid: Vec<u8> = r.try_get("guid").ok()?;
            let info_str: String = sqlx::query("SELECT info FROM audit_conn WHERE guid = $1")
                .bind(&guid)
                .fetch_one(&self.pool)
                .await
                .ok()?
                .try_get("info")
                .ok()?;
            if let Ok(info) = serde_json::from_str::<serde_json::Value>(&info_str) {
                if info.get("session_id").and_then(|v| v.as_u64()).map(|s| s.to_string()).as_deref() == Some(session_id) {
                    return Some(guid);
                }
            }
        }
        None
    }

    pub async fn find_audit_conn_by_nonce(&self, nonce: &str) -> Option<Vec<u8>> {
        let rows = sqlx::query("SELECT guid, info FROM audit_conn ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .ok()?;
        for r in &rows {
            let info_str: String = r.try_get("info").ok()?;
            if let Ok(info) = serde_json::from_str::<serde_json::Value>(&info_str) {
                if info.get("nonce").and_then(|v| v.as_str()) == Some(nonce) {
                    return Some(r.try_get("guid").ok()?);
                }
            }
        }
        None
    }

    pub async fn find_audit_file_by_nonce(&self, nonce: &str) -> bool {
        let rows = sqlx::query("SELECT info FROM audit_file ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
        for r in &rows {
            if let Ok(info_str) = r.try_get::<String, _>("info") {
                if let Ok(info) = serde_json::from_str::<serde_json::Value>(&info_str) {
                    if info.get("nonce").and_then(|v| v.as_str()) == Some(nonce) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub async fn find_audit_alarm_by_nonce(&self, nonce: &str) -> bool {
        let rows = sqlx::query("SELECT info FROM audit_alarm ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
        for r in &rows {
            if let Ok(info_str) = r.try_get::<String, _>("info") {
                if let Ok(info) = serde_json::from_str::<serde_json::Value>(&info_str) {
                    if info.get("nonce").and_then(|v| v.as_str()) == Some(nonce) {
                        return true;
                    }
                }
            }
        }
        false
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
    ) -> Option<()> {
        let is_file_i: i8 = if is_file { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO audit_file (guid, remote, local, type, path, is_file, info) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(guid)
        .bind(remote)
        .bind(local)
        .bind(file_type as i16)
        .bind(path)
        .bind(is_file_i as i16)
        .bind(info)
        .execute(&self.pool)
        .await
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
        assert_eq!(applied, vec![(1, true), (2, true), (3, true), (4, true)]);
        first.pool.close().await;

        // Second start on the same database must not fail or duplicate rows.
        let second = Database::new(&url).await.unwrap();
        let (groups,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM grp WHERE name = 'Default'")
            .fetch_one(&second.pool)
            .await
            .unwrap();
        assert_eq!(groups, 1);
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
        let found = db.find_active_audit_conn("peer3", "300", "0").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap(), guid.as_bytes().to_vec());
    });

    db_test!(find_active_audit_conn_match_u64_session_id, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"test_u64","session_id":18446744073709551615}"#;
        db.insert_audit_conn(guid.as_bytes(), Some(0), b"peer_u64", None, None, info).await;
        let found = db.find_active_audit_conn("peer_u64", "18446744073709551615", "0").await;
        assert_eq!(found, Some(guid.as_bytes().to_vec()));
    });

    db_test!(find_active_audit_conn_closed, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"test4","session_id":400}"#;
        db.insert_audit_conn(guid.as_bytes(), Some(0), b"peer4", None, None, info).await;
        db.update_audit_conn_end_time(guid.as_bytes()).await;
        let found = db.find_active_audit_conn("peer4", "400", "0").await;
        assert!(found.is_none());
    });

    db_test!(insert_audit_file_basic, |db| {
        let guid = Uuid::new_v4();
        let info = r#"{"nonce":"ftest1"}"#;
        let result = db.insert_audit_file(guid.as_bytes(), b"remote1", Some(b"local1"), 1, "/tmp/f.txt", true, info).await;
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
}
