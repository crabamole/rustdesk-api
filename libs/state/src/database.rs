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
use crate::password::UserPasswordInfo;
use crate::types;
use crate::UserId;
use serde::Serialize;
use sqlx::{
    any::{install_default_drivers, AnyPoolOptions},
    AnyPool, Row,
};
use std::env;
use std::path::Path;
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

const SCHEMA_SQLITE: &str = include_str!("../../../db_v2/create/db_sqlite.sql");
const SCHEMA_POSTGRES: &str = include_str!("../../../db_v2/create/db_postgres.sql");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

#[derive(Clone)]
pub struct Database {
    pool: AnyPool,
    backend: Backend,
}

pub struct DatabaseConnection {
    pool: AnyPool,
}

pub struct DatabaseUserInfo {
    pub active: bool,
    pub admin: bool,
}

#[derive(Serialize, Debug)]
pub struct DatabaseUserPasswordInfo {
    pub password: String,
    pub username: String,
    pub user_id: UserId,
}

macro_rules! unwrap_or_return_tuple {
    ($first:expr, $opt:expr) => {
        match $opt {
            Some(v) => v,
            None => return ($first, None),
        }
    };
}

fn split_sql(sql: &str) -> Vec<&str> {
    sql.split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with("--"))
        .collect()
}

fn normalize_url(url: &str) -> String {
    if url.starts_with("sqlite://")
        || url.starts_with("postgres://")
        || url.starts_with("postgresql://")
    {
        url.to_string()
    } else {
        format!("sqlite://{}", url)
    }
}

impl Database {
    pub async fn open<P: AsRef<Path>>(db_filename: P) -> Self {
        let url = format!("sqlite://{}", db_filename.as_ref().display());
        Self::new(&url).await.expect("Failed to open database")
    }

    pub async fn new(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        install_default_drivers();

        let url = normalize_url(url);
        let backend = if url.starts_with("postgres") {
            Backend::Postgres
        } else {
            Backend::Sqlite
        };

        if backend == Backend::Sqlite {
            let path = url.strip_prefix("sqlite://").unwrap_or(&url);
            if !Path::new(path).exists() {
                std::fs::File::create(path).ok();
            }
        }

        let max_connections: u32 = env::var("MAX_DATABASE_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or((num_cpus::get() * 4) as u32);

        let pool = AnyPoolOptions::new()
            .max_connections(max_connections)
            .connect(&url)
            .await?;

        let db = Database { pool, backend };
        db.init_db().await;
        Ok(db)
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    async fn init_db(&self) {
        let has_tables = match self.backend {
            Backend::Sqlite => {
                let res = sqlx::query("SELECT name FROM sqlite_master WHERE type='table'")
                    .fetch_all(&self.pool)
                    .await;
                match res {
                    Ok(rows) => !rows.is_empty(),
                    Err(_) => false,
                }
            }
            Backend::Postgres => {
                let res = sqlx::query(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
                )
                .fetch_all(&self.pool)
                .await;
                match res {
                    Ok(rows) => !rows.is_empty(),
                    Err(_) => false,
                }
            }
        };

        if has_tables {
            if self.backend == Backend::Sqlite {
                let migrator = sqlx::migrate!("../../db_v2/migrations/");
                migrator.run(&self.pool).await.unwrap();
            }
        }

        let schema = match self.backend {
            Backend::Sqlite => SCHEMA_SQLITE,
            Backend::Postgres => SCHEMA_POSTGRES,
        };
        for statement in split_sql(schema) {
            if let Err(e) = sqlx::query(statement).execute(&self.pool).await {
                log::debug!("init_db statement error (may be expected): {:?}", e);
            }
        }
    }

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
        let status: i32 = res.try_get::<i32, _>("status").unwrap_or(0);
        let role: i32 = res.try_get::<i32, _>("role").unwrap_or(0);
        let dbi = DatabaseUserInfo {
            active: status == 1,
            admin: role == 1,
        };

        (conn, Some((user_id, email, dbi)))
    }

    pub async fn get_user_hashed_password(
        &self,
        conn: DatabaseConnection,
        user_id: UserId,
    ) -> (DatabaseConnection, Option<DatabaseUserPasswordInfo>) {
        let res = sqlx::query(
            "SELECT guid, name, password FROM \"user\" WHERE guid = $1",
        )
        .bind(&user_id)
        .fetch_one(&self.pool)
        .await;

        let res = unwrap_or_return_tuple!(conn, res.ok());

        let dbpi = DatabaseUserPasswordInfo {
            password: res.try_get::<String, _>("password").unwrap(),
            username: res.try_get::<String, _>("name").unwrap(),
            user_id: res.try_get::<Vec<u8>, _>("guid").unwrap(),
        };

        (conn, Some(dbpi))
    }

    pub async fn get_user_hashed_password_with_username(
        &self,
        conn: DatabaseConnection,
        username: String,
    ) -> (DatabaseConnection, Option<DatabaseUserPasswordInfo>) {
        let res = sqlx::query(
            "SELECT guid, name, password FROM \"user\" WHERE name = $1",
        )
        .bind(&username)
        .fetch_one(&self.pool)
        .await;

        let res = unwrap_or_return_tuple!(conn, res.ok());

        let dbpi = DatabaseUserPasswordInfo {
            password: res.try_get::<String, _>("password").unwrap(),
            username: res.try_get::<String, _>("name").unwrap(),
            user_id: res.try_get::<Vec<u8>, _>("guid").unwrap(),
        };

        (conn, Some(dbpi))
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

    pub async fn update_user_password(
        &self,
        username: String,
        old_password: String,
        new_password: String,
    ) -> Option<()> {
        let conn = DatabaseConnection {
            pool: self.pool.clone(),
        };
        let (_, dbpi) = self
            .get_user_hashed_password_with_username(conn, username)
            .await;

        if dbpi.is_none() {
            return None;
        }

        let dbpi = dbpi.unwrap();
        let user_id = dbpi.user_id.clone();
        let old_password_info = UserPasswordInfo::from_password(old_password.as_str());
        if !old_password_info.check(dbpi) {
            return None;
        }
        let new_password_hashed = UserPasswordInfo::hash_password(new_password.as_str());
        let res = sqlx::query(
            "UPDATE \"user\" SET password = $1 WHERE guid = $2",
        )
        .bind(&new_password_hashed)
        .bind(&user_id)
        .execute(&self.pool)
        .await
        .ok()?
        .rows_affected();
        if res == 0 {
            return None;
        }
        Some(())
    }

    pub async fn reset_user_password(&self, username: String, new_password: String) -> Option<()> {
        let new_password_hashed = UserPasswordInfo::hash_password(new_password.as_str());
        let res = sqlx::query(
            "UPDATE \"user\" SET password = $1 WHERE name = $2",
        )
        .bind(&new_password_hashed)
        .bind(&username)
        .execute(&self.pool)
        .await
        .ok()?
        .rows_affected();
        if res == 0 {
            return None;
        }
        Some(())
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
                "user".password,
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
                active: row.try_get::<i32, _>("status").unwrap_or(0) != 0,
                admin: row.try_get::<i32, _>("role").unwrap_or(0) != 0,
                username: row.try_get::<String, _>("username").unwrap_or_default(),
                password: row.try_get::<String, _>("password").unwrap_or_default(),
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
                "user".password,
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
            active: row.try_get::<i32, _>("status").unwrap_or(0) != 0,
            admin: row.try_get::<i32, _>("role").unwrap_or(0) != 0,
            username: row.try_get::<String, _>("username").unwrap_or_default(),
            password: row.try_get::<String, _>("password").unwrap_or_default(),
            address_book: row.try_get::<String, _>("ab").unwrap_or_default(),
        })
    }

    pub async fn create_user(
        &self,
        username: String,
        password: String,
        admin: bool,
    ) -> Option<UserId> {
        let password_hashed = UserPasswordInfo::hash_password(password.as_str());
        let guid = Uuid::new_v4().as_bytes().to_vec();
        let role: i32 = if admin { 1 } else { 0 };

        sqlx::query(
            "INSERT INTO \"user\" (guid, status, role, name, password, grp, team) \
             VALUES ($1, 1, $2, $3, $4, \
             (SELECT guid FROM grp WHERE name = 'Default'), \
             (SELECT guid FROM team WHERE name = 'Default'))",
        )
        .bind(&guid)
        .bind(role)
        .bind(&username)
        .bind(&password_hashed)
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

        sqlx::query("DELETE FROM \"user\" WHERE guid = $1")
            .bind(&user_id)
            .execute(&self.pool)
            .await
            .ok()?;

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
        let uuid = systeminfo.uuid.clone().unwrap();

        let uuid_decoded = BASE64_STANDARD.decode(uuid);
        if uuid_decoded.is_ok() {
            let uuid_decoded = uuid_decoded.unwrap();
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
        Some(())
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

    pub async fn get_user_for_oauth2(
        &self,
        id: String,
        email: String,
        uuid: String,
    ) -> Option<(UserId, String, DatabaseUserInfo)> {
        let status = { env::var("OAUTH2_CREATE_USER").unwrap_or("0".to_string()) == "1" };
        let ab_guid = Uuid::new_v4().as_bytes().to_vec();
        let user_guid = Uuid::new_v4().as_bytes().to_vec();
        let random_password = Uuid::new_v4().to_string();
        let hashed_random_password = UserPasswordInfo::hash_password(random_password.as_str());
        log::debug!(
            "user: {:?}/{:?} has random_password: {:?}",
            uuid,
            id,
            random_password
        );
        let name = format!("{}'s Personal Address Book", id);
        let status_val: i32 = if status { 1 } else { 0 };

        let res = sqlx::query(
            "INSERT INTO \"user\"(guid, grp, team, status, role, name, email, password) \
             VALUES ($1, \
             (SELECT guid FROM grp WHERE name = 'Default'), \
             (SELECT guid FROM team WHERE name = 'Default'), $2, 0, $3, $4, $5) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&user_guid)
        .bind(status_val)
        .bind(&id)
        .bind(&email)
        .bind(&hashed_random_password)
        .execute(&self.pool)
        .await;
        if res.is_err() {
            log::error!(
                "get_user_for_oauth2 error while creating user: {:?}",
                res
            );
        }

        let res2 = sqlx::query(
            "INSERT INTO ab(guid, name, owner, personal, info) \
             VALUES ($1, $2, $3, 1, '{}') \
             ON CONFLICT DO NOTHING",
        )
        .bind(&ab_guid)
        .bind(&name)
        .bind(&user_guid)
        .execute(&self.pool)
        .await;
        if res2.is_err() {
            log::error!(
                "get_user_for_oauth2 error while creating ab: {:?}",
                res2
            );
        }

        let res = sqlx::query(
            "SELECT guid, status, role, name FROM \"user\" WHERE name = $1",
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await;

        if res.is_err() {
            log::error!(
                "get_user_for_oauth2 error while creating/getting user: {:?}",
                res.as_ref().err()
            );
            return None;
        }
        let res = res.unwrap();
        let user_id: UserId = res.try_get::<Vec<u8>, _>("guid").unwrap();
        let dbi = DatabaseUserInfo {
            active: res.try_get::<i32, _>("status").unwrap_or(0) == 1,
            admin: res.try_get::<i32, _>("role").unwrap_or(0) == 1,
        };
        Some((user_id, res.try_get::<String, _>("name").unwrap(), dbi))
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
        password: String,
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
        let password_hashed = UserPasswordInfo::hash_password(password.as_str());
        let role: i32 = if is_admin { 1 } else { 0 };

        let res = sqlx::query(
            "INSERT INTO \"user\"(guid, grp, team, status, role, name, password, email) \
             VALUES ($1, $2, (SELECT guid FROM team WHERE name = 'Default'), 1, $3, $4, $5, $6) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&user_guid)
        .bind(&group_guid)
        .bind(role)
        .bind(&name)
        .bind(&password_hashed)
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
        let status_val = status as i32;
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
                status: row.try_get::<i32, _>("status").unwrap_or(0),
                is_admin: row.try_get::<i32, _>("role").unwrap_or(0) != 0,
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
        if user_parameters.password.is_some()
            && user_parameters.confirm_password.is_some()
            && !user_parameters.password.as_ref().unwrap().is_empty()
            && !user_parameters.confirm_password.as_ref().unwrap().is_empty()
        {
            let password = user_parameters.password.unwrap();
            let confirm_password = user_parameters.confirm_password.unwrap();
            if password == confirm_password {
                let password_hashed = UserPasswordInfo::hash_password(password.as_str());
                set_clauses.push(format!("password = ${}", param_idx));
                query_params.push(password_hashed);
                param_idx += 1;
            }
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
            let status: i32 = row.try_get::<i32, _>("status").unwrap_or(0);
            peers.push(Peer {
                id: row.try_get::<String, _>("id").unwrap_or_default(),
                guid: uuid,
                info: peer_info,
                last_online: last_online.into(),
                status: status,
                strategy_name: "-".to_string(),
            });
        }
        Some(peers)
    }

    pub async fn get_groups(&self, offset: u32, page_size: u32) -> Option<Vec<Group>> {
        let res = sqlx::query(
            "SELECT guid, team, name, note, created_at, info FROM grp LIMIT $1 OFFSET $2",
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
            let access_level = row.try_get::<i64, _>("rule").unwrap_or(0) as u32;
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
                rule: row.try_get::<i32, _>("rule").unwrap_or(0) as u32,
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

        let rule_val = rule.rule as i32;
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
            Platform::Linux => "linux%",
            Platform::MacOS => "macos%",
            Platform::Android => "android%",
            Platform::All => "%",
            _ => "unknown%",
        };

        let sql = match self.backend {
            Backend::Sqlite => {
                "SELECT COUNT(*) as count FROM peer WHERE json_extract(info,'$.os') LIKE $1"
                    .to_string()
            }
            Backend::Postgres => {
                "SELECT COUNT(*) as count FROM peer WHERE info::json->>'os' LIKE $1".to_string()
            }
        };

        let res = sqlx::query(&sql)
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
        let sql = match self.backend {
            Backend::Sqlite => {
                "SELECT COALESCE(trim(json_extract(info,'$.cpu')),'unknown') as cpu, \
                 COUNT(*) AS machine_count FROM peer GROUP BY cpu"
                    .to_string()
            }
            Backend::Postgres => {
                "SELECT COALESCE(trim(info::json->>'cpu'),'unknown') as cpu, \
                 COUNT(*) AS machine_count FROM peer GROUP BY cpu"
                    .to_string()
            }
        };

        let res = sqlx::query(&sql).fetch_all(&self.pool).await.ok();
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
        let expiry_expr = match self.backend {
            Backend::Sqlite => format!("datetime('now', '+{} seconds')", ttl_secs),
            Backend::Postgres => format!("NOW() + INTERVAL '{} seconds'", ttl_secs),
        };
        let query = format!(
            "INSERT INTO session (id, ttl_secs, \"user\", expiry_at, created_at) \
             VALUES ($1, $2, $3, {}, current_timestamp)",
            expiry_expr
        );
        sqlx::query(&query)
            .bind(token_id)
            .bind(ttl_secs)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .ok()?;
        Some(())
    }

    pub async fn find_session_user(&self, token_id: &str) -> Option<Vec<u8>> {
        let now_expr = match self.backend {
            Backend::Sqlite => "datetime('now')",
            Backend::Postgres => "NOW()::text",
        };
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
        let now_expr = match self.backend {
            Backend::Sqlite => "datetime('now')",
            Backend::Postgres => "NOW()::text",
        };
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
            let admin: bool = r.try_get::<i32, _>("role").unwrap_or(0) == 1;
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
        let now_expr = match self.backend {
            Backend::Sqlite => "strftime('%Y-%m-%d %H:%M:%f', 'now')",
            Backend::Postgres => "to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS.MS')",
        };
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
                if info.get("session_id").and_then(|v| v.as_i64()).map(|s| s.to_string()).as_deref() == Some(session_id) {
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

    async fn test_db_sqlite() -> Database {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let db = Database::open(&path).await;
        std::mem::forget(dir);
        db
    }

    use tokio::sync::OnceCell;
    use testcontainers::runners::AsyncRunner;
    use testcontainers::ContainerAsync;
    use testcontainers_modules::postgres::Postgres;

    struct PgContainer {
        _container: ContainerAsync<Postgres>,
        base_url: String,
    }

    static PG: OnceCell<PgContainer> = OnceCell::const_new();

    async fn get_pg_container() -> &'static PgContainer {
        PG.get_or_init(|| async {
            let container = Postgres::default()
                .start()
                .await
                .expect("failed to start postgres container");
            let port = container.get_host_port_ipv4(5432).await.unwrap();
            let base_url = format!("postgres://postgres:postgres@127.0.0.1:{}", port);
            PgContainer { _container: container, base_url }
        }).await
    }

    async fn test_db_postgres() -> Database {
        install_default_drivers();
        let pg = get_pg_container().await;
        let db_name = format!("test_{}", Uuid::new_v4().as_simple());
        let admin_url = format!("{}/postgres", pg.base_url);
        let admin_pool = AnyPool::connect(&admin_url).await.unwrap();
        sqlx::query(&format!("CREATE DATABASE \"{}\"", db_name))
            .execute(&admin_pool)
            .await
            .unwrap();
        admin_pool.close().await;

        let test_url = format!("{}/{}", pg.base_url, db_name);
        Database::new(&test_url).await.unwrap()
    }

    macro_rules! db_test {
        ($name:ident, |$db:ident| $body:block) => {
            paste::paste! {
                #[tokio::test]
                async fn [<$name _sqlite>]() {
                    let $db = test_db_sqlite().await;
                    $body
                }

                #[tokio::test]
                #[cfg_attr(not(feature = "postgres-tests"), ignore)]
                async fn [<$name _postgres>]() {
                    let $db = test_db_postgres().await;
                    $body
                }
            }
        };
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

    db_test!(get_hashed_password_for_admin, |db| {
        let (conn, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let (_, pw_info) = db.get_user_hashed_password(conn, user_id).await;
        assert!(pw_info.is_some());
        let pw_info = pw_info.unwrap();
        assert_eq!(pw_info.username, "admin");
        assert!(pw_info.password.starts_with("$2b$"));
    });

    db_test!(get_hashed_password_by_username, |db| {
        let conn = DatabaseConnection {
            pool: db.pool.clone(),
        };
        let (_, pw_info) = db
            .get_user_hashed_password_with_username(conn, "admin".to_string())
            .await;
        assert!(pw_info.is_some());
        assert_eq!(pw_info.unwrap().username, "admin");
    });

    db_test!(admin_password_is_hello_world, |db| {
        let (conn, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let (_, pw_info) = db.get_user_hashed_password(conn, user_id).await;
        let pw_info = pw_info.unwrap();
        let checker = UserPasswordInfo::from_password("Hello,world!");
        assert!(checker.check(pw_info));
    });

    db_test!(add_user_and_find, |db| {
        let result = db
            .add_user(
                "testuser".to_string(),
                "testpass".to_string(),
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
            "pass".to_string(),
            "super@example.com".to_string(),
            true,
            "Default".to_string(),
        )
        .await;
        let (_, found) = db.find_user_by_name("superadmin").await;
        let (_, _, info) = found.unwrap();
        assert!(info.admin);
    });

    db_test!(update_user_password, |db| {
        let result = db
            .update_user_password(
                "admin".to_string(),
                "Hello,world!".to_string(),
                "newpass".to_string(),
            )
            .await;
        assert!(result.is_some());
        let conn = DatabaseConnection {
            pool: db.pool.clone(),
        };
        let (_, pw_info) = db
            .get_user_hashed_password_with_username(conn, "admin".to_string())
            .await;
        let checker = UserPasswordInfo::from_password("newpass");
        assert!(checker.check(pw_info.unwrap()));
    });

    db_test!(update_user_password_wrong_old, |db| {
        let result = db
            .update_user_password(
                "admin".to_string(),
                "wrongold".to_string(),
                "newpass".to_string(),
            )
            .await;
        assert!(result.is_none());
    });

    db_test!(reset_user_password, |db| {
        let result = db
            .reset_user_password("admin".to_string(), "reset123".to_string())
            .await;
        assert!(result.is_some());
        let conn = DatabaseConnection {
            pool: db.pool.clone(),
        };
        let (_, pw_info) = db
            .get_user_hashed_password_with_username(conn, "admin".to_string())
            .await;
        let checker = UserPasswordInfo::from_password("reset123");
        assert!(checker.check(pw_info.unwrap()));
    });

    db_test!(reset_password_nonexistent_user, |db| {
        let result = db
            .reset_user_password("nobody".to_string(), "pass".to_string())
            .await;
        assert!(result.is_none());
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
            "p".to_string(),
            "u1@e.com".to_string(),
            false,
            "Default".to_string(),
        )
        .await;
        db.add_user(
            "user2".to_string(),
            "p".to_string(),
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
        assert_eq!(filtered.unwrap().len(), 1);
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
                "pass".to_string(),
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
                "pass".to_string(),
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

    db_test!(get_shared_address_books_for_admin, |db| {
        let (_, user) = db.find_user_by_name("admin").await;
        let (user_id, _, _) = user.unwrap();
        let abs = db.get_shared_address_books(user_id).await;
        assert!(abs.is_some());
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
            "pass".to_string(),
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
            password: None,
            confirm_password: None,
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

    db_test!(user_update_password_matching, |db| {
        db.add_user(
            "pwuser".to_string(),
            "old".to_string(),
            "pw@e.com".to_string(),
            false,
            "Default".to_string(),
        )
        .await;
        let (_, user) = db.find_user_by_name("pwuser").await;
        let (user_id, _, _) = user.unwrap();

        let params = UpdateUserRequest {
            uuid: String::new(),
            name: None,
            email: None,
            note: None,
            password: Some("newpass".to_string()),
            confirm_password: Some("newpass".to_string()),
            status: None,
            is_admin: None,
            group_name: None,
        };
        db.user_update(user_id, params).await;
        let conn = DatabaseConnection {
            pool: db.pool.clone(),
        };
        let (_, pw_info) = db
            .get_user_hashed_password_with_username(conn, "pwuser".to_string())
            .await;
        let checker = UserPasswordInfo::from_password("newpass");
        assert!(checker.check(pw_info.unwrap()));
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
}
