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
use crate::database::DatabaseUserInfo;
use crate::types;
use crate::{
    bearer::AuthenticatedUserInfo, database::Database, SessionId,
    UserId,
};
use std::{
    collections::HashMap,
    default::Default,
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use oauth2::ProviderConfig;

use tokio::sync::RwLock;
use utils::{
    AbPeer, AbRule, AbTag, AddUserRequest, AddressBook, CpuCount, Group, OidcState, Peer, Platform,
    Token, UpdateUserRequest, UserListResponse,
};

pub struct ApiState {
    last_maintenance_time: AtomicU64,
    address_books: RwLock<HashMap<UserId, AddressBookInfo>>,
    oidc_sessions: RwLock<HashMap<String, OidcState>>,
    pub(crate) db: Database,
    oauth2_providers: RwLock<Vec<ProviderConfig>>,
}

#[derive(Debug, Clone)]
pub struct AccessTokenInfo {
    pub session_id: SessionId,
    pub user_id: UserId,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    pub username: String,
    pub admin: bool,
}

#[derive(Debug, Clone)]
pub struct AddressBookInfo {
    modified: bool,
    remove_after_flush: bool,
    pub address_book: AddressBook,
}

const MAINTENANCE_INTERVAL_IN_SECS: u64 = 60;

fn secs_from_epoch() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl ApiState {
    pub async fn new_with_db(db_url: &str) -> Self {
        let db = Database::connect_with_retry(db_url).await;
        Self {
            last_maintenance_time: AtomicU64::new(0),
            address_books: Default::default(),
            db,
            oidc_sessions: Default::default(),
            oauth2_providers: Default::default(),
        }
    }

    pub async fn maintenance_flush_address_books(&self) {
        let mut state_address_books = self.address_books.write().await;

        let mut values: Vec<(UserId, AddressBook)> = vec![];

        for (user_id, address_book_info) in state_address_books.iter_mut() {
            if !address_book_info.modified {
                continue;
            }
            let user_id_clone = user_id.clone();
            values.push((user_id_clone, address_book_info.address_book.clone()));
            address_book_info.modified = false;
        }

        if !values.is_empty() {
            log::debug!("Need to update_address_books");
            self.db.update_legacy_address_books(values).await;
        }
    }

    pub async fn maintenance(&self) {
        self.maintenance_flush_address_books().await;
    }

    pub async fn check_maintenance(&self) {
        log::debug!("check_maintenance...");

        let now = secs_from_epoch();
        let last_mt = self.last_maintenance_time.load(Ordering::Relaxed);

        if now >= (last_mt + MAINTENANCE_INTERVAL_IN_SECS) {
            self.last_maintenance_time.store(now, Ordering::Relaxed);
            log::debug!("check_maintenance NOW");
            self.maintenance().await;
        }
    }

    /// Simulates a successful OIDC login for `username` (creating it if needed)
    /// and issues a session. Test-only.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_oidc_login(&self, username: &String) -> Option<(utils::UserInfo, Token)> {
        let email = format!("{username}@example.org");
        self.db
            .get_user_for_oauth2(username.clone(), email, String::new())
            .await?;
        let (_, user_id, email, db_user_info) =
            match self.db.find_user_by_name(username.as_str()).await {
                (conn, Some((user_id, email, db_user_info))) => {
                    (conn, user_id, email, db_user_info)
                }
                _ => return None,
            };
        if !db_user_info.active {
            return None;
        }

        let access_token = self
            .get_access_token(user_id, username, db_user_info.admin)
            .await;

        Some((
            utils::UserInfo {
                name: username.to_string(),
                email,
                admin: db_user_info.admin,
                ..Default::default()
            },
            access_token,
        ))
    }

    async fn get_access_token(&self, user_id: Vec<u8>, _username: &String, _is_admin: bool) -> Token {
        let access_token = Token::new_random();
        let token_id = access_token.to_base64();

        self.db.insert_session(&token_id, &user_id, 2592000).await;

        let mut state_address_books = self.address_books.write().await;
        if let Some(abi) = state_address_books.get_mut(&user_id) {
            abi.remove_after_flush = false;
        }

        access_token
    }

    pub async fn find_session(&self, access_token: &Token) -> Option<AccessTokenInfo> {
        let token_id = access_token.to_base64();
        let user_id = self.db.find_session_user(&token_id).await?;
        Some(AccessTokenInfo {
            session_id: 0,
            user_id,
        })
    }

    pub async fn get_user_address_book(&self, user_id: UserId) -> Option<AddressBook> {
        let state_address_books = self.address_books.read().await;

        let opt_ab = state_address_books
            .get(&user_id)
            .map(|abi| abi.address_book.clone());

        if opt_ab.is_some() {
            return opt_ab;
        }

        drop(state_address_books);

        let ab = self.db.get_legacy_address_book(user_id.clone()).await?;
        let abi = AddressBookInfo {
            modified: false,
            remove_after_flush: false,
            address_book: ab.clone(),
        };

        let mut state_address_books = self.address_books.write().await;
        state_address_books.insert(user_id, abi.clone());

        Some(ab)
    }

    pub async fn set_user_address_book(
        &self,
        user_id: UserId,
        address_book: AddressBook,
    ) -> Option<()> {
        log::debug!("set_user_ab()");
        let mut state_address_books = self.address_books.write().await;

        if let Some(abi) = state_address_books.get_mut(&user_id) {
            if abi.address_book != address_book {
                abi.modified = true;
                abi.address_book = address_book;
            };
        } else {
            let abi = AddressBookInfo {
                modified: false,
                remove_after_flush: false,
                address_book,
            };
            state_address_books.insert(user_id, abi);
        }
        // log::debug!("set_user_ab() 2");

        // let _ = self.db.update_ab( user_id, &abi.ab ).await;

        log::debug!("ab done!");
        Some(())
    }

    /// Log out the given user from the state.
    ///
    /// This function is used to log out a user when the user's session is
    /// invalidated (e.g. when the user changes their password).
    ///
    /// This function removes the user's access token and session from the
    /// state, and decrements the number of sessions for the user. If the number
    /// of sessions for the user reaches 0, the user is removed from the state
    /// entirely.
    ///
    /// # Returns
    ///
    /// This function returns `None` if the user is not present in the state,
    /// or if removing their session and access token from the state fails.
    /// If the function returns `Some(())`, the logout was successful.
    pub async fn user_logout(&self, user: &AuthenticatedUserInfo) -> Option<()> {
        let token_id = user.access_token.to_base64();
        self.db.delete_session(&token_id).await;

        let remaining = self.db.count_user_sessions(&user.user_id).await;
        if remaining == 0 {
            let mut state_address_books = self.address_books.write().await;
            if let Some(abi) = state_address_books.get_mut(&user.user_id) {
                abi.remove_after_flush = true;
            }
        }

        Some(())
    }

    pub async fn get_current_user_name(&self, user: &AuthenticatedUserInfo) -> Option<String> {
        let (name, _) = self.db.get_user_info_by_id(&user.user_id).await?;
        Some(name)
    }

    pub async fn is_current_user_admin(&self, user: &AuthenticatedUserInfo) -> Option<bool> {
        let (_, admin) = self.db.get_user_info_by_id(&user.user_id).await?;
        Some(admin)
    }

    pub async fn with_user_info<R>(
        &self,
        user_id: &UserId,
        mut f: impl FnMut(&UserInfo) -> R,
    ) -> Option<R> {
        let (username, admin) = self.db.get_user_info_by_id(user_id).await?;
        let user_info = UserInfo { username, admin };
        Some(f(&user_info))
    }

    pub async fn ui_get_all_users(&self) -> Option<Vec<types::UserInfo>> {
        self.db.ui_get_all_users().await
    }

    /// Promotes (`admin = true`) or demotes a user; `None` if no such user.
    /// Backs the `rustdesk-api admin` CLI, the only way to make an admin.
    pub async fn set_admin(&self, name: &str, admin: bool) -> Option<()> {
        self.db.set_admin(name, admin).await
    }

    pub async fn ui_create_user(&self, username: String, admin: bool) -> Option<UserId> {
        self.db.create_user(username, admin).await
    }

    pub async fn user_delete(&self, user_id: &str) -> Option<()> {
        self.db.delete_user(user_id).await
    }

    pub async fn ui_get_user_info(&self, username: String) -> Option<types::UserInfo> {
        let res = self.db.ui_get_user_info(username).await;
        res
    }

    pub async fn update_systeminfo(&self, systeminfo: utils::SystemInfo) -> Option<()> {
        // must be written in the database immediately because peer is mainly used by hbbs
        self.db.update_systeminfo(systeminfo).await
    }

    pub async fn update_heartbeat(&self, heartbeat: utils::HeartbeatRequest) -> Option<()> {
        self.db.update_heartbeat(heartbeat).await
    }

    pub async fn get_oauth2_config(&self, config_file: &str) -> Option<Vec<ProviderConfig>> {
        let mut oauth2_providers = self.oauth2_providers.write().await;

        if oauth2_providers.is_empty() {
            log::debug!("get providers from {}", config_file);
            let config = oauth2::get_providers_config_from_file(config_file);
            if config.len() == 0 {
                return None;
            }
            for c in config.clone() {
                oauth2_providers.push(c);
            }
        }
        Some(oauth2_providers.clone())
    }

    pub async fn insert_oidc_session(
        &self,
        uuid_code: String,
        oidc_state: OidcState,
    ) -> Option<OidcState> {
        let mut oidc_sessions = self.oidc_sessions.write().await;
        let old_value = oidc_sessions.insert(uuid_code, oidc_state.clone());
        if old_value.is_none() {
            return Some(oidc_state);
        }
        None
    }

    pub async fn get_oidc_session(&self, uuid_code: String) -> Option<OidcState> {
        let oidc_sessions = self.oidc_sessions.read().await;
        oidc_sessions.get(&uuid_code).map(|s| s.clone())
    }

    /// Exchange code for tokens
    ///
    /// This function exchanges a code obtained from an oauth2 provider
    /// for an access token.
    /// If the oauth2 provider supports it, also an id token is exchanged.
    ///
    /// # Arguments
    ///
    /// * `authorization_code` - The code obtained from the oauth2 provider
    /// * `uuid_code` - The unique code to identify this code exchange request
    ///
    /// # Returns
    ///
    /// If the code exchange was successful, an `Option` containing the access
    /// and refresh tokens is returned, otherwise `None`.
    pub async fn oidc_session_exchange_code(
        &self,
        authorization_code: String,
        uuid_code: String,
    ) -> Option<String> {
        let mut oidc_sessions = self.oidc_sessions.write().await;
        let oidc_session = oidc_sessions.get_mut(&uuid_code);
        if oidc_session.is_none() {
            return None;
        }
        let oidc_session = oidc_session.unwrap();
        oidc_session.code = Some(authorization_code.clone());
        if oidc_session.provider.is_some()
            && oidc_session.code.is_some()
            && oidc_session.callback_url.is_some()
        {
            let provider = oidc_session.clone().provider.unwrap();
            let callback_url = oidc_session.clone().callback_url.unwrap();
            let exchange_result = provider
                .exchange_code(authorization_code.as_str(), callback_url.as_str())
                .await;
            if let Err(e) = &exchange_result {
                log::error!("OIDC code exchange failed: {}", e);
            }

            if exchange_result.is_ok() {
                let access_token = exchange_result.unwrap();
                let username = access_token.username.clone();

                oidc_session.auth_token = Some(access_token.access_token.clone());
                oidc_session.name = Some(if username.len() > 0 {
                    username.clone()
                } else {
                    oidc_session.id.clone()
                });
                oidc_session.email = Some(access_token.email.clone());
                log::debug!("oidc_session_exchange_code {:?}", oidc_session.auth_token);
                return Some(access_token.access_token);
            }
        }
        None
    }

    /// Check if the client uuid has completed the authorization flow
    /// If yes drop the session and provide the access token
    /// If not return None
    ///
    /// # Arguments
    ///
    /// * `uuid_code` - The uuid code of the client
    ///
    /// # Returns
    ///
    /// * `Option<(Token,String,DatabaseUserInfo)>`
    /// - The access token
    /// - The username
    /// - The database user info
    pub async fn oidc_check_session(
        &self,
        uuid_code: String,
    ) -> Option<(Token, String, DatabaseUserInfo)> {
        let mut oidc_sessions = self.oidc_sessions.write().await;
        let oidc_session = oidc_sessions.get_mut(&uuid_code);
        if oidc_session.is_none() {
            return None;
        }
        let oidc_session = oidc_session.unwrap();
        let name = if let Some(name) = oidc_session.name.clone() {
            name
        } else {
            oidc_session.id.clone()
        };
        let email = if let Some(email) = oidc_session.email.clone() {
            email
        } else {
            "tobefilled@example;org".to_string()
        };
        if oidc_session.auth_token.is_some() {
            let res = self
                .db
                .get_user_for_oauth2(name, email, oidc_session.uuid.clone())
                .await;
            if res.is_none() {
                log::debug!("oidc_check_session user not found");
                return None;
            }
            let (uuid_vec, username, db_user_info) = res.unwrap();
            if !db_user_info.active {
                log::debug!("oidc_check_session user not active");
                return None;
            }
            let token = self
                .get_access_token(uuid_vec, &username, db_user_info.admin)
                .await;
            // User has completed the authorization flow
            oidc_sessions.remove(&uuid_code);
            return Some((token, username, db_user_info));
        }
        None
    }

    /// Get the users's personal address book guid
    pub async fn get_ab_personal_guid(&self, user_id: UserId) -> Option<String> {
        self.db.get_ab_personal_guid(user_id).await
    }

    /// Add a peer to an address book
    pub async fn add_ab_peer(&self, ab: &str, ab_peer: AbPeer) -> Option<()> {
        self.db.add_peer_to_ab(ab, ab_peer).await
    }

    /// Get all peers from an address book
    /// Share rule `user_id` holds on address book `ab` (0 = no access).
    pub async fn get_ab_rule_for_user(&self, ab: &str, user_id: &UserId) -> u32 {
        let is_admin = self.with_user_info(user_id, |u| u.admin).await.unwrap_or(false);
        self.db.get_ab_rule_for_user(ab, user_id, is_admin).await.unwrap_or(0)
    }

    pub async fn get_ab_peers(&self, ab: &str) -> Option<Vec<AbPeer>> {
        self.db.get_peers_from_ab(ab).await
    }

    /// Delete a peer in an address book
    pub async fn delete_ab_peer(&self, ab: &str, peers_to_delete: Vec<String>) -> Option<()> {
        for peer in peers_to_delete {
            self.db.delete_peer_from_ab(ab, peer.as_str()).await;
        }
        Some(())
    }

    /// Get a peer from an address book
    pub async fn get_ab_peer(&self, ab: &str, peer: &str) -> Option<AbPeer> {
        self.db.get_ab_peer(ab, peer).await
    }

    /// Add a tag to an address book
    pub async fn add_ab_tag(&self, ab: &str, tag: AbTag) -> Option<()> {
        self.db.add_tag_to_ab(ab, tag).await
    }

    /// Get all tags from an address book
    pub async fn get_ab_tags(&self, ab: &str) -> Option<Vec<AbTag>> {
        self.db.get_ab_tags(ab).await
    }

    /// Get a tag from an address book
    pub async fn get_ab_tag(&self, ab: &str, tag: &str) -> Option<AbTag> {
        let ab_tag = self.db.get_ab_tag(ab, tag).await;
        if ab_tag.is_none() {
            return None;
        }
        let ab_tag = ab_tag.unwrap();
        Some(ab_tag)
    }

    /// Rename a tag in an address book
    pub async fn rename_ab_tag(&self, ab: &str, old_name: &str, tag: AbTag) -> Option<()> {
        self.db.rename_ab_tag(ab, old_name, tag).await
    }

    /// Delete some tags from an address book
    pub async fn delete_ab_tags(&self, ab: &str, tags_to_delete: Vec<String>) -> Option<()> {
        for tag in tags_to_delete {
            self.db.delete_tag_from_ab(ab, tag.as_str()).await;
        }
        Some(())
    }

    /// Add a user
    /// This function is used to add a user to the database
    pub async fn add_user(&self, user_parameters: AddUserRequest) -> Option<()> {
        self.db
            .add_user(
                user_parameters.name,
                user_parameters.email,
                user_parameters.is_admin,
                user_parameters.group_name,
            )
            .await
    }

    /// Change user status
    pub async fn user_change_status(&self, user: &str, disable: bool) -> Option<()> {
        self.db.user_change_status(user, (!disable) as u32).await
    }

    /// Get all users
    pub async fn get_all_users(
        &self,
        name: Option<&str>,
        email: Option<&str>,
        current: u32,
        page_size: u32,
    ) -> Option<Vec<UserListResponse>> {
        self.db.get_all_users(name, email, current, page_size).await
    }

    /// Update a user
    pub async fn user_update(
        &self,
        user_id: UserId,
        user_parameters: UpdateUserRequest,
    ) -> Option<()> {
        self.db.user_update(user_id, user_parameters).await
    }

    /// Get all peers
    pub async fn get_all_peers(&self) -> Option<Vec<Peer>> {
        self.db.get_all_peers().await
    }

    /// Get groups
    pub async fn get_groups(&self, offset: u32, page_size: u32) -> Option<Vec<Group>> {
        self.db.get_groups(offset, page_size).await
    }

    /// Get shared address books
    pub async fn get_shared_address_books(&self, user_id: UserId) -> Option<Vec<AddressBook>> {
        self.db.get_shared_address_books(user_id).await
    }

    pub async fn get_ab_rules(&self, offset: u32, page_size: u32, ab: &str) -> Option<Vec<AbRule>> {
        self.db.get_ab_rules(offset, page_size, ab).await
    }

    pub async fn delete_ab_rule(&self, rule: &str) -> Option<()> {
        self.db.delete_ab_rule(rule).await
    }

    pub async fn add_ab_rule(&self, rule: AbRule) -> Option<()> {
        self.db.add_ab_rule(rule).await
    }

    pub async fn get_peers_count(&self, platform: Platform) -> u32 {
        self.db.get_peers_count(platform).await
    }

    pub async fn get_cpus_count(&self) -> Vec<CpuCount> {
        self.db.get_cpus_count().await
    }

    pub async fn create_group(&self, name: &str, team: &str, note: &str) -> Option<()> {
        self.db.create_group(name, team, note).await
    }

    pub async fn update_group(&self, guid: &str, name: &str, team: &str, note: &str) -> Option<()> {
        self.db.update_group(guid, name, team, note).await
    }

    pub async fn get_group(&self, guid: &str) -> Option<Group> {
        self.db.get_group(guid).await
    }

    pub async fn delete_group(&self, guid: &str) -> Option<()> {
        self.db.delete_group(guid).await
    }

    /// Add a shared address book given its name and its owner
    /// It returns the guid of the shared address book
    ///
    /// # Arguments
    ///
    /// - `name` - The name of the shared address book
    ///
    /// - `owner` - The owner of the shared address book
    ///
    /// # Returns
    ///
    /// - `Option<String>` - The guid of the shared address book
    pub async fn add_shared_address_book(&self, name: &str, owner: &str) -> Option<String> {
        self.db.add_shared_address_book(name, owner).await
    }

    pub async fn delete_shared_address_book(&self, guid: &str) -> Option<()> {
        self.db.delete_shared_address_book(guid).await
    }

    pub async fn delete_shared_address_books(&self, shareds:Vec<String>) -> Option<()> {
        for shared in shareds {
            self.db.delete_shared_address_book(shared.as_str()).await;
        }
        Some(())
    }
    pub async fn update_shared_address_book(&self, guid: &str, name: &str) -> Option<()> {
        self.db.update_shared_address_book(guid, name).await
    }

    pub async fn audit_conn(&self, request: &utils::AuditConnRequest) -> Option<String> {
        let action = request.action.to_lowercase();
        match action.as_str() {
            "new" => {
                if !request.nonce.is_empty() {
                    if let Some(existing) = self.db.find_audit_conn_by_nonce(&request.nonce).await {
                        let uuid = uuid::Uuid::from_slice(&existing).ok()?;
                        return Some(uuid.to_string());
                    }
                }
                let guid = uuid::Uuid::new_v4();
                let info = serde_json::json!({
                    "id": request.id,
                    "uuid": request.uuid,
                    "conn_id": request.conn_id,
                    "session_id": request.session_id,
                    "nonce": request.nonce,
                    "ip": request.ip,
                });
                self.db.insert_audit_conn(
                    guid.as_bytes(),
                    Some(0),
                    request.id.as_bytes(),
                    None,
                    request.note.as_deref(),
                    &info.to_string(),
                ).await?;
                Some(guid.to_string())
            }
            "close" => {
                if let Some(ref conn_audit_ref) = request.conn_audit_ref {
                    if let Ok(guid) = uuid::Uuid::parse_str(conn_audit_ref) {
                        self.db.update_audit_conn_end_time(guid.as_bytes()).await;
                    }
                } else if !request.nonce.is_empty() {
                    if let Some(existing) = self.db.find_audit_conn_by_nonce(&request.nonce).await {
                        self.db.update_audit_conn_end_time(&existing).await;
                    }
                }
                None
            }
            "login" => {
                if let Some(ref conn_audit_ref) = request.conn_audit_ref {
                    if let Ok(guid) = uuid::Uuid::parse_str(conn_audit_ref) {
                        let note = serde_json::json!({
                            "name": request.name,
                            "os_login": request.os_login,
                        });
                        self.db.update_audit_conn_note(guid.as_bytes(), &note.to_string()).await;
                    }
                }
                None
            }
            _ => {
                log::debug!("audit_conn: unknown action {}", action);
                None
            }
        }
    }

    pub async fn audit_file(&self, request: &utils::AuditFileRequest) -> Option<()> {
        if !request.nonce.is_empty() && self.db.find_audit_file_by_nonce(&request.nonce).await {
            return Some(());
        }
        let guid = uuid::Uuid::new_v4();
        let info = serde_json::json!({
            "conn_id": request.conn_id,
            "nonce": request.nonce,
            "uuid": request.uuid,
            "info": request.info,
        });
        self.db.insert_audit_file(
            guid.as_bytes(),
            request.peer_id.as_bytes(),
            Some(request.id.as_bytes()),
            request.file_type,
            &request.path,
            request.is_file,
            &info.to_string(),
        ).await
    }

    pub async fn audit_alarm(&self, request: &utils::AuditAlarmRequest) -> Option<()> {
        if !request.nonce.is_empty() && self.db.find_audit_alarm_by_nonce(&request.nonce).await {
            return Some(());
        }
        let guid = uuid::Uuid::new_v4();
        let info = serde_json::json!({
            "conn_id": request.conn_id,
            "nonce": request.nonce,
            "uuid": request.uuid,
            "info": request.info,
            "conn_audit_ref": request.conn_audit_ref,
        });
        self.db.insert_audit_alarm(
            guid.as_bytes(),
            request.typ,
            &info.to_string(),
            None,
            Some(request.id.as_bytes()),
        ).await
    }

    pub async fn find_active_audit_conn(
        &self,
        id: &str,
        session_id: &str,
        conn_type: &str,
    ) -> Option<String> {
        let guid = self.db.find_active_audit_conn(id, session_id, conn_type).await?;
        let uuid = uuid::Uuid::from_slice(&guid).ok()?;
        Some(uuid.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bearer::AuthenticatedUserInfo;

    /// State with an OIDC user `admin` promoted to admin.
    async fn test_state() -> ApiState {
        let state = ApiState::new_with_db(&crate::testing::fresh_database_url().await).await;
        state
            .db
            .get_user_for_oauth2("admin".to_string(), "admin@example.org".to_string(), "admin-uuid".to_string())
            .await
            .unwrap();
        state.set_admin("admin", true).await.unwrap();
        state
    }

    #[tokio::test]
    async fn test_oidc_login_issues_a_session_for_the_admin() {
        let state = test_state().await;
        let result = state
            .test_oidc_login(&"admin".to_string())
            .await;
        assert!(result.is_some());
        let (info, token) = result.unwrap();
        assert_eq!(info.name, "admin");
        assert!(info.admin);
        assert!(!token.to_base64().is_empty());
    }

    #[tokio::test]
    async fn new_oidc_user_gets_no_session_until_activated() {
        // OAUTH2_CREATE_USER is unset, so the new user is inactive.
        let state = test_state().await;
        let result = state
            .test_oidc_login(&"nobody".to_string())
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn login_inactive_user_rejected() {
        let state = test_state().await;
        state
            .add_user(AddUserRequest {
                name: "inactive".to_string(),
                email: "inact@e.com".to_string(),
                is_admin: false,
                group_name: "Default".to_string(),
            })
            .await;
        let (_, user) = state.db.find_user_by_name("inactive").await;
        let (user_id, _, _) = user.unwrap();
        let guid = uuid::Uuid::from_slice(&user_id).unwrap().to_string();
        state.user_change_status(&guid, true).await;

        let result = state
            .test_oidc_login(&"inactive".to_string())
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn find_session_after_login() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await;
        assert!(session.is_some());
    }

    #[tokio::test]
    async fn find_session_invalid_token() {
        let state = test_state().await;
        let fake = Token::new_random();
        let session = state.find_session(&fake).await;
        assert!(session.is_none());
    }

    #[tokio::test]
    async fn get_current_user_name() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await.unwrap();
        let auth_info = AuthenticatedUserInfo {
            session_id: session.session_id,
            user_id: session.user_id,
            access_token: token,
        };
        let name = state.get_current_user_name(&auth_info).await;
        assert_eq!(name, Some("admin".to_string()));
    }

    #[tokio::test]
    async fn is_current_user_admin() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await.unwrap();
        let auth_info = AuthenticatedUserInfo {
            session_id: session.session_id,
            user_id: session.user_id,
            access_token: token,
        };
        assert_eq!(state.is_current_user_admin(&auth_info).await, Some(true));
    }

    #[tokio::test]
    async fn logout_removes_session() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await.unwrap();
        let auth_info = AuthenticatedUserInfo {
            session_id: session.session_id,
            user_id: session.user_id,
            access_token: token.clone(),
        };
        let result = state.user_logout(&auth_info).await;
        assert!(result.is_some());
        assert!(state.find_session(&token).await.is_none());
    }

    #[tokio::test]
    async fn multiple_logins_then_logout() {
        let state = test_state().await;
        let (_, token1) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let (_, token2) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();

        let s1 = state.find_session(&token1).await.unwrap();
        let auth1 = AuthenticatedUserInfo {
            session_id: s1.session_id,
            user_id: s1.user_id,
            access_token: token1.clone(),
        };
        state.user_logout(&auth1).await;
        assert!(state.find_session(&token1).await.is_none());
        assert!(state.find_session(&token2).await.is_some());

        let name = state
            .get_current_user_name(&AuthenticatedUserInfo {
                session_id: 2,
                user_id: auth1.user_id.clone(),
                access_token: token2.clone(),
            })
            .await;
        assert_eq!(name, Some("admin".to_string()));
    }

    #[tokio::test]
    async fn address_book_set_and_get() {
        let state = test_state().await;
        let user_id: UserId = vec![1, 2, 3];
        let ab = AddressBook {
            ab: "test data".to_string(),
            ..Default::default()
        };
        state
            .set_user_address_book(user_id.clone(), ab)
            .await;
        let result = state.get_user_address_book(user_id).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().ab, "test data");
    }

    #[tokio::test]
    async fn address_book_update_marks_modified() {
        let state = test_state().await;
        let user_id: UserId = vec![1, 2, 3];
        let ab1 = AddressBook {
            ab: "v1".to_string(),
            ..Default::default()
        };
        state
            .set_user_address_book(user_id.clone(), ab1)
            .await;
        let ab2 = AddressBook {
            ab: "v2".to_string(),
            ..Default::default()
        };
        state
            .set_user_address_book(user_id.clone(), ab2)
            .await;
        let result = state.get_user_address_book(user_id).await;
        assert_eq!(result.unwrap().ab, "v2");
    }

    #[tokio::test]
    async fn oidc_session_lifecycle() {
        let state = test_state().await;
        let oidc = OidcState {
            id: "user1".to_string(),
            uuid: "uuid1".to_string(),
            code: None,
            auth_token: None,
            redirect_url: None,
            callback_url: None,
            provider: None,
            name: None,
            email: None,
            client_redirect_uri: None,
        };
        let result = state
            .insert_oidc_session("code1".to_string(), oidc)
            .await;
        assert!(result.is_some());

        let session = state.get_oidc_session("code1".to_string()).await;
        assert!(session.is_some());
        assert_eq!(session.unwrap().id, "user1");

        let missing = state.get_oidc_session("missing".to_string()).await;
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn oidc_insert_duplicate_returns_none() {
        let state = test_state().await;
        let oidc = OidcState {
            id: "u".to_string(),
            uuid: "u".to_string(),
            code: None,
            auth_token: None,
            redirect_url: None,
            callback_url: None,
            provider: None,
            name: None,
            email: None,
            client_redirect_uri: None,
        };
        state
            .insert_oidc_session("dup".to_string(), oidc.clone())
            .await;
        let result = state
            .insert_oidc_session("dup".to_string(), oidc)
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn oidc_check_session_no_auth_token() {
        let state = test_state().await;
        let oidc = OidcState {
            id: "u".to_string(),
            uuid: "u".to_string(),
            code: None,
            auth_token: None,
            redirect_url: None,
            callback_url: None,
            provider: None,
            name: None,
            email: None,
            client_redirect_uri: None,
        };
        state
            .insert_oidc_session("check".to_string(), oidc)
            .await;
        let result = state.oidc_check_session("check".to_string()).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn oidc_check_session_missing() {
        let state = test_state().await;
        let result = state.oidc_check_session("missing".to_string()).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn oidc_exchange_code_missing_session() {
        let state = test_state().await;
        let result = state
            .oidc_session_exchange_code("code".to_string(), "missing".to_string())
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn maintenance_runs_without_error() {
        let state = test_state().await;
        state.maintenance().await;
        state.check_maintenance().await;
    }

    #[tokio::test]
    async fn with_user_info_no_user() {
        let state = test_state().await;
        let result = state
            .with_user_info(&vec![99], |_| true)
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn ui_get_all_users() {
        let state = test_state().await;
        let users = state.ui_get_all_users().await;
        assert!(users.is_some());
        assert!(!users.unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_and_get_user() {
        let state = test_state().await;
        let result = state
            .add_user(AddUserRequest {
                name: "newuser".to_string(),
                email: "new@e.com".to_string(),
                is_admin: false,
                group_name: "Default".to_string(),
            })
            .await;
        assert!(result.is_some());
        let info = state.ui_get_user_info("newuser".to_string()).await;
        assert!(info.is_some());
    }

    #[tokio::test]
    async fn get_groups() {
        let state = test_state().await;
        let groups = state.get_groups(0, 100).await;
        assert!(groups.is_some());
    }

    #[tokio::test]
    async fn group_crud() {
        let state = test_state().await;
        state.create_group("G1", "Default", "note").await;
        let groups = state.get_groups(0, 100).await.unwrap();
        let g = groups.iter().find(|g| g.name == "G1").unwrap();
        state.update_group(&g.guid, "G2", "Default", "n2").await;
        let g2 = state.get_group(&g.guid).await.unwrap();
        assert_eq!(g2.name, "G2");
        state.delete_group(&g.guid).await;
        assert!(state.get_group(&g.guid).await.is_none());
    }

    #[tokio::test]
    async fn get_all_peers_empty() {
        let state = test_state().await;
        let peers = state.get_all_peers().await;
        assert!(peers.is_some());
        assert!(peers.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_peers_count() {
        let state = test_state().await;
        assert_eq!(state.get_peers_count(Platform::All).await, 0);
    }

    #[tokio::test]
    async fn get_cpus_count() {
        let state = test_state().await;
        let cpus = state.get_cpus_count().await;
        assert!(cpus.is_empty());
    }

    #[tokio::test]
    async fn shared_address_book_lifecycle() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await.unwrap();
        let owner_uuid = uuid::Uuid::from_slice(&session.user_id)
            .unwrap()
            .to_string();

        let guid = state
            .add_shared_address_book("Shared", &owner_uuid)
            .await;
        assert!(guid.is_some());
        let guid = guid.unwrap();

        state
            .update_shared_address_book(&guid, "Renamed")
            .await;

        let abs = state
            .get_shared_address_books(session.user_id.clone())
            .await;
        assert!(abs.is_some());

        state.delete_shared_address_book(&guid).await;
    }

    #[tokio::test]
    async fn delete_shared_address_books_batch() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await.unwrap();
        let owner_uuid = uuid::Uuid::from_slice(&session.user_id)
            .unwrap()
            .to_string();

        let g1 = state
            .add_shared_address_book("S1", &owner_uuid)
            .await
            .unwrap();
        let g2 = state
            .add_shared_address_book("S2", &owner_uuid)
            .await
            .unwrap();

        let result = state
            .delete_shared_address_books(vec![g1, g2])
            .await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn ab_personal_guid() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await.unwrap();
        let guid = state
            .get_ab_personal_guid(session.user_id)
            .await;
        assert!(guid.is_some());
    }

    #[tokio::test]
    async fn ab_tags_lifecycle() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await.unwrap();
        let ab = state
            .get_ab_personal_guid(session.user_id)
            .await
            .unwrap();

        let tag = AbTag {
            name: "test".to_string(),
            color: 0xFF,
        };
        state.add_ab_tag(&ab, tag).await;
        let tags = state.get_ab_tags(&ab).await;
        assert!(tags.is_some());
        let found = state.get_ab_tag(&ab, "test").await;
        assert!(found.is_some());

        let renamed = AbTag {
            name: "renamed".to_string(),
            color: 0x00,
        };
        state.rename_ab_tag(&ab, "test", renamed).await;
        state
            .delete_ab_tags(&ab, vec!["renamed".to_string()])
            .await;
    }

    #[tokio::test]
    async fn ab_peers_lifecycle() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await.unwrap();
        let ab = state
            .get_ab_personal_guid(session.user_id)
            .await
            .unwrap();

        let peer = AbPeer {
            id: "peer1".to_string(),
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
        };
        state.add_ab_peer(&ab, peer).await;
        let peers = state.get_ab_peers(&ab).await;
        assert!(peers.is_some());
        let p = state.get_ab_peer(&ab, "peer1").await;
        assert!(p.is_some());
        state
            .delete_ab_peer(&ab, vec!["peer1".to_string()])
            .await;
    }

    #[tokio::test]
    async fn ab_rules_lifecycle() {
        let state = test_state().await;
        let (_, token) = state
            .test_oidc_login(&"admin".to_string())
            .await
            .unwrap();
        let session = state.find_session(&token).await.unwrap();
        let owner_uuid = uuid::Uuid::from_slice(&session.user_id)
            .unwrap()
            .to_string();

        let ab_guid = state
            .add_shared_address_book("RuleAB", &owner_uuid)
            .await
            .unwrap();

        let rule = AbRule {
            guid: ab_guid.clone(),
            user: Some(owner_uuid.clone()),
            group: None,
            rule: 2,
        };
        state.add_ab_rule(rule).await;
        let rules = state.get_ab_rules(0, 100, &ab_guid).await;
        assert!(rules.is_some());

        let rules = rules.unwrap();
        // add_shared_address_book already inserted an owner rule=3; our own add_ab_rule call
        // above added a second row (rule=2) for the same user.
        let added = rules
            .iter()
            .find(|r| r.rule == 2)
            .expect("the rule just inserted must be present");
        state.delete_ab_rule(&added.guid).await;
    }

    #[tokio::test]
    async fn get_all_users() {
        let state = test_state().await;
        let users = state
            .get_all_users(None, None, 1, 100)
            .await;
        assert!(users.is_some());
    }

    #[tokio::test]
    async fn user_update() {
        let state = test_state().await;
        state
            .add_user(AddUserRequest {
                name: "upd".to_string(),
                email: "upd@e.com".to_string(),
                is_admin: false,
                group_name: "Default".to_string(),
            })
            .await;
        let (_, user) = state.db.find_user_by_name("upd").await;
        let (user_id, _, _) = user.unwrap();
        let params = UpdateUserRequest {
            uuid: String::new(),
            name: Some("updated".to_string()),
            email: None,
            note: None,
            status: None,
            is_admin: None,
            group_name: None,
        };
        let result = state.user_update(user_id, params).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn user_delete() {
        let state = test_state().await;
        state
            .add_user(AddUserRequest {
                name: "todelete".to_string(),
                email: "del@e.com".to_string(),
                is_admin: false,
                group_name: "Default".to_string(),
            })
            .await;
        let (_, user) = state.db.find_user_by_name("todelete").await;
        let (user_id, _, _) = user.unwrap();
        let guid = uuid::Uuid::from_slice(&user_id).unwrap().to_string();
        let result = state.user_delete(&guid).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn user_change_status_wrapper() {
        let state = test_state().await;
        state
            .add_user(AddUserRequest {
                name: "statususer".to_string(),
                email: "status@e.com".to_string(),
                is_admin: false,
                group_name: "Default".to_string(),
            })
            .await;
        let (_, user) = state.db.find_user_by_name("statususer").await;
        let (user_id, _, _) = user.unwrap();
        let guid = uuid::Uuid::from_slice(&user_id).unwrap().to_string();
        let result = state.user_change_status(&guid, false).await;
        assert!(result.is_some());
    }
}
