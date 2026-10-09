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
    collections::BTreeMap,
    default::Default,
};

use base64::Engine as _;
use oauth2::ProviderConfig;
use std::sync::Arc;
use oauth2::oauth_provider::OAuthProvider;

use tokio::sync::RwLock;
use utils::{
    AbPeer, AbRule, AbTag, AddUserRequest, AddressBook, CpuCount, Group, HeartbeatResponse, OidcState, Peer, Platform,
    StrategyPush, StrategySummary, Token, UpdateUserRequest, UserListResponse,
};

pub struct ApiState {
    /// IdP stand-ins by login code, on this instance only. Test-only.
    #[cfg(any(test, feature = "test-util"))]
    test_providers: std::sync::Mutex<std::collections::HashMap<String, Arc<dyn OAuthProvider>>>,
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

/// `set_audit_note` failure modes (spec §8).
#[derive(Debug, PartialEq, Eq)]
pub enum AuditNoteError {
    BadGuid,
    NotFound,
    Db,
}

const VIEWER_FIELD_MAX_CHARS: usize = 255;

impl ApiState {
    pub async fn new_with_db(db_url: &str) -> Self {
        let db = Database::connect_with_retry(db_url).await;
        Self {
            db,
            #[cfg(any(test, feature = "test-util"))]
            test_providers: Default::default(),
            oauth2_providers: Default::default(),
        }
    }

    /// Simulates a successful OIDC login whose `sub` and `name` are `username`
    /// (creating the user if needed) and issues a session. Test-only.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_oidc_login(&self, username: &String) -> Option<(utils::UserInfo, Token)> {
        let email = format!("{username}@example.org");
        let (user_id, name, db_user_info) =
            self.db.get_user_for_oauth2(username, username, Some(&email)).await?;
        if !db_user_info.active {
            return None;
        }
        let access_token = self.get_access_token(user_id, &name, db_user_info.admin).await;
        Some((
            utils::UserInfo {
                name,
                email: Some(email),
                admin: db_user_info.admin,
                ..Default::default()
            },
            access_token,
        ))
    }

    /// Makes a pending login use `provider` when this instance runs its callback. Test-only.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_set_oidc_provider(&self, uuid_code: &str, provider: Arc<dyn OAuthProvider>) -> bool {
        if self.get_oidc_session(uuid_code.to_string()).await.is_none() {
            return false;
        }
        self.test_providers.lock().unwrap().insert(uuid_code.to_string(), provider);
        true
    }

    #[cfg(any(test, feature = "test-util"))]
    fn test_provider(&self, uuid_code: &str) -> Option<Arc<dyn OAuthProvider>> {
        self.test_providers.lock().unwrap().get(uuid_code).cloned()
    }

    #[cfg(not(any(test, feature = "test-util")))]
    fn test_provider(&self, _uuid_code: &str) -> Option<Arc<dyn OAuthProvider>> {
        None
    }

    /// Makes a pending login `secs` older. Test-only.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_age_oidc_session(&self, uuid_code: &str, secs: u64) -> bool {
        self.db.test_age_oidc_login(uuid_code, secs).await
    }

    async fn get_access_token(&self, user_id: Vec<u8>, _username: &String, _is_admin: bool) -> Token {
        let access_token = Token::new_random();
        let token_id = access_token.to_base64();

        self.db.insert_session(&token_id, &user_id, 2592000).await;

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
        self.db.get_legacy_address_book(user_id).await
    }

    pub async fn set_user_address_book(&self, user_id: UserId, address_book: AddressBook) -> Option<()> {
        self.db.update_legacy_address_books(vec![(user_id, address_book)]).await
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

    /// Promotes (`admin = true`) or demotes the user matching `identifier` (OIDC subject,
    /// email or name; must be unambiguous) and returns its display name.
    /// Backs the `rustdesk-api admin` CLI, the only way to make an admin.
    pub async fn set_admin(&self, email: &str, admin: bool) -> Result<String, String> {
        self.db.set_admin(email, admin).await
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
        // The client can exit before its close record is sent; its next heartbeat no longer lists the connection.
        self.db
            .end_audit_conns_not_alive(&heartbeat.id, &heartbeat.uuid, &heartbeat.conns, AUDIT_CONN_HEARTBEAT_GRACE_SECS)
            .await;
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

    pub async fn insert_oidc_session(&self, uuid_code: String, oidc_state: OidcState) -> Option<OidcState> {
        let provider = oidc_state.provider.as_ref().map(|p| p.get_provider_type());
        self.db
            .insert_oidc_login(&uuid_code, &oidc_state, provider, OIDC_LOGIN_TTL_SECS)
            .await?
            .then_some(oidc_state)
    }

    pub async fn get_oidc_session(&self, uuid_code: String) -> Option<OidcState> {
        self.db.get_oidc_login(&uuid_code, OIDC_LOGIN_TTL_SECS).await
    }

    /// Finishes the provider leg of a login; returns where to send the browser and, when it
    /// succeeded, the one-time result for the starter.
    pub async fn oidc_complete_callback(&self, uuid_code: &str, code: &str) -> Option<(String, Option<String>)> {
        // Single use across pods: a replayed callback must not replace or drop the login's result.
        let (login, provider) = self.db.claim_oidc_callback(uuid_code, OIDC_LOGIN_TTL_SECS).await?;
        let Some(identity) = self.exchange_oidc_code(uuid_code, &login, provider, code).await else {
            self.db.delete_oidc_login(uuid_code).await;
            self.record_login(&login, "idp_error", String::new(), String::new()).await;
            return Some((login.return_to, None));
        };
        let result = oauth2::pkce::random_secret();
        self.db
            .finish_oidc_login(uuid_code, &identity.subject, identity.name.as_deref(), identity.email.as_deref(), &result)
            .await?;
        Some((login.return_to, Some(result)))
    }

    /// The IdP's answer for `code`; the provider is rebuilt from its type, so any pod can ask.
    async fn exchange_oidc_code(
        &self,
        uuid_code: &str,
        login: &OidcState,
        provider: Option<oauth2::Provider>,
        code: &str,
    ) -> Option<oauth2::oauth_provider::OAuthResponse> {
        let provider = self.test_provider(uuid_code).or_else(|| oauth2::oauth_provider::provider_for(provider?))?;
        let callback_url = login.callback_url.as_deref()?;
        let provider_login = login.provider_login.as_ref()?;
        provider
            .exchange_code(code, callback_url, provider_login)
            .await
            .map_err(|e| log::error!("OIDC code exchange failed: {}", e))
            .ok()
    }

    /// Ends a login the IdP sent back with `error` (e.g. the user cancelled); returns where to
    /// send the browser.
    pub async fn oidc_fail_callback(&self, uuid_code: &str, error: &str) -> Option<String> {
        let login = self.db.take_failed_oidc_login(uuid_code, OIDC_LOGIN_TTL_SECS).await?;
        let detail = error.chars().filter(|c| c.is_ascii_graphic()).take(64).collect();
        self.record_login(&login, "idp_denied", detail, String::new()).await;
        Some(login.return_to)
    }

    /// Issues the session for a one-time result when the starter proves itself; the result
    /// is used up either way.
    pub async fn oidc_redeem(&self, req: &utils::OidcTokenRequest) -> Option<(Token, String, DatabaseUserInfo)> {
        let (login, expired) = self.db.take_oidc_result(&req.result, OIDC_RESULT_TTL_SECS).await?;
        let uuid = base64::prelude::BASE64_STANDARD.decode(&req.uuid).ok().and_then(|u| String::from_utf8(u).ok());
        if expired
            || oauth2::pkce::s256_challenge(&req.code_verifier) != login.code_challenge
            || login.id != req.id
            || uuid.as_deref() != Some(login.uuid.as_str())
        {
            log::warn!("oidc_redeem: refused a result (expired, wrong verifier or another client)");
            let detail = if expired {
                "expired"
            } else if oauth2::pkce::s256_challenge(&req.code_verifier) != login.code_challenge {
                "wrong verifier"
            } else {
                "another client"
            };
            let name = login.name.clone().or_else(|| login.email.clone()).unwrap_or_default();
            self.record_login(&login, "refused", detail.to_string(), name).await;
            return None;
        }
        let sub = login.sub.clone()?;
        let email = login.email.clone();
        let name = login.name.clone().or_else(|| email.clone()).unwrap_or_else(|| sub.clone());
        let (user_id, username, db_user_info) = self.db.get_user_for_oauth2(&sub, &name, email.as_deref()).await?;
        if !db_user_info.active {
            log::debug!("oidc_redeem: user not active");
            self.record_login(&login, "inactive", String::new(), username).await;
            return None;
        }
        let token = self.get_access_token(user_id.clone(), &username, db_user_info.admin).await;
        self.record_viewer_login(&login, &user_id).await;
        self.record_login(&login, "ok", String::new(), username.clone()).await;
        Some((token, username, db_user_info))
    }

    /// Writes the login's outcome to the login audit.
    async fn record_login(&self, login: &OidcState, outcome: &'static str, detail: String, user_name: String) {
        // Self-reported by the client; bounded like the viewer list.
        let bounded = |s: &str| s.chars().take(VIEWER_FIELD_MAX_CHARS).collect::<String>();
        let record = utils::LoginRecord {
            outcome,
            detail,
            client: login_client(&login.return_to),
            sub: login.sub.clone(),
            user_name,
            rustdesk_id: bounded(&login.id),
            hostname: bounded(&login.device_name),
            os: bounded(&login.device_os),
            ip: login.requester_ip.clone().unwrap_or_default(),
        };
        self.db.insert_audit_login(&record).await;
    }

    pub async fn list_audit_logins(&self, q: &utils::AuditQuery, outcome: Option<&str>) -> Option<(i64, Vec<utils::AuditLoginLog>)> {
        self.db.list_audit_logins(q, outcome).await
    }

    /// Remembers the machine of a native client login so viewers that never register are listed.
    async fn record_viewer_login(&self, login: &OidcState, user_id: &[u8]) {
        let id_ok = (1..=32).contains(&login.id.len()) && login.id.bytes().all(|b| b.is_ascii_alphanumeric());
        if login.device_type != "client" || !id_ok || login.uuid.is_empty() || login.uuid.chars().count() > VIEWER_FIELD_MAX_CHARS {
            return;
        }
        // Both come unchecked from the client's login request.
        let bounded = |s: &str| s.chars().take(VIEWER_FIELD_MAX_CHARS).collect::<String>();
        self.db
            .upsert_viewer_device(
                &login.id,
                &login.uuid,
                &bounded(&login.device_name),
                &bounded(&login.device_os),
                login.requester_ip.as_deref().unwrap_or_default(),
                user_id,
            )
            .await;
    }

    /// Registers a device as hbbs would; `uuid` is base64 as in device records. Test-only.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_register_device(&self, id: &str, uuid: &str) {
        self.db.test_register_device(id, uuid).await;
    }

    /// A device's stored info JSON. Test-only.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_peer_info(&self, id: &str) -> String {
        self.db.test_peer_info(id).await
    }

    /// Makes a recorded viewer machine `secs` older (all its times). Test-only.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn test_age_viewer_device(&self, id: &str, secs: i64) {
        self.db.test_age_viewer_device(id, secs).await;
    }

    /// Bumps `last_seen` of a viewer machine already recorded for this user.
    pub async fn touch_viewer_device(&self, id: &str, uuid: &str, user_id: &[u8]) -> Option<bool> {
        self.db.touch_viewer_device(id, uuid, user_id).await
    }

    pub async fn list_viewer_devices(&self, offset: i64, limit: i64) -> Option<(i64, Vec<utils::ViewerDevice>)> {
        self.db.list_viewer_devices(offset, limit).await
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

    pub async fn list_strategies(&self) -> Option<Vec<StrategySummary>> {
        self.db.list_strategies().await
    }

    pub async fn get_strategy(&self, guid: &str) -> Option<(StrategySummary, BTreeMap<String, String>)> {
        self.db.get_strategy(guid).await
    }

    pub async fn set_strategy_options(&self, guid: &str, options: &BTreeMap<String, String>) -> Option<i64> {
        self.db.set_strategy_options(guid, options).await
    }

    pub async fn bump_strategy(&self, guid: &str) -> Option<i64> {
        self.db.bump_strategy(guid).await
    }

    /// The heartbeat reply: the policy only when the device's `modified_at` differs (Pro semantics).
    pub async fn policy_for_heartbeat(&self, device_modified_at: i64) -> HeartbeatResponse {
        match self.db.get_strategy(utils::policy::DEFAULT_STRATEGY_GUID).await {
            Some((s, options)) if s.modified_at != device_modified_at => HeartbeatResponse {
                modified_at: s.modified_at,
                strategy: Some(StrategyPush { config_options: utils::policy::allowed_options(options) }),
            },
            Some((s, _)) => HeartbeatResponse { modified_at: s.modified_at, strategy: None },
            None => HeartbeatResponse { modified_at: device_modified_at, strategy: None },
        }
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

    /// Stores one connection record (docs/audit-api-spec.md §3); `None` means it was not stored.
    pub async fn audit_conn(&self, request: &utils::AuditConnRequest) -> Option<()> {
        let (id, uuid, conn_id) = (&request.id, &request.uuid, request.conn_id);
        // A viewer's menu note (spec §4) carries no uuid; it only lands on an existing row of its session.
        let menu_note = request.action.is_empty() && request.note.is_some() && uuid.is_empty()
            && request.peer.is_none() && request.conn_type.is_none();
        if !menu_note && !self.from_registered_device("conn", id, uuid).await {
            return Some(());
        }
        match request.action.to_lowercase().as_str() {
            "new" => {
                if !request.nonce.is_empty() && self.db.find_audit_conn_by_nonce(&request.nonce).await.is_some() {
                    return Some(());
                }
                let info = serde_json::json!({
                    "id": id,
                    "uuid": uuid,
                    "conn_id": conn_id,
                    "session_id": request.session_id,
                    "nonce": request.nonce,
                    "ip": request.ip,
                });
                let guid = uuid::Uuid::new_v4();
                if !self.db
                    .insert_audit_conn(guid.as_bytes(), None, id.as_bytes(), None, request.note.as_deref(), &info.to_string())
                    .await?
                {
                    // Another pod stored this record first.
                    return Some(());
                }
                // conn_id restarts with the RustDesk process, so an older open row with this key is a dead session.
                self.db.end_open_audit_conns(id, uuid, conn_id, guid.as_bytes()).await?;
                if let Some(conn_ref) = request.conn_audit_ref.as_deref().filter(|r| !r.is_empty()) {
                    match self.resolve_audit_conn_ref(conn_ref, id).await {
                        // The row is already stored; a failed attribution update must not make the
                        // client retry (it would just hit find_audit_conn_by_nonce and never retry this).
                        Some(user) => { self.db.set_audit_conn_user(guid.as_bytes(), &user).await; }
                        None => log::debug!("audit_conn: unknown conn_audit_ref"),
                    }
                }
                Some(())
            }
            // close carries neither the new record's nonce nor a conn_audit_ref.
            "close" => match self.db.find_open_audit_conn(id, uuid, conn_id).await {
                Some(guid) => self.db.update_audit_conn_end_time(&guid).await,
                None => Some(()),
            },
            // Menu note from the viewer (spec §4): no action, uuid, peer or type.
            // session_id 0 is the "new" row's default, not a real session; applying the note
            // there would overwrite the device's latest not-yet-authorized row.
            "" if request.note.is_some() && request.uuid.is_empty() && request.peer.is_none() && request.conn_type.is_none() && request.session_id == 0 => {
                log::debug!("audit_conn: menu note without a session_id");
                Some(())
            }
            "" if request.note.is_some() && request.uuid.is_empty() && request.peer.is_none() && request.conn_type.is_none() => {
                let id = request.id.split('@').next().unwrap_or_default();
                let note = request.note.as_deref().unwrap_or_default();
                if self.db.set_audit_conn_note_by_session(id, request.session_id, note).await.is_none() {
                    log::debug!("audit_conn: note for unknown session of {id}");
                }
                Some(())
            }
            "" if request.peer.is_some() || request.conn_type.is_some() => {
                let guid = match self.db.find_open_audit_conn(id, uuid, conn_id).await {
                    Some(guid) => guid,
                    None => {
                        // The new record was lost; keep the connection anyway. The record's nonce
                        // keeps a retry that reaches another pod from adding a second row.
                        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
                        let info = serde_json::json!({ "id": id, "uuid": uuid, "conn_id": conn_id, "nonce": request.nonce });
                        if !self.db.insert_audit_conn(&guid, None, id.as_bytes(), None, None, &info.to_string()).await? {
                            return Some(());
                        }
                        guid
                    }
                };
                let peer = request.peer.as_deref().unwrap_or_default();
                let mut patch = serde_json::json!({
                    "session_id": request.session_id,
                    "peer_name": peer.get(1),
                    "primary_auth": request.primary_auth,
                    "two_factor": request.two_factor,
                });
                // Copied, not joined at read time: the record keeps the machine as it was during the session.
                if let Some((hostname, os, login_ip)) = self.viewer_machine(id, uuid, conn_id, peer.first()).await {
                    patch["peer_hostname"] = hostname.into();
                    patch["peer_os"] = os.into();
                    patch["peer_login_ip"] = login_ip.into();
                }
                self.db
                    .set_audit_conn_authorized(&guid, request.conn_type, peer.first().map(String::as_str), &patch.to_string())
                    .await
            }
            action => {
                log::debug!("audit_conn: unhandled record (action {action:?})");
                Some(())
            }
        }
    }

    /// The viewer's machine from its latest login, when the session's user logged in from that viewer ID.
    async fn viewer_machine(&self, id: &str, uuid: &str, conn_id: i64, viewer: Option<&String>) -> Option<(String, String, String)> {
        let user = self.db.audit_conn_user(id, uuid, conn_id).await?;
        self.db.viewer_machine(viewer?, &user).await.filter(|(hostname, _, _)| !hostname.is_empty())
    }

    pub async fn audit_file(&self, request: &utils::AuditFileRequest) -> Option<()> {
        if !self.from_registered_device("file", &request.id, &request.uuid).await {
            return Some(());
        }
        if !request.nonce.is_empty() && self.db.find_audit_file_by_nonce(&request.nonce).await {
            return Some(());
        }
        let guid = uuid::Uuid::new_v4();
        let info = serde_json::json!({
            "conn_id": request.conn_id,
            "nonce": request.nonce,
            "uuid": request.uuid,
            "info": audit_info(&request.info),
        });
        let user = self.db.audit_conn_user(&request.id, &request.uuid, request.conn_id).await;
        self.db.insert_audit_file(
            guid.as_bytes(),
            request.id.as_bytes(),
            Some(request.peer_id.as_bytes()),
            request.file_type,
            &request.path,
            request.is_file,
            &info.to_string(),
            user.as_deref(),
        ).await
    }

    pub async fn audit_alarm(&self, request: &utils::AuditAlarmRequest) -> Option<()> {
        if !self.from_registered_device("alarm", &request.id, &request.uuid).await {
            return Some(());
        }
        if !request.nonce.is_empty() && self.db.find_audit_alarm_by_nonce(&request.nonce).await {
            return Some(());
        }
        let guid = uuid::Uuid::new_v4();
        let info = serde_json::json!({
            "conn_id": request.conn_id,
            "nonce": request.nonce,
            "uuid": request.uuid,
            "info": audit_info(&request.info),
        });
        let user = match request.conn_audit_ref.as_deref().filter(|r| !r.is_empty()) {
            Some(conn_ref) => match self.resolve_audit_conn_ref(conn_ref, &request.id).await {
                Some(user) => Some(user),
                None => self.db.audit_conn_user(&request.id, &request.uuid, request.conn_id).await,
            },
            None => self.db.audit_conn_user(&request.id, &request.uuid, request.conn_id).await,
        };
        self.db.insert_audit_alarm(
            guid.as_bytes(),
            request.typ,
            &info.to_string(),
            user.as_deref(),
            Some(request.id.as_bytes()),
        ).await
    }

    pub async fn find_active_audit_conn(
        &self,
        id: &str,
        session_id: &str,
        conn_type: &str,
        caller: &UserId,
    ) -> Option<String> {
        let conn_type_i: i16 = conn_type.parse().ok()?;
        let guid = self.db.find_active_audit_conn(id, session_id, conn_type_i, caller).await?;
        let uuid = uuid::Uuid::from_slice(&guid).ok()?;
        Some(uuid.to_string())
    }

    /// Spec §8: the caller sets the note on its own row, or an unattributed one.
    pub async fn set_audit_note(&self, guid: &str, note: &str, caller: &UserId) -> Result<(), AuditNoteError> {
        let guid = uuid::Uuid::parse_str(guid).map_err(|_| AuditNoteError::BadGuid)?;
        match self.db.set_audit_conn_note_by_guid(guid.as_bytes(), note, caller).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(AuditNoteError::NotFound),
            Err(e) => {
                log::error!("set_audit_note error: {e:?}");
                Err(AuditNoteError::Db)
            }
        }
    }

    /// The note of a device's most recent conn row. Test-only (integration tests lack a read API yet).
    #[cfg(any(test, feature = "test-util"))]
    pub async fn audit_conn_note_for_test(&self, remote: &str) -> Option<String> {
        self.db.audit_conn_rows(remote).await.last()?.note.clone()
    }

    /// Opaque ref hbbs forwards to the controlled device `target`; it identifies `user` without exposing a token.
    pub async fn mint_audit_conn_ref(&self, user: &UserId, target: &str) -> Option<String> {
        let conn_ref = uuid::Uuid::new_v4().simple().to_string();
        self.db.insert_audit_conn_ref(&conn_ref, user, target).await?;
        Some(conn_ref)
    }

    pub async fn resolve_audit_conn_ref(&self, conn_ref: &str, target: &str) -> Option<UserId> {
        self.db.resolve_audit_conn_ref(conn_ref, target).await
    }

    /// Audit records are stored only from the device they name (spec §12.1); others are answered and dropped.
    async fn from_registered_device(&self, kind: &str, id: &str, uuid: &str) -> bool {
        let registered = self.db.is_registered_device(id, uuid).await;
        if !registered {
            log::warn!("audit {kind}: dropped a record for {id:?}: no registered device with that uuid");
        }
        registered
    }

    /// Admin read API (audit-api-spec.md §9).
    pub async fn list_audit_conns(&self, q: &utils::AuditQuery) -> Option<(i64, Vec<utils::AuditConnLog>)> {
        self.db.list_audit_conns(q).await
    }

    pub async fn list_audit_files(&self, q: &utils::AuditQuery) -> Option<(i64, Vec<utils::AuditFileLog>)> {
        self.db.list_audit_files(q).await
    }

    pub async fn list_audit_alarms(&self, q: &utils::AuditQuery) -> Option<(i64, Vec<utils::AuditAlarmLog>)> {
        self.db.list_audit_alarms(q).await
    }
}

/// The client's `info` is a JSON string; store it as an object so readers need not decode twice.
fn audit_info(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_owned()))
}

/// How long a started OIDC login waits for the browser sign-in.
pub const OIDC_LOGIN_TTL_SECS: u64 = 180;

/// How long the one-time result of a finished login can be redeemed.
pub const OIDC_RESULT_TTL_SECS: u64 = 60;

/// Heartbeats come every 3–15 s; a row this young may have been opened after the heartbeat's snapshot.
pub const AUDIT_CONN_HEARTBEAT_GRACE_SECS: i64 = 30;

/// Which client started a login, from its `returnTo` (checked when the login started).
fn login_client(return_to: &str) -> &'static str {
    if return_to.starts_with("http://127.") || return_to.starts_with("http://[::1]") {
        "native"
    } else if return_to.ends_with("/oidc-callback.html") {
        "web"
    } else {
        "console"
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
            .get_user_for_oauth2("admin", "admin", Some("admin@example.org"))
            .await
            .unwrap();
        state.set_admin("admin@example.org", true).await.unwrap();
        state
    }

    /// Two instances on one database, as two api-server pods.
    async fn two_pods() -> (ApiState, ApiState) {
        let url = crate::testing::fresh_database_url().await;
        let a = ApiState::new_with_db(&url).await;
        let b = ApiState::new_with_db(&url).await;
        a.db.get_user_for_oauth2("admin", "admin", Some("admin@example.org")).await.unwrap();
        a.set_admin("admin@example.org", true).await.unwrap();
        (a, b)
    }

    /// An IdP that accepts any code and says the user is its `sub`.
    struct StubIdp(&'static str);

    impl oauth2::oauth_provider::OAuthProvider for StubIdp {
        fn get_redirect_url(&self, _callback_url: &str, login: &oauth2::pkce::ProviderLogin) -> String {
            format!("https://idp.example.com/authorize?state={}", login.state)
        }
        fn exchange_code(
            &self,
            _code: &str,
            _callback_url: &str,
            _login: &oauth2::pkce::ProviderLogin,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<oauth2::oauth_provider::OAuthResponse, oauth2::errors::Oauth2Error>> + Send + Sync>> {
            let sub = self.0.to_string();
            Box::pin(async move {
                Ok(oauth2::oauth_provider::OAuthResponse { access_token: "at".into(), subject: sub.clone(), name: Some(sub), email: None })
            })
        }
        fn get_provider_type(&self) -> oauth2::Provider {
            oauth2::Provider::Dex
        }
    }

    /// A login started on `pod` as `oidc_auth` would; its verifier is "v".
    async fn start_login(pod: &ApiState, code: &str) {
        let login = OidcState {
            id: "601".into(),
            uuid: "dev".into(),
            callback_url: Some("https://rustdesk.example.com/api/oidc/callback".into()),
            return_to: "/ui/login".into(),
            code_challenge: oauth2::pkce::s256_challenge("v"),
            provider_login: Some(oauth2::pkce::ProviderLogin::new(code)),
            provider: Some(Arc::new(StubIdp("admin"))),
            ..Default::default()
        };
        pod.insert_oidc_session(code.into(), login).await.unwrap();
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

    async fn admin_id(state: &ApiState) -> UserId {
        state.db.find_user_by_name("admin").await.1.unwrap().0
    }

    fn book(ab: &str) -> AddressBook {
        AddressBook { ab: ab.to_string(), ..Default::default() }
    }

    #[tokio::test]
    async fn address_book_set_and_get() {
        let state = test_state().await;
        let user = admin_id(&state).await;
        state.set_user_address_book(user.clone(), book("test data")).await.unwrap();
        assert_eq!(state.get_user_address_book(user).await.unwrap().ab, "test data");
    }

    #[tokio::test]
    async fn address_book_writes_are_seen_by_another_pod_at_once() {
        let (a, b) = two_pods().await;
        let user = admin_id(&a).await;
        a.set_user_address_book(user.clone(), book("v1")).await.unwrap();
        assert_eq!(b.get_user_address_book(user.clone()).await.unwrap().ab, "v1", "the first write is saved");
        assert_eq!(a.get_user_address_book(user.clone()).await.unwrap().ab, "v1");
        b.set_user_address_book(user.clone(), book("v2")).await.unwrap();
        assert_eq!(a.get_user_address_book(user).await.unwrap().ab, "v2");
    }

    #[tokio::test]
    async fn address_book_write_failure_is_reported() {
        let state = test_state().await;
        assert!(state.set_user_address_book(vec![1, 2, 3], book("x")).await.is_none());
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
            sub: None,
            name: None,
            email: None,
            ..Default::default()
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
            sub: None,
            name: None,
            email: None,
            ..Default::default()
        };
        state
            .insert_oidc_session("dup".to_string(), oidc.clone())
            .await;
        let result = state
            .insert_oidc_session("dup".to_string(), oidc)
            .await;
        assert!(result.is_none());
    }

    /// A login whose provider leg finished for `sub`, waiting for `verifier` to redeem `result`.
    async fn finished_login(state: &ApiState, sub: &str, verifier: &str, result: &str) {
        let login = OidcState {
            id: "601".into(),
            uuid: "dev".into(),
            code_challenge: oauth2::pkce::s256_challenge(verifier),
            ..Default::default()
        };
        state.insert_oidc_session(result.into(), login).await.unwrap();
        state.db.finish_oidc_login(result, sub, None, None, result).await.unwrap();
    }

    fn token_request(result: &str, verifier: &str) -> utils::OidcTokenRequest {
        let uuid = base64::prelude::BASE64_STANDARD.encode("dev");
        utils::OidcTokenRequest { result: result.into(), code_verifier: verifier.into(), id: "601".into(), uuid }
    }

    #[tokio::test]
    async fn oidc_redeem_issues_a_session_once() {
        let state = test_state().await;
        finished_login(&state, "admin", "v", "r1").await;
        let (_, username, _) = state.oidc_redeem(&token_request("r1", "v")).await.unwrap();
        assert_eq!(username, "admin");
        assert!(state.oidc_redeem(&token_request("r1", "v")).await.is_none());
    }

    #[tokio::test]
    async fn oidc_redeem_gives_an_inactive_user_no_session() {
        let state = test_state().await;
        finished_login(&state, "nobody", "v", "r2").await;
        assert!(state.oidc_redeem(&token_request("r2", "v")).await.is_none());
    }

    #[tokio::test]
    async fn oidc_redeem_unknown_result() {
        let state = test_state().await;
        assert!(state.oidc_redeem(&token_request("missing", "v")).await.is_none());
    }

    #[tokio::test]
    async fn oidc_login_started_on_one_pod_finishes_on_another() {
        let (a, b) = two_pods().await;
        start_login(&a, "c").await;
        assert!(b.test_set_oidc_provider("c", Arc::new(StubIdp("admin"))).await);
        let (return_to, result) = b.oidc_complete_callback("c", "idp-code").await.unwrap();
        assert_eq!(return_to, "/ui/login");
        let (_, username, _) = a.oidc_redeem(&token_request(&result.unwrap(), "v")).await.unwrap();
        assert_eq!(username, "admin");
    }

    #[tokio::test]
    async fn oidc_callback_runs_once_across_pods() {
        let (a, b) = two_pods().await;
        start_login(&a, "c").await;
        for pod in [&a, &b] {
            assert!(pod.test_set_oidc_provider("c", Arc::new(StubIdp("admin"))).await);
        }
        let (ra, rb) = tokio::join!(a.oidc_complete_callback("c", "x"), b.oidc_complete_callback("c", "x"));
        assert_eq!(ra.is_some() as u8 + rb.is_some() as u8, 1, "{ra:?} {rb:?}");
    }

    #[tokio::test]
    async fn oidc_result_is_redeemed_once_across_pods() {
        let (a, b) = two_pods().await;
        finished_login(&a, "admin", "v", "r").await;
        let req = token_request("r", "v");
        let (ra, rb) = tokio::join!(a.oidc_redeem(&req), b.oidc_redeem(&req));
        assert_eq!(ra.is_some() as u8 + rb.is_some() as u8, 1);
    }

    #[tokio::test]
    async fn oidc_idp_error_on_another_pod_ends_the_login() {
        let (a, b) = two_pods().await;
        start_login(&a, "c").await;
        assert_eq!(b.oidc_fail_callback("c", "access_denied").await, Some("/ui/login".to_string()));
        assert!(a.get_oidc_session("c".into()).await.is_none());
        assert!(a.oidc_fail_callback("c", "access_denied").await.is_none());
    }

    #[tokio::test]
    async fn oidc_complete_callback_without_provider_fails_and_drops_the_login() {
        let state = test_state().await;
        let login = OidcState { return_to: "/ui/login".into(), ..Default::default() };
        state.insert_oidc_session("c".into(), login).await;
        assert_eq!(state.oidc_complete_callback("c", "code").await, Some(("/ui/login".to_string(), None)));
        assert!(state.get_oidc_session("c".into()).await.is_none());
        assert!(state.oidc_complete_callback("missing", "code").await.is_none());
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

    #[tokio::test]
    async fn strategy_wrappers() {
        let state = test_state().await;
        let guid = utils::policy::DEFAULT_STRATEGY_GUID;
        assert_eq!(state.list_strategies().await.unwrap().len(), 1);
        let opts: BTreeMap<String, String> = [("enable-audio".to_string(), "N".to_string())].into();
        let m1 = state.set_strategy_options(guid, &opts).await.unwrap();
        assert!(state.bump_strategy(guid).await.unwrap() > m1);
        assert_eq!(state.get_strategy(guid).await.unwrap().1, opts);
    }

    /// A test state where the devices the audit tests post for are registered (base64 uuid "uuid").
    async fn audit_state() -> ApiState {
        let state = test_state().await;
        for id in ["dev", "dev1", "dev2", "dev3", "dev4", "dev5"] {
            state.test_register_device(id, "dXVpZA==").await;
        }
        state
    }

    fn conn_record(json: &str) -> utils::AuditConnRequest {
        serde_json::from_str(json).unwrap()
    }

    // Bodies as sent by upstream clients (docs/audit-api-spec.md §3); every record has its own nonce.
    fn new_record(conn_id: i64, nonce: &str) -> utils::AuditConnRequest {
        conn_record(&format!(
            r#"{{"action":"new","ip":"10.0.0.1","id":"dev1","uuid":"dXVpZA==","conn_id":{conn_id},"session_id":0,"nonce":"{nonce}"}}"#
        ))
    }

    fn close_record(id: &str, uuid: &str, conn_id: i64, nonce: &str) -> utils::AuditConnRequest {
        conn_record(&format!(
            r#"{{"action":"close","id":"{id}","uuid":"{uuid}","conn_id":{conn_id},"session_id":0,"nonce":"{nonce}"}}"#
        ))
    }

    #[tokio::test]
    async fn audit_conn_close_matches_the_connection_key() {
        let state = audit_state().await;
        state.audit_conn(&new_record(17, "n-new")).await.unwrap();
        state.audit_conn(&close_record("dev1", "dXVpZA==", 17, "n-close")).await.unwrap();
        let rows = state.db.audit_conn_rows("dev1").await;
        assert_eq!(rows.len(), 1);
        assert!(rows[0].end_time.is_some(), "close must set end_time");
    }

    #[tokio::test]
    async fn heartbeat_ends_open_rows_missing_from_conns() {
        let state = audit_state().await;
        state.audit_conn(&new_record(1, "n-hb1")).await.unwrap();
        state.audit_conn(&new_record(2, "n-hb2")).await.unwrap();
        state.db.end_audit_conns_not_alive("dev1", "dXVpZA==", &[2], 0).await.unwrap();
        let rows = state.db.audit_conn_rows("dev1").await;
        let ended: Vec<bool> = rows.iter().map(|r| r.end_time.is_some()).collect();
        assert_eq!(ended, vec![true, false], "conn 1 is gone from the heartbeat, conn 2 is alive");
    }

    #[tokio::test]
    async fn heartbeat_without_conns_ends_every_open_row_of_the_device_only() {
        let state = audit_state().await;
        state.audit_conn(&new_record(3, "n-hb3")).await.unwrap();
        state.audit_conn(&conn_record(
            r#"{"action":"new","id":"dev2","uuid":"dXVpZA==","conn_id":3,"session_id":0,"nonce":"n-hb4"}"#,
        )).await.unwrap();
        state.db.end_audit_conns_not_alive("dev1", "dXVpZA==", &[], 0).await.unwrap();
        assert!(state.db.audit_conn_rows("dev1").await[0].end_time.is_some());
        assert!(state.db.audit_conn_rows("dev2").await[0].end_time.is_none(), "other devices are untouched");
    }

    #[tokio::test]
    async fn heartbeat_spares_rows_younger_than_the_grace_period() {
        let state = audit_state().await;
        state.audit_conn(&new_record(5, "n-hb5")).await.unwrap();
        state.db.end_audit_conns_not_alive("dev1", "dXVpZA==", &[], AUDIT_CONN_HEARTBEAT_GRACE_SECS).await.unwrap();
        assert!(state.db.audit_conn_rows("dev1").await[0].end_time.is_none());
    }

    #[tokio::test]
    async fn audit_conn_close_ignores_other_connections() {
        let state = audit_state().await;
        state.audit_conn(&new_record(17, "n-new")).await.unwrap();
        state.audit_conn(&close_record("dev1", "dXVpZA==", 18, "c1")).await.unwrap();
        state.audit_conn(&close_record("dev1", "b3RoZXI=", 17, "c2")).await.unwrap();
        state.audit_conn(&close_record("dev2", "dXVpZA==", 17, "c3")).await.unwrap();
        let rows = state.db.audit_conn_rows("dev1").await;
        assert!(rows[0].end_time.is_none());
    }

    #[tokio::test]
    async fn audit_conn_new_retry_is_stored_once() {
        let state = audit_state().await;
        state.audit_conn(&new_record(17, "same")).await.unwrap();
        state.audit_conn(&new_record(17, "same")).await.unwrap();
        assert_eq!(state.db.audit_conn_rows("dev1").await.len(), 1);
    }

    #[tokio::test]
    async fn audit_conn_reused_conn_id_ends_the_stale_row() {
        // conn_id restarts with the RustDesk process; a still-open row with the same key is dead.
        let state = audit_state().await;
        state.audit_conn(&new_record(17, "first")).await.unwrap();
        state.audit_conn(&new_record(17, "second")).await.unwrap();
        let rows = state.db.audit_conn_rows("dev1").await;
        assert_eq!(rows.len(), 2);
        assert!(rows[0].end_time.is_some(), "older row ended");
        assert!(rows[1].end_time.is_none(), "current row open");
        state.audit_conn(&close_record("dev1", "dXVpZA==", 17, "c")).await.unwrap();
        assert!(state.db.audit_conn_rows("dev1").await[1].end_time.is_some());
    }

    #[tokio::test]
    async fn audit_conn_new_has_no_type_until_authorized() {
        let state = audit_state().await;
        state.audit_conn(&new_record(17, "n")).await.unwrap();
        assert_eq!(state.db.audit_conn_rows("dev1").await[0].conn_type, None);
    }

    #[tokio::test]
    async fn audit_conn_authorized_records_the_controller() {
        let state = audit_state().await;
        state.audit_conn(&new_record(17, "n")).await.unwrap();
        state
            .audit_conn(&conn_record(
                r#"{"peer":["987654321","alice-laptop"],"type":1,"primary_auth":2,"two_factor":1,"id":"dev1","uuid":"dXVpZA==","conn_id":17,"session_id":18446744073709551615,"nonce":"a"}"#,
            ))
            .await
            .unwrap();
        let rows = state.db.audit_conn_rows("dev1").await;
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.conn_type, Some(1));
        assert_eq!(row.local.as_deref(), Some(&b"987654321"[..]));
        let info: serde_json::Value = serde_json::from_str(&row.info).unwrap();
        assert_eq!(info["peer_name"], "alice-laptop");
        assert_eq!(info["primary_auth"], 2);
        assert_eq!(info["two_factor"], 1);
        assert_eq!(info["session_id"].as_u64(), Some(u64::MAX));
        assert_eq!(info["ip"], "10.0.0.1", "fields from new are kept");
    }

    #[tokio::test]
    async fn audit_conn_authorized_retry_on_another_pod_adds_no_row() {
        let (a, b) = two_pods().await;
        a.test_register_device("dev1", "dXVpZA==").await;
        let authorized = conn_record(
            r#"{"peer":["987654321","alice-laptop"],"type":0,"id":"dev1","uuid":"dXVpZA==","conn_id":5,"session_id":7,"nonce":"auth-5"}"#,
        );
        a.audit_conn(&authorized).await.unwrap();
        a.audit_conn(&close_record("dev1", "dXVpZA==", 5, "close-5")).await.unwrap();
        b.audit_conn(&authorized).await.unwrap();
        assert_eq!(a.db.audit_conn_rows("dev1").await.len(), 1);
    }

    #[tokio::test]
    async fn audit_records_taken_by_two_pods_at_once_are_stored_once() {
        let (a, b) = two_pods().await;
        a.test_register_device("dev1", "dXVpZA==").await;
        let new = new_record(17, "n-race");
        assert_eq!(tokio::join!(a.audit_conn(&new), b.audit_conn(&new)), (Some(()), Some(())));
        let rows = a.db.audit_conn_rows("dev1").await;
        assert_eq!(rows.len(), 1);
        assert!(rows[0].end_time.is_none(), "the stored row stays open");
        let file: utils::AuditFileRequest = serde_json::from_str(
            r#"{"id":"dev1","uuid":"dXVpZA==","peer_id":"v","conn_id":17,"type":1,"path":"/tmp","is_file":true,"info":"{}","nonce":"f-race"}"#,
        ).unwrap();
        assert_eq!(tokio::join!(a.audit_file(&file), b.audit_file(&file)), (Some(()), Some(())));
        let alarm: utils::AuditAlarmRequest = serde_json::from_str(
            r#"{"id":"dev1","uuid":"dXVpZA==","typ":1,"info":"{}","conn_id":17,"nonce":"a-race"}"#,
        ).unwrap();
        assert_eq!(tokio::join!(a.audit_alarm(&alarm), b.audit_alarm(&alarm)), (Some(()), Some(())));
        assert_eq!(a.db.count_nonce_rows_for_test("audit_file", "f-race").await, 1);
        assert_eq!(a.db.count_nonce_rows_for_test("audit_alarm", "a-race").await, 1);
    }

    #[tokio::test]
    async fn audit_conn_authorized_without_new_creates_the_row() {
        let state = audit_state().await;
        state
            .audit_conn(&conn_record(
                r#"{"peer":["987654321","alice-laptop"],"type":0,"id":"dev1","uuid":"dXVpZA==","conn_id":5,"session_id":7,"nonce":"a"}"#,
            ))
            .await
            .unwrap();
        let rows = state.db.audit_conn_rows("dev1").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].conn_type, Some(0));
        state.audit_conn(&close_record("dev1", "dXVpZA==", 5, "c")).await.unwrap();
        assert!(state.db.audit_conn_rows("dev1").await[0].end_time.is_some());
    }

    #[tokio::test]
    async fn audit_menu_note_without_session_id_is_ignored() {
        let state = audit_state().await;
        state.audit_conn(&new_record(5, "n-note2")).await.unwrap();

        // session_id 0 is the "new" row's own default, not a real session; applying the
        // note here would hit that not-yet-authorized row instead of the intended one.
        state.audit_conn(&conn_record(r#"{"id":"dev1","session_id":0,"note":"hi"}"#)).await.unwrap();
        assert_eq!(state.db.audit_conn_rows("dev1").await[0].note, None);

        // authorized record carries the real session id
        state.audit_conn(&conn_record(
            r#"{"peer":["v1","Viewer"],"type":0,"id":"dev1","uuid":"dXVpZA==","conn_id":5,"session_id":18446744073709551615,"nonce":"a-note2"}"#,
        )).await.unwrap();
        state.audit_conn(&conn_record(r#"{"id":"dev1","session_id":18446744073709551615,"note":"hello"}"#)).await.unwrap();
        assert_eq!(state.db.audit_conn_rows("dev1").await[0].note.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn audit_conn_unknown_shapes_are_accepted() {
        let state = audit_state().await;
        assert!(state.audit_conn(&conn_record(r#"{"id":"dev1","session_id":1,"note":"hi"}"#)).await.is_some());
        assert!(state.audit_conn(&conn_record(r#"{"action":"bogus","id":"dev1"}"#)).await.is_some());
    }

    #[tokio::test]
    async fn audit_conn_ref_resolves_to_its_user() {
        let state = audit_state().await;
        let (user, _, _) = state.db.get_user_for_oauth2("bob", "bob", Some("bob@example.org")).await.unwrap();
        let r = state.mint_audit_conn_ref(&user, "dev1").await.unwrap();
        assert_eq!(r.len(), 32);
        assert_eq!(state.resolve_audit_conn_ref(&r, "dev1").await, Some(user));
        assert_eq!(state.resolve_audit_conn_ref("unknown", "dev1").await, None);
    }

    #[tokio::test]
    async fn audit_conn_new_with_ref_records_the_viewer_user() {
        let state = audit_state().await;
        let (user, _, _) = state.db.get_user_for_oauth2("carol", "carol", Some("carol@example.org")).await.unwrap();
        let r = state.mint_audit_conn_ref(&user, "dev1").await.unwrap();
        let new = conn_record(&format!(
            r#"{{"action":"new","id":"dev1","uuid":"dXVpZA==","conn_id":7,"nonce":"n-ref","conn_audit_ref":"{r}"}}"#
        ));
        state.audit_conn(&new).await.unwrap();
        assert_eq!(state.db.audit_conn_user("dev1", "dXVpZA==", 7).await, Some(user));
    }

    /// Logs `viewer` in as a new user (`name`) on machine `host`, then records new + authorized for a session from it.
    async fn session_from_viewer(state: &ApiState, name: &str, viewer: &str, host: Option<&str>, conn_id: i64) -> Vec<u8> {
        let (user, _, _) = state.db.get_user_for_oauth2(name, name, Some(&format!("{name}@example.org"))).await.unwrap();
        if let Some(host) = host {
            state.db.upsert_viewer_device(viewer, "vu", host, "Windows", "198.51.100.7", &user).await.unwrap();
        }
        let r = state.mint_audit_conn_ref(&user, "dev1").await.unwrap();
        state.audit_conn(&conn_record(&format!(
            r#"{{"action":"new","ip":"10.0.0.1","id":"dev1","uuid":"dXVpZA==","conn_id":{conn_id},"nonce":"n{conn_id}","conn_audit_ref":"{r}"}}"#
        ))).await.unwrap();
        state.audit_conn(&conn_record(&format!(
            r#"{{"peer":["{viewer}","Alice"],"type":0,"id":"dev1","uuid":"dXVpZA==","conn_id":{conn_id},"session_id":1,"nonce":"a{conn_id}"}}"#
        ))).await.unwrap();
        user
    }

    fn conn_info(rows: &[crate::database::AuditConnRow], conn_id: i64) -> serde_json::Value {
        rows.iter()
            .map(|r| serde_json::from_str::<serde_json::Value>(&r.info).unwrap())
            .find(|i| i["conn_id"] == conn_id)
            .unwrap()
    }

    #[tokio::test]
    async fn audit_conn_authorized_records_the_viewer_machine() {
        let state = audit_state().await;
        session_from_viewer(&state, "alice", "111222333", Some("LAPTOP-FIN-042"), 1).await;
        let info = conn_info(&state.db.audit_conn_rows("dev1").await, 1);
        assert_eq!(info["peer_hostname"], "LAPTOP-FIN-042");
        assert_eq!(info["peer_os"], "Windows");
        assert_eq!(info["peer_login_ip"], "198.51.100.7");
        assert_eq!(info["ip"], "10.0.0.1", "the network address is kept");
    }

    #[tokio::test]
    async fn audit_conn_viewer_machine_needs_a_login_by_the_same_user() {
        let state = audit_state().await;
        let (other, _, _) = state.db.get_user_for_oauth2("mallory", "mallory", Some("mallory@example.org")).await.unwrap();
        state.db.upsert_viewer_device("111222333", "vu", "OTHER-PC", "Linux", "", &other).await.unwrap();
        session_from_viewer(&state, "bob", "111222333", None, 2).await;
        let info = conn_info(&state.db.audit_conn_rows("dev1").await, 2);
        assert!(info.get("peer_hostname").is_none(), "{info}");
        assert!(info.get("peer_os").is_none(), "{info}");
    }

    #[tokio::test]
    async fn viewer_login_with_another_users_id_and_uuid_does_not_take_the_row_over() {
        let state = audit_state().await;
        let (victim, _, _) = state.db.get_user_for_oauth2("erin", "erin", Some("erin@example.org")).await.unwrap();
        let (other, _, _) = state.db.get_user_for_oauth2("frank", "frank", Some("frank@example.org")).await.unwrap();
        state.db.upsert_viewer_device("555666777", "vu", "ERIN-PC", "Windows", "", &victim).await.unwrap();
        state.db.upsert_viewer_device("555666777", "vu", "FAKE", "Linux", "", &other).await.unwrap();
        assert_eq!(state.db.viewer_machine("555666777", &victim).await.map(|m| m.0), Some("ERIN-PC".to_string()));
        assert_eq!(state.db.viewer_machine("555666777", &other).await.map(|m| m.0), Some("FAKE".to_string()));
    }

    #[tokio::test]
    async fn audit_conn_without_user_records_no_viewer_machine() {
        let state = audit_state().await;
        let (user, _, _) = state.db.get_user_for_oauth2("dave", "dave", Some("dave@example.org")).await.unwrap();
        state.db.upsert_viewer_device("987654321", "vu", "DAVE-PC", "macOS", "", &user).await.unwrap();
        state.audit_conn(&new_record(3, "n-nouser")).await.unwrap();
        state.audit_conn(&conn_record(
            r#"{"peer":["987654321","Dave"],"type":0,"id":"dev1","uuid":"dXVpZA==","conn_id":3,"session_id":1,"nonce":"a-nouser"}"#,
        )).await.unwrap();
        let info = conn_info(&state.db.audit_conn_rows("dev1").await, 3);
        assert!(info.get("peer_hostname").is_none(), "{info}");
    }

    #[tokio::test]
    async fn audit_conn_new_with_unknown_ref_is_stored_without_user() {
        let state = audit_state().await;
        let new = conn_record(r#"{"action":"new","id":"dev2","uuid":"dXVpZA==","conn_id":1,"nonce":"n-unk","conn_audit_ref":"nope"}"#);
        state.audit_conn(&new).await.unwrap();
        assert_eq!(state.db.audit_conn_rows("dev2").await.len(), 1);
        assert_eq!(state.db.audit_conn_user("dev2", "dXVpZA==", 1).await, None);
    }

    #[tokio::test]
    async fn audit_menu_note_lands_on_the_session_row() {
        let state = audit_state().await;
        state.audit_conn(&new_record(5, "n-note")).await.unwrap();
        // authorized record carries the session id
        state.audit_conn(&conn_record(
            r#"{"peer":["v1","Viewer"],"type":0,"id":"dev","uuid":"dXVpZA==","conn_id":5,"session_id":18446744073709551615,"nonce":"a-note"}"#,
        )).await.unwrap();
        state.audit_conn(&conn_record(r#"{"id":"dev@srv","session_id":18446744073709551615,"note":"hello"}"#)).await.unwrap();
        assert_eq!(state.db.audit_conn_rows("dev").await[0].note.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn find_active_audit_conn_is_scoped_to_the_row_owner() {
        let state = audit_state().await;
        let (owner, _, _) = state.db.get_user_for_oauth2("erin", "erin", Some("erin@example.org")).await.unwrap();
        let (other, _, _) = state.db.get_user_for_oauth2("frank", "frank", Some("frank@example.org")).await.unwrap();
        let r = state.mint_audit_conn_ref(&owner, "dev4").await.unwrap();
        state.audit_conn(&conn_record(&format!(
            r#"{{"action":"new","id":"dev4","uuid":"dXVpZA==","conn_id":9,"session_id":42,"nonce":"n-active","conn_audit_ref":"{r}"}}"#
        ))).await.unwrap();
        state.audit_conn(&conn_record(
            r#"{"peer":["v1","Viewer"],"type":0,"id":"dev4","uuid":"dXVpZA==","conn_id":9,"session_id":42,"nonce":"a-active"}"#,
        )).await.unwrap();

        assert!(state.find_active_audit_conn("dev4", "42", "0", &owner).await.is_some());
        assert_eq!(state.find_active_audit_conn("dev4", "42", "0", &other).await, None);

        // unattributed row: open to any logged-in caller
        state.audit_conn(&new_record(10, "n-unattrib")).await.unwrap();
        state.audit_conn(&conn_record(
            r#"{"peer":["v1","Viewer"],"type":0,"id":"dev1","uuid":"dXVpZA==","conn_id":10,"session_id":0,"nonce":"a-unattrib"}"#,
        )).await.unwrap();
        assert!(state.find_active_audit_conn("dev1", "0", "0", &other).await.is_some());
    }

    #[tokio::test]
    async fn set_audit_note_enforces_ownership() {
        let state = audit_state().await;
        let (owner, _, _) = state.db.get_user_for_oauth2("gina", "gina", Some("gina@example.org")).await.unwrap();
        let (other, _, _) = state.db.get_user_for_oauth2("hank", "hank", Some("hank@example.org")).await.unwrap();
        let r = state.mint_audit_conn_ref(&owner, "dev5").await.unwrap();
        state.audit_conn(&conn_record(&format!(
            r#"{{"action":"new","id":"dev5","uuid":"dXVpZA==","conn_id":11,"session_id":1,"nonce":"n-set","conn_audit_ref":"{r}"}}"#
        ))).await.unwrap();
        let guid = state.find_active_audit_conn("dev5", "1", "0", &owner).await;
        assert_eq!(guid, None, "row has no type until authorized");
        state.audit_conn(&conn_record(
            r#"{"peer":["v1","Viewer"],"type":0,"id":"dev5","uuid":"dXVpZA==","conn_id":11,"session_id":1,"nonce":"a-set"}"#,
        )).await.unwrap();
        let guid = state.find_active_audit_conn("dev5", "1", "0", &owner).await.unwrap();

        assert_eq!(state.set_audit_note(&guid, "owner note", &owner).await, Ok(()));
        assert_eq!(state.db.audit_conn_rows("dev5").await[0].note.as_deref(), Some("owner note"));

        assert_eq!(state.set_audit_note(&guid, "nope", &other).await, Err(AuditNoteError::NotFound));
        assert_eq!(
            state.set_audit_note("00000000-0000-0000-0000-000000000000", "n", &owner).await,
            Err(AuditNoteError::NotFound)
        );
        assert_eq!(state.set_audit_note("xyz", "n", &owner).await, Err(AuditNoteError::BadGuid));
    }

    #[tokio::test]
    async fn audit_file_is_stored_against_the_device_and_attributed() {
        let state = audit_state().await;
        let (user, _, _) = state.db.get_user_for_oauth2("dave", "dave", Some("dave@example.org")).await.unwrap();
        let r = state.mint_audit_conn_ref(&user, "dev3").await.unwrap();
        state.audit_conn(&conn_record(&format!(
            r#"{{"action":"new","id":"dev3","uuid":"dXVpZA==","conn_id":2,"nonce":"n3","conn_audit_ref":"{r}"}}"#
        ))).await.unwrap();
        let file: utils::AuditFileRequest = serde_json::from_str(
            r#"{"id":"dev3","uuid":"dXVpZA==","peer_id":"viewer9","conn_id":2,"type":1,"path":"/tmp","is_file":false,
                "info":"{\"ip\":\"203.0.113.5\",\"name\":\"v\",\"num\":1,\"files\":[[\"a.txt\",3]]}","nonce":"f1"}"#,
        ).unwrap();
        state.audit_file(&file).await.unwrap();
        let row = state.db.audit_file_row_for_test("f1").await;
        assert_eq!(row.remote, b"dev3".to_vec());
        assert_eq!(row.local, Some(b"viewer9".to_vec()));
        assert_eq!(row.user, Some(user));
        let info: serde_json::Value = serde_json::from_str(&row.info).unwrap();
        assert_eq!(info["info"]["num"], 1);
    }

    #[tokio::test]
    async fn audit_alarm_without_ref_is_attributed_from_the_connection() {
        let state = audit_state().await;
        let (user, _, _) = state.db.get_user_for_oauth2("erin", "erin", Some("erin@example.org")).await.unwrap();
        let r = state.mint_audit_conn_ref(&user, "dev4").await.unwrap();
        state.audit_conn(&conn_record(&format!(
            r#"{{"action":"new","id":"dev4","uuid":"dXVpZA==","conn_id":3,"nonce":"n4","conn_audit_ref":"{r}"}}"#
        ))).await.unwrap();
        let alarm: utils::AuditAlarmRequest = serde_json::from_str(
            r#"{"id":"dev4","uuid":"dXVpZA==","typ":1,"info":"{\"ip\":\"203.0.113.5\",\"id\":\"1\",\"name\":\"n\"}","conn_id":3,"nonce":"a1"}"#,
        ).unwrap();
        state.audit_alarm(&alarm).await.unwrap();
        let row = state.db.audit_alarm_row_for_test("a1").await;
        assert_eq!(row.user, Some(user));
        let info: serde_json::Value = serde_json::from_str(&row.info).unwrap();
        assert_eq!(info["info"]["id"], "1");
    }

    #[tokio::test]
    async fn audit_alarm_with_ref_is_attributed_from_the_ref() {
        let state = audit_state().await;
        let (user, _, _) = state.db.get_user_for_oauth2("frank", "frank", Some("frank@example.org")).await.unwrap();
        let r = state.mint_audit_conn_ref(&user, "dev5").await.unwrap();
        let alarm: utils::AuditAlarmRequest = serde_json::from_str(&format!(
            r#"{{"id":"dev5","uuid":"dXVpZA==","typ":0,"info":"{{\"ip\":\"203.0.113.5\"}}","conn_id":9,"nonce":"a2","conn_audit_ref":"{r}"}}"#
        )).unwrap();
        state.audit_alarm(&alarm).await.unwrap();
        let row = state.db.audit_alarm_row_for_test("a2").await;
        assert_eq!(row.user, Some(user));
    }

    #[tokio::test]
    async fn audit_records_from_unregistered_devices_are_dropped() {
        let state = audit_state().await;
        // Wrong uuid for a registered ID, an unknown ID, a uuid that is not base64.
        for (id, uuid) in [("dev1", "b3RoZXI="), ("ghost", "dXVpZA=="), ("dev1", "not base64")] {
            let new = conn_record(&format!(r#"{{"action":"new","id":"{id}","uuid":"{uuid}","conn_id":1,"nonce":"n-{id}-{uuid}"}}"#));
            assert!(state.audit_conn(&new).await.is_some(), "answered as stored");
            let file: utils::AuditFileRequest = serde_json::from_str(&format!(
                r#"{{"id":"{id}","uuid":"{uuid}","peer_id":"v","conn_id":1,"type":1,"path":"/","is_file":true,"info":"{{}}","nonce":"f-{id}-{uuid}"}}"#
            )).unwrap();
            assert!(state.audit_file(&file).await.is_some());
            let alarm: utils::AuditAlarmRequest = serde_json::from_str(&format!(
                r#"{{"id":"{id}","uuid":"{uuid}","typ":1,"info":"{{}}","conn_id":1,"nonce":"a-{id}-{uuid}"}}"#
            )).unwrap();
            assert!(state.audit_alarm(&alarm).await.is_some());
        }
        assert!(state.db.audit_conn_rows("dev1").await.is_empty());
        assert!(state.db.audit_conn_rows("ghost").await.is_empty());
        assert!(!state.db.find_audit_file_by_nonce("f-dev1-b3RoZXI=").await);
        assert!(!state.db.find_audit_alarm_by_nonce("a-ghost-dXVpZA==").await);
    }

    #[tokio::test]
    async fn audit_ref_attributes_only_records_of_its_target() {
        let state = audit_state().await;
        let (user, _, _) = state.db.get_user_for_oauth2("ivy", "ivy", Some("ivy@example.org")).await.unwrap();
        let r = state.mint_audit_conn_ref(&user, "dev1").await.unwrap();
        state.audit_conn(&conn_record(&format!(
            r#"{{"action":"new","id":"dev2","uuid":"dXVpZA==","conn_id":1,"nonce":"n-other","conn_audit_ref":"{r}"}}"#
        ))).await.unwrap();
        assert_eq!(state.db.audit_conn_rows("dev2").await.len(), 1, "the record is kept");
        assert_eq!(state.db.audit_conn_user("dev2", "dXVpZA==", 1).await, None);
        let alarm: utils::AuditAlarmRequest = serde_json::from_str(&format!(
            r#"{{"id":"dev2","uuid":"dXVpZA==","typ":0,"info":"{{}}","conn_id":9,"nonce":"a-other","conn_audit_ref":"{r}"}}"#
        )).unwrap();
        state.audit_alarm(&alarm).await.unwrap();
        assert_eq!(state.db.audit_alarm_row_for_test("a-other").await.user, None);
    }

    #[tokio::test]
    async fn viewer_login_bounds_hostname_and_os() {
        let state = test_state().await;
        let (user, _, _) = state.db.get_user_for_oauth2("admin", "admin", None).await.unwrap();
        let login = OidcState {
            id: "601".into(),
            uuid: "u".into(),
            device_type: "client".into(),
            device_name: "h".repeat(300),
            device_os: "é".repeat(300),
            ..Default::default()
        };
        state.record_viewer_login(&login, &user).await;
        let row = &state.list_viewer_devices(0, 10).await.unwrap().1[0];
        assert_eq!((row.hostname.chars().count(), row.os.chars().count()), (255, 255));
    }

    #[tokio::test]
    async fn viewer_login_skips_oversized_or_malformed_ids() {
        let state = test_state().await;
        let (user, _, _) = state.db.get_user_for_oauth2("admin", "admin", None).await.unwrap();
        let bad = [("7".repeat(33), "u".to_string()), ("12 34".into(), "u".into()), ("702".into(), "u".repeat(256))];
        for (id, uuid) in bad {
            let login = OidcState { id, uuid, device_type: "client".into(), ..Default::default() };
            state.record_viewer_login(&login, &user).await;
        }
        assert_eq!(state.list_viewer_devices(0, 10).await.unwrap().0, 0);
        let ok = OidcState { id: "7".repeat(32), uuid: "u".repeat(255), device_type: "client".into(), ..Default::default() };
        state.record_viewer_login(&ok, &user).await;
        assert_eq!(state.list_viewer_devices(0, 10).await.unwrap().0, 1);
    }
}
