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
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use oauth2::oauth_provider::OAuthProvider;
use rocket_okapi::okapi::schemars;
use rocket_okapi::JsonSchema;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};

use crate::Token;

pub type SessionId = u64;
pub type UserId = Vec<u8>;

struct BoolVisitor;

impl<'de> Visitor<'de> for BoolVisitor {
    type Value = Option<bool>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a boolean or a string 'true', 'false', '0', '1'")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Some(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match value {
            "true" | "1" => Ok(Some(true)),
            "false" | "0" => Ok(Some(false)),
            _ => Err(serde::de::Error::custom(
                "expected 'true', 'false', '0', '1'",
            )),
        }
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(None)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(None)
    }
}

fn from_str_to_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(BoolVisitor)
}

fn from_bool_to_str<S>(val: &Option<bool>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match val {
        Some(true) => serializer.serialize_str("true"),
        Some(false) => serializer.serialize_str("false"),
        None => serializer.serialize_none(),
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, JsonSchema)]
pub struct AddressBook {
    pub ab: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<u32>,
}

impl AddressBook {
    pub fn empty() -> Self {
        Self {
            ab: "{}".to_string(),
            name: None,
            owner: None,
            rule: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SystemInfo {
    pub cpu: Option<String>,
    pub hostname: Option<String>,
    pub id: Option<String>,
    pub memory: Option<String>,
    pub os: Option<String>,
    pub username: Option<String>,
    pub uuid: Option<String>,
    pub version: Option<String>,
    pub ip: Option<String>,
}

#[derive(Deserialize, Debug, JsonSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub id: String,
    pub uuid: String,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone, Default)]
pub struct UserInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub admin: bool
}

#[derive(Serialize, Debug, JsonSchema)]
pub struct LoginReply {
    #[serde(rename = "type")]
    pub response_type: String,
    pub user: UserInfo,
    pub access_token: Token,
}
#[derive(Serialize, Debug, JsonSchema)]
pub struct LogoutReply {
    pub data: String,
}

#[derive(Deserialize, Debug, JsonSchema)]
pub struct CurrentUserRequest {
    pub id: String,
    pub uuid: String,
}

#[derive(Serialize, Debug, JsonSchema)]
pub struct CurrentUserResponse {
    pub error: bool,
    #[serde(flatten)]
    pub data: UserInfo,
}

#[derive(Deserialize, Debug, JsonSchema)]
pub struct AbRequest {
    pub data: String,
}

#[derive(Deserialize, Debug, JsonSchema)]
pub struct AuditRequest {
    #[serde(default)]
    #[serde(rename = "Id")]
    pub id_: usize,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub uuid: String,
}

#[derive(Deserialize, Debug, JsonSchema)]
pub struct AuditConnRequest {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub conn_id: i64,
    #[serde(default)]
    pub session_id: u64,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub os_login: Option<String>,
    #[serde(default)]
    pub conn_audit_ref: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Deserialize, Debug, JsonSchema)]
pub struct AuditFileRequest {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub peer_id: String,
    #[serde(default)]
    pub conn_id: i64,
    #[serde(default, rename = "type")]
    pub file_type: i8,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub is_file: bool,
    #[serde(default)]
    pub info: String,
    #[serde(default)]
    pub nonce: String,
}

#[derive(Deserialize, Debug, JsonSchema)]
pub struct AuditAlarmRequest {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub typ: i8,
    #[serde(default)]
    pub info: String,
    #[serde(default)]
    pub conn_id: i64,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub conn_audit_ref: Option<String>,
}

// {
//    peers: [{id: "abcd", username: "", hostname: "", platform: "", alias: "", tags: ["", "", ...]}, ...],
//    tags: [],
// }

#[derive(Serialize, Debug, JsonSchema)]
pub struct Ab {
    pub tags: Vec<String>,
    pub peers: Vec<AbPeer>,
}

#[derive(Serialize, Debug, JsonSchema)]
pub struct AbGetResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    pub data: String,
}

#[derive(Serialize, Debug, JsonSchema)]
pub struct AbPersonal {
    pub guid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct AbSettingsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub max_peer_one_ab: u32,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct AbProfile {
    pub guid: String,
    pub name: String,
    pub owner: String,
    pub note: Option<String>,
    pub rule: u32,
}

impl Default for AbProfile {
    fn default() -> Self {
        AbProfile {
            guid: "".to_string(),
            name: "".to_string(),
            owner: "".to_string(),
            note: None,
            rule: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct AbSharedProfilesResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub total: u32,
    pub data: Vec<AbProfile>,
}

impl Default for AbSharedProfilesResponse {
    fn default() -> Self {
        AbSharedProfilesResponse {
            error: None,
            total: 0,
            data: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct AbPeer {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(
        rename = "forceAlwaysRelay",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "from_str_to_bool",
        serialize_with = "from_bool_to_str"
    )]
    pub force_always_relay: Option<bool>,
    #[serde(rename = "rdpPort")]
    pub rdp_port: Option<String>,
    #[serde(rename = "rdpUsername", skip_serializing_if = "Option::is_none")]
    pub rdp_username: Option<String>,
    #[serde(rename = "loginName", skip_serializing_if = "Option::is_none")]
    pub login_name: Option<String>, //login username
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "from_str_to_bool",
        serialize_with = "from_bool_to_str"
    )]
    pub same_server: Option<bool>,
}
impl Default for AbPeer {
    fn default() -> Self {
        AbPeer {
            id: "".to_string(),
            hash: Some("".to_string()),
            password: Some("".to_string()),
            username: Some("".to_string()),
            hostname: Some("".to_string()),
            platform: Some("".to_string()),
            alias: Some("".to_string()),
            tags: Some(Vec::new()),
            force_always_relay: Some(false),
            rdp_port: Some("".to_string()),
            rdp_username: Some("".to_string()),
            login_name: Some("".to_string()),
            same_server: None,
        }
    }
}

impl AbPeer {
    pub fn default_test() -> Self {
        AbPeer {
            id: "123456789".to_string(),
            hash: Some("0".to_string()),
            password: Some("none".to_string()),
            username: Some("someone".to_string()),
            hostname: Some("unknown".to_string()),
            platform: Some("windows".to_string()),
            alias: Some("Test peer".to_string()),
            tags: Some(Vec::new()),
            force_always_relay: Some(false),
            rdp_port: Some("".to_string()),
            rdp_username: Some("".to_string()),
            login_name: Some("user".to_string()),
            same_server: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct AbTag {
    pub name: String,
    pub color: u32,
}
impl Default for AbTag {
    fn default() -> Self {
        AbTag {
            name: "TAG1".to_string(),
            color: 4288585374,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct AbTagRenameRequest {
    pub old: String,
    pub new: String,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct AbPeersResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub total: u32,
    pub data: Vec<AbPeer>,
}
impl Default for AbPeersResponse {
    fn default() -> Self {
        AbPeersResponse {
            error: None,
            total: 0,
            data: Vec::new(),
        }
    }
}
impl AbPeersResponse {
    pub fn default_test() -> Self {
        AbPeersResponse {
            error: None,
            total: 1,
            data: vec![AbPeer::default_test()],
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HeartbeatRequest {
    pub id: String,
    pub modified_at: u64,
    pub uuid: String,
    pub ver: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SystemInfoRequest {
    pub cpu: String,
    pub hostname: String,
    pub id: String,
    pub memory: String,
    pub os: String,
    pub username: String,
    pub uuid: String,
    pub version: String,
}

#[derive(Serialize, Debug, JsonSchema)]
pub struct UsersResponse {
    pub msg: String,
    pub total: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct User {
    name: String,
    password: String,
    #[serde(rename = "confirm-password")]
    confirm_password: String,
    email: String,
    is_admin: bool,
    #[serde(rename = "group_name")]
    group_name: String,
    note: String,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct UpdateUserRequest {
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_admin: Option<bool>,
    #[serde(default, rename = "group_name", skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
}
impl Default for UpdateUserRequest {
    fn default() -> Self {
        UpdateUserRequest {
            uuid: uuid::Uuid::new_v4().to_string(),
            name: None,
            email: None,
            is_admin: None,
            group_name: None,
            note: None,
            status: None,
        }
    }
}
#[derive(Serialize, Deserialize, Clone, JsonSchema, Debug)]
pub struct OidcDeviceInfo {
    pub name: String,
    pub os: String,
    pub r#type: String,
}

impl Default for OidcDeviceInfo {
    fn default() -> Self {
        OidcDeviceInfo {
            name: "".to_string(),
            os: "".to_string(),
            r#type: "".to_string(),
        }
    }
}
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct OidcAuthRequest {
    #[serde(rename = "deviceInfo")]
    pub device_info: OidcDeviceInfo,
    pub id: String,
    pub op: String,
    pub uuid: String,
    #[serde(default, rename = "redirectUri")]
    pub redirect_uri: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct OidcAuthUrl {
    pub code: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct AuthQueryParams {
    pub code: String,
    pub id: String,
    pub uuid: String,
}

// OIDC response
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[repr(i32)]
pub enum OidcUserStatus {
    Disabled = 0,
    Normal = 1,
    Unverified = -1,
}
impl Default for OidcUserStatus {
    fn default() -> Self {
        OidcUserStatus::Normal
    }
}
impl Into<i32> for OidcUserStatus {
    fn into(self) -> i32 {
        self as i32
    }
}

impl Into<i64> for OidcUserStatus {
    fn into(self) -> i64 {
        self as i64
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct OidcResponse {
    pub access_token: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub tfa_type: String,
    pub secret: String,
    pub user: OidcUser,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct OidcUser {
    pub name: String,
    pub email: String,
    pub note: String,
    pub status: i64,
    pub info: OidcUserInfo,
    pub is_admin: bool,
    pub third_auth_type: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct OidcUserInfo {
    pub email_verification: bool,
    pub email_alarm_notification: bool,
    pub login_device_whitelist: Vec<String>,
    pub other: HashMap<String, String>,
}

#[derive(Clone)]
pub struct OidcState {
    pub id: String,           // is id of the Rustdesk client
    pub uuid: String,         // is uuid of the Rustdesk client
    pub code: Option<String>, // is openid_code
    pub auth_token: Option<String>,
    pub redirect_url: Option<String>,
    pub callback_url: Option<String>,
    pub provider: Option<Arc<dyn OAuthProvider>>,
    pub sub: Option<String>, // is the OIDC subject, the user's identity
    pub name: Option<String>,
    pub email: Option<String>,
    pub client_redirect_uri: Option<String>,
    /// When the login started (Unix seconds); pending logins expire.
    pub created_at: u64,
    /// Secret cookie value given to the browser that started the login.
    pub browser_key: Option<String>,
    /// Set once the login is tied to its starting browser or confirmed by the user.
    pub approved: bool,
    /// One-time value on the confirmation page shown after the IdP login.
    pub confirm_token: Option<String>,
    /// What the starting client said it is, and where it asked from; shown for confirmation.
    pub device_name: String,
    pub device_os: String,
    pub requester_ip: Option<String>,
}
impl Default for OidcState {
    fn default() -> Self {
        OidcState {
            id: "".to_string(),
            uuid: "".to_string(),
            code: None,
            auth_token: None,
            redirect_url: None,
            callback_url: None,
            provider: None,
            sub: None,
            name: None,
            email: None,
            client_redirect_uri: None,
            created_at: 0,
            browser_key: None,
            approved: false,
            confirm_token: None,
            device_name: String::new(),
            device_os: String::new(),
            requester_ip: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct OidcTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub id_token: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
struct JwtClaims {
    sub: String,
    email: String,
    name: String,
    iat: i64,
    exp: i64,
    iss: String,
    aud: String,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct AddUserRequest {
    pub name: String,
    pub email: String,
    pub is_admin: bool,
    pub group_name: String,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct EnableUserRequest {
    pub rows: Vec<String>,
    pub disable: bool,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct Provider {
    name: String,
    order_index: u32,
    enabled: bool,
    client_id: String,
    client_secret: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct OidcSettingsResponse {
    max_auth_count: u32,
    callback_url: String,
    providers: Vec<Provider>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct UserListResponse {
    pub guid: String,
    pub name: String,
    pub email: String,
    pub note: Option<String>,
    pub status: i32,
    pub group_name: String,
    pub is_admin: bool,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct UserList {
    pub msg: String,
    pub total: u32,
    pub data: Vec<UserListResponse>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct SoftwareVersionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct PeersResponse {
    pub msg: String,
    pub total: u32,
    pub data: Vec<Peer>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct PeersCountResponse {
    pub total: u32,
}
#[derive(Serialize, Deserialize, Clone, JsonSchema, Debug, Default)]
pub struct PeerInfo {
    pub cpu: Option<String>,
    pub hostname: Option<String>,
    pub id: Option<String>,
    pub memory: Option<String>,
    pub os: Option<String>,
    pub username: Option<String>,
    pub uuid: Option<String>,
    pub version: Option<String>,
    pub ip: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct Peer{
    pub guid: String,
    pub id: String,
    pub status: i32,
    pub strategy_name: String,
    pub last_online: String,
    pub info: PeerInfo,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct GroupsResponse {
    pub msg: String,
    pub total: u32,
    pub data: Vec<Group>,
}

pub type GroupInfo = String;
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct Group {
    pub guid: String,
    pub name: String,
    pub team: String,
    pub created_at: String,
    pub access_to: Vec<String>,
    pub accessed_from: Vec<String>,
    pub note: Option<String>,
    pub info: GroupInfo,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct AbSharedAddRequest {
    pub name: String,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct AbRule {
    pub guid: String,
    pub user: Option<String>,
    pub group: Option<String>,
    pub rule: u32,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct AbRulesResponse {
    pub msg: String,
    pub total: u32,
    pub data: Vec<AbRule>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct AbRuleAddRequest {
    pub guid: String, // address book guid
    pub user: Option<String>, // user=None and group=None means all users
    pub group: Option<String>,
    pub rule: u32,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct AbRuleDeleteRequest {
    pub guid: String, // rule guid
}

pub enum Platform {
    Windows,MacOS,Linux,Android,All
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct CpuCount {
    pub cpu: String,
    pub total: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct AddGoupRequest {
    pub name: String,
    pub note: String,
    pub allowed_outgoings: Vec<String>,
    pub allowed_incomings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct UpdateGoupRequest {
    pub guid: String,
    pub name: String,
    pub note: String,
    pub allowed_outgoings: Vec<String>,
    pub allowed_incomings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct AbSharedNameRequest {
    pub name: Option<String>,
    pub note: Option<String>,
    pub guid: String,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct DeleteUserRequest {
    pub rows: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BoolVisitor / from_str_to_bool / from_bool_to_str ---

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct BoolWrapper {
        #[serde(deserialize_with = "from_str_to_bool", serialize_with = "from_bool_to_str")]
        val: Option<bool>,
    }

    #[test]
    fn bool_deser_from_true_string() {
        let w: BoolWrapper = serde_json::from_str(r#"{"val":"true"}"#).unwrap();
        assert_eq!(w.val, Some(true));
    }

    #[test]
    fn bool_deser_from_false_string() {
        let w: BoolWrapper = serde_json::from_str(r#"{"val":"false"}"#).unwrap();
        assert_eq!(w.val, Some(false));
    }

    #[test]
    fn bool_deser_from_1_string() {
        let w: BoolWrapper = serde_json::from_str(r#"{"val":"1"}"#).unwrap();
        assert_eq!(w.val, Some(true));
    }

    #[test]
    fn bool_deser_from_0_string() {
        let w: BoolWrapper = serde_json::from_str(r#"{"val":"0"}"#).unwrap();
        assert_eq!(w.val, Some(false));
    }

    #[test]
    fn bool_deser_from_bool_true() {
        let w: BoolWrapper = serde_json::from_str(r#"{"val":true}"#).unwrap();
        assert_eq!(w.val, Some(true));
    }

    #[test]
    fn bool_deser_from_bool_false() {
        let w: BoolWrapper = serde_json::from_str(r#"{"val":false}"#).unwrap();
        assert_eq!(w.val, Some(false));
    }

    #[test]
    fn bool_deser_from_null() {
        let w: BoolWrapper = serde_json::from_str(r#"{"val":null}"#).unwrap();
        assert_eq!(w.val, None);
    }

    #[test]
    fn bool_deser_invalid_string() {
        let result: Result<BoolWrapper, _> = serde_json::from_str(r#"{"val":"maybe"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn bool_ser_true() {
        let w = BoolWrapper { val: Some(true) };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains(r#""val":"true""#));
    }

    #[test]
    fn bool_ser_false() {
        let w = BoolWrapper { val: Some(false) };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains(r#""val":"false""#));
    }

    #[test]
    fn bool_ser_none() {
        let w = BoolWrapper { val: None };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains(r#""val":null"#));
    }

    // --- AbPeer serde with BoolVisitor fields ---

    #[test]
    fn ab_peer_serde_roundtrip() {
        let peer = AbPeer::default_test();
        let json = serde_json::to_string(&peer).unwrap();
        let recovered: AbPeer = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.id, peer.id);
        assert_eq!(recovered.force_always_relay, peer.force_always_relay);
        assert_eq!(recovered.same_server, peer.same_server);
    }

    #[test]
    fn ab_peer_force_relay_serialized_as_string() {
        let peer = AbPeer {
            force_always_relay: Some(true),
            ..AbPeer::default()
        };
        let json = serde_json::to_string(&peer).unwrap();
        assert!(json.contains(r#""forceAlwaysRelay":"true""#));
    }

    #[test]
    fn ab_peer_deser_force_relay_from_string() {
        let json = r#"{"id":"test","forceAlwaysRelay":"true","rdpPort":""}"#;
        let peer: AbPeer = serde_json::from_str(json).unwrap();
        assert_eq!(peer.force_always_relay, Some(true));
    }

    #[test]
    fn ab_peer_deser_force_relay_from_bool() {
        let json = r#"{"id":"test","forceAlwaysRelay":false,"rdpPort":""}"#;
        let peer: AbPeer = serde_json::from_str(json).unwrap();
        assert_eq!(peer.force_always_relay, Some(false));
    }

    #[test]
    fn ab_peer_skip_none_fields() {
        let peer = AbPeer {
            id: "test".to_string(),
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
        let json = serde_json::to_string(&peer).unwrap();
        assert!(!json.contains("hash"));
        assert!(!json.contains("username"));
        assert!(!json.contains("forceAlwaysRelay"));
    }

    // --- AddressBook ---

    #[test]
    fn address_book_empty() {
        let ab = AddressBook::empty();
        assert_eq!(ab.ab, "{}");
        assert!(ab.name.is_none());
        assert!(ab.owner.is_none());
        assert!(ab.rule.is_none());
    }

    #[test]
    fn address_book_serde_roundtrip() {
        let ab = AddressBook {
            ab: r#"{"peers":[],"tags":[]}"#.to_string(),
            name: Some("work".to_string()),
            owner: Some(vec![1, 2, 3]),
            rule: Some(1),
        };
        let json = serde_json::to_string(&ab).unwrap();
        let recovered: AddressBook = serde_json::from_str(&json).unwrap();
        assert_eq!(ab, recovered);
    }

    #[test]
    fn address_book_skip_none_fields() {
        let ab = AddressBook::empty();
        let json = serde_json::to_string(&ab).unwrap();
        assert!(!json.contains("name"));
        assert!(!json.contains("owner"));
        assert!(!json.contains("rule"));
    }

    // --- OidcUserStatus ---

    #[test]
    fn oidc_user_status_into_i32() {
        let disabled: i32 = OidcUserStatus::Disabled.into();
        let normal: i32 = OidcUserStatus::Normal.into();
        let unverified: i32 = OidcUserStatus::Unverified.into();
        assert_eq!(disabled, 0);
        assert_eq!(normal, 1);
        assert_eq!(unverified, -1);
    }

    #[test]
    fn oidc_user_status_into_i64() {
        let normal: i64 = OidcUserStatus::Normal.into();
        assert_eq!(normal, 1);
    }

    #[test]
    fn oidc_user_status_default() {
        assert_eq!(OidcUserStatus::default(), OidcUserStatus::Normal);
    }

    #[test]
    fn oidc_user_status_serde_roundtrip() {
        let status = OidcUserStatus::Disabled;
        let json = serde_json::to_string(&status).unwrap();
        let recovered: OidcUserStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, recovered);
    }

    // --- OidcState ---

    #[test]
    fn oidc_state_default() {
        let state = OidcState::default();
        assert_eq!(state.id, "");
        assert_eq!(state.uuid, "");
        assert!(state.code.is_none());
        assert!(state.auth_token.is_none());
        assert!(state.provider.is_none());
    }

    // --- AbProfile ---

    #[test]
    fn ab_profile_default() {
        let p = AbProfile::default();
        assert_eq!(p.guid, "");
        assert_eq!(p.name, "");
        assert_eq!(p.owner, "");
        assert_eq!(p.rule, 0);
        assert!(p.note.is_none());
    }

    #[test]
    fn ab_profile_serde_roundtrip() {
        let p = AbProfile {
            guid: "abc-123".to_string(),
            name: "test ab".to_string(),
            owner: "admin".to_string(),
            note: Some("a note".to_string()),
            rule: 2,
        };
        let json = serde_json::to_string(&p).unwrap();
        let recovered: AbProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.guid, p.guid);
        assert_eq!(recovered.name, p.name);
        assert_eq!(recovered.rule, p.rule);
    }

    // --- AbTag ---

    #[test]
    fn ab_tag_default() {
        let tag = AbTag::default();
        assert_eq!(tag.name, "TAG1");
        assert_eq!(tag.color, 4288585374);
    }

    #[test]
    fn ab_tag_serde_roundtrip() {
        let tag = AbTag { name: "work".to_string(), color: 123456 };
        let json = serde_json::to_string(&tag).unwrap();
        let recovered: AbTag = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.name, "work");
        assert_eq!(recovered.color, 123456);
    }

    // --- LoginRequest / LoginReply / CurrentUser ---

    #[test]
    fn login_request_deser() {
        let json = r#"{"username":"admin","password":"pass","id":"123","uuid":"abc-def"}"#;
        let req: LoginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "admin");
        assert_eq!(req.id, "123");
    }

    #[test]
    fn current_user_response_flattens_user_info() {
        let resp = CurrentUserResponse {
            error: false,
            data: UserInfo {
                name: "admin".to_string(),
                email: Some("a@b.com".to_string()),
                admin: true,
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""name":"admin""#));
        assert!(json.contains(r#""error":false"#));
        // flattened, not nested under "data"
        assert!(!json.contains(r#""data":"#));
    }

    // --- UpdateUserRequest ---

    #[test]
    fn update_user_request_default_has_uuid() {
        let req = UpdateUserRequest::default();
        assert!(!req.uuid.is_empty());
        assert!(req.name.is_none());
        assert!(req.status.is_none());
    }

    #[test]
    fn update_user_request_serde_skip_none() {
        let req = UpdateUserRequest {
            uuid: "test-uuid".to_string(),
            name: Some("newname".to_string()),
            ..UpdateUserRequest::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("newname"));
        assert!(!json.contains("email"));
        assert!(!json.contains("password"));
    }

    // --- OidcDeviceInfo ---

    #[test]
    fn oidc_device_info_default() {
        let d = OidcDeviceInfo::default();
        assert_eq!(d.name, "");
        assert_eq!(d.os, "");
        assert_eq!(d.r#type, "");
    }

    // --- AbPeersResponse ---

    #[test]
    fn ab_peers_response_default() {
        let r = AbPeersResponse::default();
        assert!(r.error.is_none());
        assert_eq!(r.total, 0);
        assert!(r.data.is_empty());
    }

    #[test]
    fn ab_peers_response_default_test() {
        let r = AbPeersResponse::default_test();
        assert_eq!(r.total, 1);
        assert_eq!(r.data.len(), 1);
        assert_eq!(r.data[0].id, "123456789");
    }

    // --- AbSharedProfilesResponse ---

    #[test]
    fn ab_shared_profiles_response_default() {
        let r = AbSharedProfilesResponse::default();
        assert!(r.error.is_none());
        assert_eq!(r.total, 0);
        assert!(r.data.is_empty());
    }

    // --- PeerInfo ---

    #[test]
    fn peer_info_default() {
        let p = PeerInfo::default();
        assert!(p.cpu.is_none());
        assert!(p.hostname.is_none());
    }

    // --- EnableUserRequest ---

    #[test]
    fn enable_user_request_serde() {
        let req = EnableUserRequest {
            rows: vec!["user1".to_string(), "user2".to_string()],
            disable: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let recovered: EnableUserRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.rows.len(), 2);
        assert!(recovered.disable);
    }

    // --- SoftwareVersionResponse ---

    #[test]
    fn software_version_response_skip_none() {
        let r = SoftwareVersionResponse { server: None, client: Some("1.0".to_string()) };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("server"));
        assert!(json.contains(r#""client":"1.0""#));
    }

    // --- AbSharedNameRequest ---

    #[test]
    fn ab_shared_name_request_default() {
        let r = AbSharedNameRequest::default();
        assert!(r.name.is_none());
        assert!(r.note.is_none());
        assert_eq!(r.guid, "");
    }
}