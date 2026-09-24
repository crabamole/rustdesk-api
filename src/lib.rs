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
mod api;
mod extended_json;
mod extended_request;

use std::collections::HashMap;
use std::env;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;

use api::ActionResponse;
use extended_json::ExtendedJson;
use extended_request::ExtendedRequest;
use oauth2::oauth_provider::OAuthProvider;
use oauth2::oauth_provider::OAuthProviderFactory;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::form::validate::Len;
use rocket::http::{ContentType, Header, Status};
use rocket::response::{Redirect, Responder};
use rocket::{async_trait, delete, options, put, routes, uri};
use rocket::{Request, Response};

use s3software::extract_version;
use s3software::get_software_download_page;
use s3software::{get_s3_config_file, get_signed_release_url_with_config};

use state::{self};

#[cfg(feature = "ui")]
use ui;
use utils::guid_into_uuid;
use utils::AbProfile;
use utils::AbRule;
use utils::AbRuleAddRequest;
use utils::AbRuleDeleteRequest;
use utils::AbRulesResponse;
use utils::AbSharedAddRequest;
use utils::AbSharedNameRequest;
use utils::AddGoupRequest;
use utils::CpuCount;
use utils::PeersCountResponse;
use utils::Platform;
use utils::UpdateGoupRequest;
use utils::{
    self, get_host::get_host, AbPeer, AbPeersResponse, AbPersonal, AbSettingsResponse,
    AbSharedProfilesResponse, AbTag, BearerAuthToken, OidcAuthRequest, OidcAuthUrl, OidcResponse,
    OidcState, OidcUser, OidcUserInfo, OidcUserStatus,
};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use rocket::{
    self, figment::Figment, get, post, response::status, serde::json::Json, Build, Rocket, State,
};
pub use state::{ApiState, UserPasswordInfo};
use utils::{
    include_png_as_base64, unwrap_or_return, uuid_into_guid, AbTagRenameRequest, AddUserRequest,
    AddressBook, EnableUserRequest, DeleteUserRequest, GroupsResponse, OidcSettingsResponse, PeersResponse,
    SoftwareResponse, SoftwareVersionResponse, UpdateUserRequest, UserList,
};
use utils::{
    AbGetResponse, AbRequest, AuditRequest, CurrentUserRequest, CurrentUserResponse,
    HeartbeatRequest, LoginReply, LoginRequest, LogoutReply, UserInfo, UsersResponse,
};

type AuthenticatedUser = state::AuthenticatedUser<BearerAuthToken>;
type AuthenticatedAdmin = state::AuthenticatedAdmin<BearerAuthToken>;

use rocket_okapi::{openapi, openapi_get_routes, rapidoc::*, settings::UrlObject};
use uuid::Uuid;

use include_dir::{include_dir, Dir};

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PUT, DELETE, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

/// # Answers to OPTIONS requests
#[openapi(tag = "Cors")]
#[options("/<_path..>")]
async fn options(_path: PathBuf) -> Result<(), std::io::Error> {
    Ok(())
}

/// Read the required database URL.
pub fn database_url_from_env() -> Result<String, String> {
    std::env::var("DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "DATABASE_URL is required (postgres://user:pass@host:5432/db)".to_string())
}

pub async fn build_rocket(figment: Figment, db_url: &str) -> Rocket<Build> {
    build_rocket_with_db(figment, db_url).await
}

pub async fn build_rocket_with_db(figment: Figment, db_path: &str) -> Rocket<Build> {
    let state = ApiState::new_with_db(db_path).await;

    let rocket = rocket::custom(figment)
        .attach(CORS)
        .mount(
            "/",
            openapi_get_routes![
                options,
                login,
                login_options,
                ab_get,
                ab_post,
                ab,
                current_user,
                audit,
                audit_conn,
                audit_conn_active,
                audit_file,
                audit_alarm,
                logout,
                heartbeat,
                sysinfo,
                groups,
                group_get,
                group_add,
                group_delete,
                group_update,
                users,
                users_client,
                user_add,
                user_delete,
                user_enable,
                user_update,
                peers,
                peers_count,
                peers_cpus,
                strategies,
                oidc_auth,
                oidc_state,
                oidc_add,
                oidc_get,
                ab_peer_add,
                ab_peer_update,
                ab_peer_delete,
                ab_peers,
                ab_personal,
                ab_tags,
                ab_tag_add,
                ab_tag_update,
                ab_tag_rename,
                ab_tag_delete,
                ab_shared,
                ab_shared_add,
                ab_shared_delete,
                ab_shared_name,
                ab_settings,
                ab_rules,
                ab_rule_add,
                ab_rule_delete,
                software,
                software_version,
                software_releases_latest,
                software_download,
                software_releases_tag,
                webconsole_index,
                webconsole_index_html,
                // webconsole_assets,
            ],
        )
        .mount("/",routes![
            favicon,
            webconsole_vue,
            openapi_snippet,
            openapi_snippet_map,
            oidc_callback,
        ])
        .mount(
            "/api/doc/",
            make_rapidoc(&RapiDocConfig {
                title: Some("SCTGDesk API Doc".to_owned()),
                custom_html: Some(include_str!("../rapidoc/index.html").to_owned()),
                slots: SlotsConfig{
                    logo: Some(include_png_as_base64!("../assets/logo.png")),
                    footer: Some(r#"© 2024 <a style="color: #ffffff; text-decoration: none;" href='https://sctg.eu.org/'>SCTG</a>. All rights reserved. <a style="color: #ffffff; text-decoration: none;" href="https://github.com/sctg-development/sctgdesk-server">sctgdesk-server <svg style="height:1.25em" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 496 512"><path d="M165.9 397.4c0 2-2.3 3.6-5.2 3.6-3.3 .3-5.6-1.3-5.6-3.6 0-2 2.3-3.6 5.2-3.6 3-.3 5.6 1.3 5.6 3.6zm-31.1-4.5c-.7 2 1.3 4.3 4.3 4.9 2.6 1 5.6 0 6.2-2s-1.3-4.3-4.3-5.2c-2.6-.7-5.5 .3-6.2 2.3zm44.2-1.7c-2.9 .7-4.9 2.6-4.6 4.9 .3 2 2.9 3.3 5.9 2.6 2.9-.7 4.9-2.6 4.6-4.6-.3-1.9-3-3.2-5.9-2.9zM244.8 8C106.1 8 0 113.3 0 252c0 110.9 69.8 205.8 169.5 239.2 12.8 2.3 17.3-5.6 17.3-12.1 0-6.2-.3-40.4-.3-61.4 0 0-70 15-84.7-29.8 0 0-11.4-29.1-27.8-36.6 0 0-22.9-15.7 1.6-15.4 0 0 24.9 2 38.6 25.8 21.9 38.6 58.6 27.5 72.9 20.9 2.3-16 8.8-27.1 16-33.7-55.9-6.2-112.3-14.3-112.3-110.5 0-27.5 7.6-41.3 23.6-58.9-2.6-6.5-11.1-33.3 2.6-67.9 20.9-6.5 69 27 69 27 20-5.6 41.5-8.5 62.8-8.5s42.8 2.9 62.8 8.5c0 0 48.1-33.6 69-27 13.7 34.7 5.2 61.4 2.6 67.9 16 17.7 25.8 31.5 25.8 58.9 0 96.5-58.9 104.2-114.8 110.5 9.2 7.9 17 22.9 17 46.4 0 33.7-.3 75.4-.3 83.6 0 6.5 4.6 14.4 17.3 12.1C428.2 457.8 496 362.9 496 252 496 113.3 383.5 8 244.8 8zM97.2 352.9c-1.3 1-1 3.3 .7 5.2 1.6 1.6 3.9 2.3 5.2 1 1.3-1 1-3.3-.7-5.2-1.6-1.6-3.9-2.3-5.2-1zm-10.8-8.1c-.7 1.3 .3 2.9 2.3 3.9 1.6 1 3.6 .7 4.3-.7 .7-1.3-.3-2.9-2.3-3.9-2-.6-3.6-.3-4.3 .7zm32.4 35.6c-1.6 1.3-1 4.3 1.3 6.2 2.3 2.3 5.2 2.6 6.5 1 1.3-1.3 .7-4.3-1.3-6.2-2.2-2.3-5.2-2.6-6.5-1zm-11.4-14.7c-1.6 1-1.6 3.6 0 5.9 1.6 2.3 4.3 3.3 5.6 2.3 1.6-1.3 1.6-3.9 0-6.2-1.4-2.3-4-3.3-5.6-2z"/></svg></a>"#.to_owned()),
                    ..Default::default()
                },
                general: GeneralConfig {
                    spec_urls: vec![UrlObject::new("General", "../../openapi.json")],
                    ..Default::default()
                },
                hide_show: HideShowConfig {
                    allow_spec_url_load: false,
                    allow_spec_file_load: false,
                    allow_spec_file_download: true,
                    show_curl_before_try: true,
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .manage(state);

    #[cfg(feature = "ui")]
    {
        rocket = ui::update_rocket(rocket);
    }

    rocket
}

/// # User Login
///
/// This function is an API endpoint that allows a user to log in without oauth.
/// It is tagged with "login" for OpenAPI documentation. <br>
///
/// ## Parameters
///
/// - `request`: The request data, which includes the user's username and password.  <br>
///
/// ## Returns
///
/// If successful, this function returns a `Json<LoginReply>` object, which includes the user's information and access token.  <br>
/// If the user is not authorized, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the user is not authorized or if the system is in maintenance mode.
#[openapi(tag = "login")]
#[post("/api/login", format = "application/json", data = "<request>")]
async fn login(
    state: &State<ApiState>,
    request: Json<LoginRequest>,
) -> Result<Json<LoginReply>, status::Unauthorized<()>> {
    let status_forbidden = || status::Unauthorized::<()>(());

    let user_password_info = UserPasswordInfo::from_password(request.password.as_str());
    let (user, access_token) = state
        .user_login(&request.username, user_password_info, false)
        .await
        .ok_or_else(status_forbidden)?;

    let reply = LoginReply {
        response_type: "access_token".to_string(),
        user: user,
        access_token,
    };

    log::debug!("login: {:?}", request);

    state.check_maintenance().await;

    Ok(Json(reply))
}

/// # Get the User's Legacy Address Book
///
/// This function is an API endpoint that allows an authenticated user to retrieve their legacy address book. <br>
/// The Legacy Address Book is the address book that was used in the previous version of SCTGDesk. <br>
/// Rustdesk client uses the legacy address book if it cannot find the new one <br>
/// It is tagged with "address book legacy" for OpenAPI documentation.
///
/// ## Parameters
///
/// - none
///
/// ## Returns
///
/// If successful, this function returns a `Json<AbGetResponse>` object, which includes the legacy address book information.  <br>
/// If the user is not authorized, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the user is not authorized.
///
#[openapi(tag = "address book legacy")]
#[get("/api/ab", format = "application/json")]
async fn ab_get(
    state: &State<ApiState>,
    user: AuthenticatedUser,
) -> Result<Json<AbGetResponse>, status::Unauthorized<()>> {
    ab_get_handler(state, user).await
}

/// # Get the User's Address Book
///
/// This function is an API endpoint that allows an authenticated user to retrieve their address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - none
///
/// ## Returns
///
/// If successful, this function returns a `Json<AbGetResponse>` object, which includes the address book information.  <br>
/// If the user is not authorized, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the user is not authorized.
///
/// # Example
///
/// POST /api/ab/get
#[openapi(tag = "address book")]
#[post("/api/ab/get", format = "application/json")]
async fn ab_post(
    state: &State<ApiState>,
    user: AuthenticatedUser,
) -> Result<Json<AbGetResponse>, status::Unauthorized<()>> {
    ab_get_handler(state, user).await
}

/// Common handler for the user's address book
///
/// # Arguments
///
/// * `state` - The API state
/// * `user` - The authenticated user supplied via a Bearer token
///
/// # Returns
///
/// The user's address book in JSON format
async fn ab_get_handler(
    state: &State<ApiState>,
    user: AuthenticatedUser,
) -> Result<Json<AbGetResponse>, status::Unauthorized<()>> {
    log::debug!("ab get");

    // Get the user's address book from the state
    let abi = state
        .get_user_address_book(user.info.user_id)
        .await
        .unwrap_or_else(|| AddressBook::empty());

    let error = if abi.ab.is_empty() { Some(true) } else { None };
    // Create the reply with the address book and a timestamp
    let reply = AbGetResponse {
        error: error,
        updated_at: if error.is_some() {
            Some("now".to_string())
        } else {
            None
        },
        data: abi.ab,
    };

    // Check if the server is in maintenance mode
    state.check_maintenance().await;

    // Debug log the reply
    log::debug!("ab get reply: {:?}", Json(&reply));

    // Return the reply as JSON
    Ok(Json(reply))
}

/// Set the user's address book
#[openapi(tag = "address book legacy")]
#[post("/api/ab", format = "application/json", data = "<request>")]
async fn ab(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    request: Json<AbRequest>,
) -> Result<(), status::Unauthorized<()>> {
    log::debug!("ab: {:?}", request);

    let ab = request.data.clone();

    log::debug!("new ab: {:?}", &ab);

    let ab = AddressBook {
        ab,
        ..Default::default()
    };

    let _ = unwrap_or_return!(state
        .set_user_address_book(user.info.user_id, ab)
        .await
        .ok_or(Err(status::Unauthorized::<()>(()))));

    state.check_maintenance().await;

    Ok(())
}

/// # Get the Current User
///
/// This function is an API endpoint that allows an authenticated user to retrieve their current user information.
/// It is tagged with "user" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `request`: The request data, which includes the current user information.  <br>
///
/// ## Returns
///
/// If successful, this function returns a `Json<CurrentUserResponse>` object, which includes the current user information.  <br>
/// If the user is not authorized, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the user is not authorized.
#[openapi(tag = "user")]
#[post("/api/currentUser", format = "application/json", data = "<request>")]
async fn current_user(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    request: Json<CurrentUserRequest>,
) -> Result<Json<CurrentUserResponse>, status::Unauthorized<()>> {
    log::debug!("current_user authenticated request: {:?}", request);

    let username = unwrap_or_return!(state
        .get_current_user_name(&user.info)
        .await
        .ok_or(Err(status::Unauthorized::<()>(()))));

    let reply = CurrentUserResponse {
        error: false,
        data: UserInfo {
            name: username,
            ..Default::default()
        },
    };

    log::debug!("current_user reply: {:?}", reply);
    Ok(Json(reply))
}

/// Audit (legacy endpoint, delegates to conn handler)
#[openapi(tag = "audit")]
#[post("/api/audit", format = "application/json", data = "<request>")]
async fn audit(state: &State<ApiState>, request: Json<AuditRequest>) {
    log::debug!("audit: {:?}", request);
    state.check_maintenance().await;
}

/// Audit connection events
#[openapi(tag = "audit")]
#[post("/api/audit/conn", format = "application/json", data = "<request>")]
async fn audit_conn(
    state: &State<ApiState>,
    request: Json<utils::AuditConnRequest>,
) -> String {
    log::debug!("audit_conn: {:?}", request);
    let result = state.audit_conn(&request).await;
    state.check_maintenance().await;
    match result {
        Some(guid) => serde_json::to_string(&guid).unwrap_or_default(),
        None => String::new(),
    }
}

/// Query active audit connection
#[openapi(tag = "audit")]
#[get("/api/audit/conn/active?<id>&<session_id>&<conn_type>")]
async fn audit_conn_active(
    state: &State<ApiState>,
    id: &str,
    session_id: &str,
    conn_type: &str,
) -> String {
    log::debug!("audit_conn_active: id={}, session_id={}, conn_type={}", id, session_id, conn_type);
    let result = state.find_active_audit_conn(id, session_id, conn_type).await;
    match result {
        Some(guid) => serde_json::to_string(&guid).unwrap_or_default(),
        None => serde_json::to_string("").unwrap_or_default(),
    }
}

/// Audit file transfer events
#[openapi(tag = "audit")]
#[post("/api/audit/file", format = "application/json", data = "<request>")]
async fn audit_file(
    state: &State<ApiState>,
    request: Json<utils::AuditFileRequest>,
) {
    log::debug!("audit_file: {:?}", request);
    state.audit_file(&request).await;
    state.check_maintenance().await;
}

/// Audit alarm events
#[openapi(tag = "audit")]
#[post("/api/audit/alarm", format = "application/json", data = "<request>")]
async fn audit_alarm(
    state: &State<ApiState>,
    request: Json<utils::AuditAlarmRequest>,
) {
    log::debug!("audit_alarm: {:?}", request);
    state.audit_alarm(&request).await;
    state.check_maintenance().await;
}

/// # Log the User Out
///
/// This function is an API endpoint that allows an authenticated user to log out.
/// It is tagged with "login" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `request`: The request data, which includes the current user information.  <br>
///
/// ## Returns
///
/// If successful, this function returns a `Json<LogoutReply>` object, which includes a success message.  <br>
/// If the user is not authorized, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the user is not authorized.
///
#[openapi(tag = "login")]
#[post("/api/logout", format = "application/json", data = "<request>")]
async fn logout(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    request: Json<CurrentUserRequest>,
) -> Result<Json<LogoutReply>, status::Unauthorized<()>> {
    log::debug!("logout: {:?}", request);

    let _ = unwrap_or_return!(state
        .user_logout(&user.info)
        .await
        .ok_or(Err(status::Unauthorized::<()>(()))));

    let reply = LogoutReply {
        data: String::new(),
    };

    state.check_maintenance().await;

    Ok(Json(reply))
}

/// # Heartbeat
///
/// This function is an API endpoint that is frequently hit by the client at the /api/heartbeat endpoint.
/// It updates the `last_online` field of the peer.
/// It is tagged with "peer" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `request`: The request data, which includes the heartbeat information.  
///
/// ## Returns
///
/// This function always returns a `String` with the message "OK".  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode.
#[openapi(tag = "peer")]
#[post("/api/heartbeat", format = "application/json", data = "<request>")]
async fn heartbeat(state: &State<ApiState>, request: Json<HeartbeatRequest>) -> String {
    log::debug!("heartbeat: {:?}", request);
    let heartbeat = request.0;
    let res = state.update_heartbeat(heartbeat).await;
    log::debug!("res: {:?}", res);
    "OK".to_string()
}

/// # Set the System Info
///
/// This function is an API endpoint that allows a connected client to update its system information.
/// It is tagged with "peer" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `request`: The request data, which includes the system information.  
///
/// ## Returns
///
/// If successful, this function returns a `String` with the message "SYSINFO_UPDATED".  <br>
/// If the system info is not found, this function returns a `String` with the message "ID_NOT_FOUND".  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the system info is not found.
///
#[openapi(tag = "peer")]
#[post("/api/sysinfo", format = "application/json", data = "<request>")]
async fn sysinfo(state: &State<ApiState>, request: Json<utils::SystemInfo>) -> String {
    let sysinfo = request.0;
    let res = state.update_systeminfo(sysinfo).await;

    if res.is_none() {
        return "ID_NOT_FOUND".to_string();
    } else {
        return "SYSINFO_UPDATED".to_string();
    }
}

/// # Get the List of Users
///
/// This function is an API endpoint that allows an authenticated admin to retrieve a paginated list of users.
/// It is tagged with "user" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `current`: The current page number.  
///
/// - `pageSize`: The number of users per page.  
///
/// - `email`: The email to filter the users by.  
///
/// - `name`: The name to filter the users by.  
///
/// ## Returns
///
/// If successful, this function returns a `Json<UserList>` object, which includes a success message, the total number of users, and the list of users.  <br>
/// If no users are found, this function returns a `status::NotFound` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if no users are found.
///
/// # Example
///
/// GET /api/user-list?current=1&pageSize=10&email=test@test.com&name=Test
#[openapi(tag = "user")]
#[get(
    "/api/user-list?<current>&<pageSize>&<email>&<name>",
    format = "application/json"
)]
async fn users(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    current: u32,
    #[allow(non_snake_case)] pageSize: u32,
    email: Option<&str>,
    name: Option<&str>,
) -> Result<Json<UserList>, status::NotFound<()>> {
    log::debug!("users");
    state.check_maintenance().await;

    let email = if email.is_some() && email.unwrap().is_empty() {
        None
    } else {
        email
    };
    let res = state.get_all_users(name, email, current, pageSize).await;
    if res.is_none() {
        return Err(status::NotFound::<()>(()));
    }
    let response = UserList {
        msg: "success".to_string(),
        total: res.len() as u32,
        data: res.unwrap(),
    };

    Ok(Json(response))
}

/// # Get the List of Groups
///
/// This function is an API endpoint that allows an authenticated admin to retrieve a paginated list of groups.
/// It is tagged with "group" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `current`: The current page number.  
///
/// - `pageSize`: The number of groups per page.  
///
/// ## Returns
///
/// If successful, this function returns a `Json<GroupsResponse>` object, which includes a success message, the total number of groups, and the list of groups.  <br>
/// If no groups are found, this function returns a `status::NotFound` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if no groups are found.
///
/// # Example
///
/// GET /api/groups?current=1&pageSize=10
#[openapi(tag = "group")]
#[get("/api/groups?<current>&<pageSize>", format = "application/json")]
async fn groups(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    #[allow(unused_variables)] current: u32,
    #[allow(non_snake_case, unused_variables)] pageSize: u32,
) -> Result<Json<GroupsResponse>, status::NotFound<()>> {
    log::debug!("groups");
    state.check_maintenance().await;
    let offset = if current < 1 { 0 } else { current - 1 };
    let page_size = if pageSize < 1 {
        u32::max_value()
    } else {
        pageSize
    };
    let groups = state.get_groups(offset, page_size).await;
    if groups.is_none() {
        return Err(status::NotFound::<()>(()));
    }
    let groups = groups.unwrap();
    let response = GroupsResponse {
        msg: "success".to_string(),
        total: groups.len() as u32,
        data: groups,
    };

    Ok(Json(response))
}

/// # Get a Group
/// 
/// This function is an API endpoint that allows an authenticated admin to retrieve a group.
/// It is tagged with "group" for OpenAPI documentation.
/// 
/// ## Parameters
/// 
/// - `guid`: The GUID of the group to retrieve.
/// 
/// ## Returns
/// 
/// If successful, this function returns a `Json<Group>` object
/// If the group is not found, this function returns a `status::NotFound` error.
#[openapi(tag = "group")]
#[get("/api/group/<guid>", format = "application/json")]
async fn group_get(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    guid: String,
) -> Result<Json<utils::Group>, status::NotFound<()>> {
    log::debug!("group_get");
    state.check_maintenance().await;
    let group = state.get_group(guid.as_str()).await;
    if group.is_none() {
        return Err(status::NotFound::<()>(()));
    }
    Ok(Json(group.unwrap()))
}

/// # Add a Group
///
/// This function is an API endpoint that allows an authenticated admin to add a new group.
/// It is tagged with "group" for OpenAPI documentation..<br>
/// Todo allow to use different team
///
/// ## Parameters
///
/// - `request`: The request data, which includes the details of the group to be added.  <br>
///
/// ## Returns
///
/// If successful, this function returns a `Json<UsersResponse>` object, which includes a success message, the total number of groups, and the list of groups.  <br>
/// If the admin is not authorized, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the admin is not authorized.
///
/// # Example
///
/// POST /api/group
/// {"name":"new group","password":"string","confirm-password":"string","email":"string","is_admin":false,"group_name":"string"}
#[openapi(tag = "group")]
#[post("/api/group", format = "application/json", data = "<request>")]
async fn group_add(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    request: Json<AddGoupRequest>,
) -> Result<Json<UsersResponse>, status::Unauthorized<()>> {
    log::debug!("create_group");
    state.check_maintenance().await;

    let request = request.into_inner();
    let _res = state
        .create_group(request.name.as_str(), "Default", request.note.as_str()) // Todo allow to use different team
        .await;
    let response = UsersResponse {
        msg: "success".to_string(),
        total: 1,
        data: "[{}]".to_string(),
    };

    Ok(Json(response))
}

/// # Update a group
///
/// This function is an API endpoint that allows an authenticated admin to update a group.<br>
/// Todo allow to use different team
///
/// ## Parameters
///
/// - `guid`: The request data, which includes the details of the group to be updated.  <br>
///
/// ## Returns
///
/// If successful, this function returns a `Json<UsersResponse>` object, which includes a success message, the total number of groups, and the list of groups.  <br>
#[openapi(tag = "group")]
#[put("/api/group", format = "application/json", data = "<request>")]
async fn group_update(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    request: Json<UpdateGoupRequest>,
) -> Result<Json<UsersResponse>, status::Unauthorized<()>> {
    log::debug!("update_group");
    state.check_maintenance().await;

    let request = request.into_inner();
    let _res = state
        .update_group(
            request.guid.as_str(),
            request.name.as_str(),
            "Default", // Todo allow to use different team
            request.note.as_str(),
        )
        .await;
    let response = UsersResponse {
        msg: "success".to_string(),
        total: 1,
        data: "[{}]".to_string(),
    };

    Ok(Json(response))
}

/// # Delete a group
/// 
/// This function is an API endpoint that allows an authenticated admin to delete a group.
/// It is tagged with "group" for OpenAPI documentation.
/// 
/// ## Parameters
/// 
/// - `guid`: The GUID of the group to retrieve.
/// 
/// ## Returns
/// 
#[openapi(tag = "group")]
#[delete("/api/group/<guid>", format = "application/json", data = "<request>")]
async fn group_delete(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    request: Json<Vec<String>>,
    guid: &str,
) -> Result<(), status::Unauthorized<()>> {
    log::debug!("group_delete");
    state.check_maintenance().await;
    let _res = state.delete_group(guid).await;
    Ok(())
}

/// # Get Peers
///
/// This function is an API endpoint that retrieves the list of all peers in the network.
/// It is tagged with "peer" for OpenAPI documentation.
///
/// ## Parameters
///
/// - none
///
/// ## Returns
///
/// If successful, this function returns a `Json<PeersResponse>` object, which includes a success message, the total number of peers, and the list of peers.  <br>
/// If no peers are found, this function returns a `status::NotFound` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if no peers are found.
///
/// # Example
///
/// GET /api/peers
#[openapi(tag = "peer")]
#[get("/api/peers", format = "application/json")]
async fn peers(
    state: &State<ApiState>,
    _user: AuthenticatedUser,
) -> Result<Json<PeersResponse>, status::NotFound<()>> {
    log::debug!("peers");
    state.check_maintenance().await;
    let peers = state.get_all_peers().await;

    if peers.is_none() {
        return Err(status::NotFound::<()>(()));
    }
    Ok(Json(PeersResponse {
        msg: "success".to_string(),
        total: peers.len() as u32,
        data: peers.unwrap(),
    }))
}

/// # Count Peers per platform
///
/// This function is an API endpoint that retrieves the count of peers per platform.
/// It is tagged with "peer" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `platform`: The platform to filter the peers by (windows, macos, linux, android or all). <br>
///
/// ## Returns
///
/// If successful, this function returns a `Json<PeersCountResponse>` object, which includes the total number of peers for the specified platform.  <br>
///
#[openapi(tag = "peer")]
#[get("/api/peers/count/<platform>", format = "application/json")]
async fn peers_count(
    state: &State<ApiState>,
    _user: AuthenticatedUser,
    platform: String,
) -> Result<Json<PeersCountResponse>, status::NotFound<()>> {
    let count = match platform.to_lowercase().as_str() {
        "windows" => {
            let count = state.get_peers_count(Platform::Windows).await;
            log::debug!("peers_count: {:?}", count);
            count
        }
        "mac" | "macos" => {
            let count = state.get_peers_count(Platform::MacOS).await;
            log::debug!("peers_count: {:?}", count);
            count
        }
        "linux" => {
            let count = state.get_peers_count(Platform::Linux).await;
            log::debug!("peers_count: {:?}", count);
            count
        }
        "android" => {
            let count = state.get_peers_count(Platform::Android).await;
            log::debug!("peers_count: {:?}", count);
            count
        }
        "all" => {
            let count = state.get_peers_count(Platform::All).await;
            log::debug!("peers_count: {:?}", count);
            count
        }
        _ => 0,
    };
    return Ok(Json(PeersCountResponse { total: count }));
}

/// # Get the List of cpus used by the peers
///
/// This function is an API endpoint that retrieves the count of cpus used by the peers.
/// It is tagged with "peer" for OpenAPI documentation.
///
/// ## Parameters
///
/// ## Returns
///
/// If successful, this function returns a `Json<Vec<CpuCount>>` object, which includes the total number of cpus used by the peers.  <br>
#[openapi(tag = "peer")]
#[get("/api/peers/cpus", format = "application/json")]
async fn peers_cpus(
    state: &State<ApiState>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<CpuCount>>, status::NotFound<()>> {
    let cpus = state.get_cpus_count().await;
    return Ok(Json(cpus));
}

/// # Login Options
///
/// This is called by the client for knowing the Oauth2 provider(s) available
/// You must provide a list of Oauth2 providers in the `oauth2.toml` config file
/// The config file can be overridden by the `OAUTH2_CONFIG_FILE` environment variable
///
/// This function is an API endpoint that is called by the client to get the list of available OAuth2 providers.
/// The list of providers is defined in the `oauth2.toml` config file, which can be overridden by the `OAUTH2_CONFIG_FILE` environment variable.
/// It is tagged with "login" for OpenAPI documentation.
///
/// ## Limitations
///
/// It needs to be completed for mapping the username and email from the OAuth2 provider to the SCTGDesk user.
///
/// ## Parameters
///
/// - none
///
/// ## Returns
///
/// If successful, this function returns a `Json<Vec<String>>` object, which includes the list of available OAuth2 providers.  <br>
/// If the config file is not found or cannot be read, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the config file is not found or cannot be read.
///
/// # Example
///
/// GET /api/login-options
#[openapi(tag = "login")]
#[get("/api/login-options", format = "application/json")]
async fn login_options(
    state: &State<ApiState>,
) -> Result<Json<Vec<String>>, status::Unauthorized<()>> {
    let mut providers: Vec<String> = Vec::new();
    let providers_config = state
        .get_oauth2_config(oauth2::get_providers_config_file().as_str())
        .await;
    if providers_config.is_none() {
        return Err(status::Unauthorized::<()>(()));
    }
    for p in providers_config.unwrap() {
        providers.push(p.op_auth_string);
    }
    Ok(Json(providers))
}

/// OIDC Auth request
///
/// This entrypoint is called by the client for getting the authorization url for the Oauth2 provider he chooses
///
/// For testing you can generate a valid uuid field with the following command: `uuidgen | base64`
/// # OIDC Auth Request
///
/// This function is an API endpoint that is called by the client to get the authorization URL for the chosen OAuth2 provider.
/// It is tagged with "login" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `request`: The request data, which includes the chosen OAuth2 provider and a UUID.  <br> For testing you can generate a valid uuid field with the following command: `uuidgen | base64`
///
/// ## Returns
///
/// If successful, this function returns a `Json<OidcAuthUrl>` object, which includes the authorization URL and a session code.  <br>
/// If the UUID is invalid or the OAuth2 provider is not found, this function returns an `OidcAuthUrl` object with an empty URL and an error code.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the UUID is invalid or the OAuth2 provider is not found.
///
/// # Example
///
/// POST /api/oidc/auth
/// {
///     "op": "github",
///     "uuid": "generated_uuid_base64_encoded"
/// }
#[openapi(tag = "login")]
#[post("/api/oidc/auth", format = "application/json", data = "<request>")]
async fn oidc_auth(
    state: &State<ApiState>,
    request: ExtendedJson<OidcAuthRequest>,
) -> Json<OidcAuthUrl> {
    log::debug!("oidc_auth: {:?}", request);
    let headers = request.headers();
    log::debug!("headers: {:?}", headers);
    let request = request.data;

    let uuid_code = Uuid::new_v4().to_string();
    let uuid_decoded = BASE64_STANDARD.decode(request.uuid.clone());
    if uuid_decoded.is_err() {
        return Json(OidcAuthUrl {
            url: "".to_string(),
            code: "UUID_ERROR".to_string(),
        });
    }
    let uuid_decoded = uuid_decoded.unwrap();
    let uuid_client = String::from_utf8(uuid_decoded).unwrap();
    let callback_url = format!("{}/api/oidc/callback", get_host(headers.clone()));
    let providers_config = state
        .get_oauth2_config(oauth2::get_providers_config_file().as_str())
        .await;
    if providers_config.is_none() {
        return Json(OidcAuthUrl {
            url: "".to_string(),
            code: "".to_string(),
        });
    }
    let providers_config = providers_config.unwrap();
    let provider_config = providers_config
        .iter()
        .find(|config| config.op == request.op);

    if provider_config.is_none() {
        return Json(OidcAuthUrl {
            url: "".to_string(),
            code: "".to_string(),
        });
    }
    let provider_config = provider_config.unwrap();
    let provider_trait_object: Arc<dyn OAuthProvider> = {
        match provider_config.provider {
            oauth2::Provider::Github => Arc::new(oauth2::github_provider::GithubProvider::new()),
            oauth2::Provider::Gitlab => todo!(),
            oauth2::Provider::Google => todo!(),
            oauth2::Provider::Apple => todo!(),
            oauth2::Provider::Okta => todo!(),
            oauth2::Provider::Facebook => todo!(),
            oauth2::Provider::Azure => todo!(),
            oauth2::Provider::Auth0 => todo!(),
            oauth2::Provider::Dex => Arc::new(oauth2::dex_provider::DexProvider::new()),
            oauth2::Provider::Oauth2 => Arc::new(oauth2::oauth2_provider::Oauth2Provider::new()),
        }
    };

    let redirect_url =
        provider_trait_object.get_redirect_url(callback_url.as_str(), uuid_code.as_str());
    let _oidc_session = state
        .insert_oidc_session(
            uuid_code.clone(),
            OidcState {
                id: request.id.clone(),
                uuid: uuid_client,
                code: None,
                auth_token: None,
                redirect_url: Some(redirect_url.clone()),
                callback_url: Some(callback_url),
                provider: Some(provider_trait_object),
                name: None,
                email: None,
                client_redirect_uri: request.redirect_uri.clone(),
            },
        )
        .await;
    log::debug!("uuid_code: {:?}", uuid_code);

    Json(OidcAuthUrl {
        url: redirect_url.clone(),
        code: uuid_code,
    })
}

/// # OIDC Auth Callback
///
/// This function is an API endpoint that serves as the OAuth2 callback.
/// It exchanges the authorization code for an access token and stores it in the state.
/// It is tagged with "login" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `code`: The authorization code received from the OIDC provider.  
///
/// - `state`: The state parameter received from the OIDC provider. This is the session code.  
///
/// ## Returns
///
/// If successful, this function returns "OK".  <br>
/// If the session does not exist or the code exchange fails, this function returns "ERROR".  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the session does not exist or the code exchange fails.
///
/// # Example
///
/// GET /api/oidc/callback?code=authorization_code&state=session_code
#[get("/api/oidc/callback?<code>&<state>")]
async fn oidc_callback(
    apistate: &State<ApiState>,
    code: &str,
    state: &str,
) -> OidcCallbackResponse {
    let oidc_code = state;
    let oidc_authorization_code = code;
    let client_redirect_uri = apistate
        .get_oidc_session(oidc_code.to_string())
        .await
        .and_then(|s| s.client_redirect_uri);
    let updated_oidc_session = apistate
        .oidc_session_exchange_code(oidc_authorization_code.to_string(), oidc_code.to_string())
        .await;

    if let Some(redirect_uri) = client_redirect_uri {
        let separator = if redirect_uri.contains('?') { "&" } else { "?" };
        if updated_oidc_session.is_some() {
            return OidcCallbackResponse::Redirect(Redirect::found(format!(
                "{redirect_uri}{separator}oidc_code={oidc_code}"
            )));
        } else {
            return OidcCallbackResponse::Redirect(Redirect::found(format!(
                "{redirect_uri}{separator}oidc_error=login_failed"
            )));
        }
    }

    let message = if updated_oidc_session.is_none() {
        "Login failed. Please close this window and try again."
    } else {
        "Login successful!"
    };
    OidcCallbackResponse::Html(rocket::response::content::RawHtml(format!(
        r#"<!DOCTYPE html>
<html><head><title>RustDesk Login</title></head>
<body>
<p id="msg">{message}</p>
<script>
try {{ window.close(); }} catch(e) {{}}
</script>
</body></html>"#
    )))
}

#[derive(Responder)]
enum OidcCallbackResponse {
    Redirect(Redirect),
    Html(rocket::response::content::RawHtml<String>),
}

/// # OIDC State
///
/// This function is an API endpoint that checks the state of an OpenID Connect (OIDC) session.
/// It is tagged with "login" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `code`: The authorization code received from the OIDC provider.  
///
/// - `id`: The identifier of the OIDC session.  
///
/// - `uuid`: The UUID of the OIDC session.  
///
/// ## Returns
///
/// If successful, this function returns a `Json<Option<OidcResponse>>` object.  <br>
/// If the session does not exist, this function returns `Json(None)`.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the session does not exist.
///
/// # Example
///
/// GET /api/oidc/auth-query?code=authorization_code&id=session_id&uuid=session_uuid
#[openapi(tag = "login")]
#[get("/api/oidc/auth-query?<code>&<id>&<uuid>")]
async fn oidc_state(
    state: &State<ApiState>,
    code: &str,
    id: &str,
    uuid: &str,
) -> Json<Option<OidcResponse>> {
    log::debug!("oidc_state: {:?} {:?} {:?}", code, id, uuid);

    let res = state.oidc_check_session(code.to_string()).await;

    if res.is_none() {
        return Json(None);
    }

    let (token, username, userinfo) = res.unwrap();
    let auth_response = OidcResponse {
        access_token: token.to_base64(),
        type_field: "access_token".to_string(),
        tfa_type: "".to_string(),
        secret: "".to_string(),
        user: OidcUser {
            name: username,
            email: "".to_string(),
            note: "".to_string(),
            status: OidcUserStatus::Normal.into(),
            info: OidcUserInfo {
                email_verification: false,
                email_alarm_notification: false,
                login_device_whitelist: Vec::<String>::new(),
                other: HashMap::<String, String>::new(),
            },
            is_admin: userinfo.admin,
            third_auth_type: "Oauth2".to_string(),
        },
    };

    Json(Some(auth_response))
}

/// # Get Personal Address Book
///
/// This function is an API endpoint that retrieves the personal address book of the authenticated user.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - none
///
/// ## Returns
///
/// If successful, this function returns a `Json<AbPersonal>` object.  <br>
/// If the user is not authorized to access their personal address book, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the user is not authorized to access their personal address book.
///
/// # Example
///
/// POST /api/ab/personal
#[openapi(tag = "address book")]
#[post("/api/ab/personal")]
async fn ab_personal(
    state: &State<ApiState>,
    user: AuthenticatedUser,
) -> Result<Json<AbPersonal>, status::Unauthorized<()>> {
    state.check_maintenance().await;
    let guid = state.get_ab_personal_guid(user.info.user_id.clone()).await;
    if guid.is_none() {
        return Err(status::Unauthorized::<()>(()));
    }
    let guid = guid.unwrap();
    log::debug!("user: {:?} ab_personal: {:?}", user.info.user_id, guid);
    let ab_personal = AbPersonal {
        guid: guid,
        error: None,
    };
    Ok(Json(ab_personal))
}

/// Require share rule `min` or higher (1 read, 2 read/write, 3 full control)
/// on address book `ab`. Denials are 403, not 401: clients log out on 401.
async fn require_ab_rule(
    state: &ApiState,
    user: &AuthenticatedUser,
    ab: &str,
    min: u32,
) -> Result<(), Status> {
    if state.get_ab_rule_for_user(ab, &user.info.user_id).await >= min {
        Ok(())
    } else {
        Err(Status::Forbidden)
    }
}

/// # Get the Tags
///
/// This function is an API endpoint that retrieves all tags from an address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `ab`: The identifier of the address book.  
///
/// ## Returns
///
/// If successful, this function returns a JSON array of `AbTag` objects.  <br>
/// If the address book does not exist or the user is not authorized to access it, this function returns a `status::NotFound` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the address book does not exist or the user is not authorized to access it.
///
/// # Example
///
/// POST /api/ab/tags/018fab24-0ae5-731c-be23-88aa4518ea26
#[openapi(tag = "address book")]
#[post("/api/ab/tags/<ab>")]
async fn ab_tags(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    ab: &str,
) -> Result<Json<Vec<AbTag>>, Status> {
    require_ab_rule(state, &user, ab, 1).await?;
    state.check_maintenance().await;
    let ab_tags = state.get_ab_tags(ab).await;
    if ab_tags.is_none() {
        return Err(Status::NotFound);
    }
    let ab_tags = ab_tags.unwrap();
    Ok(Json(ab_tags))
}

/// # Add a Tag
///
/// This function is an API endpoint that adds a new tag to an address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `ab`: The identifier of the address book.  
///
/// - `request`: A JSON object containing the new tag to be added.  
///
/// ## Returns
///
/// If successful, this function returns an `ActionResponse::Empty` object.  <br>
/// If the tag already exists or the user is not authorized to add it, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the tag already exists or the user is not authorized to add it.
///
/// # Example
///
/// POST /api/ab/tag/add/018fab24-0ae5-731c-be23-88aa4518ea26
/// Content-Type: application/json
///
/// {"name": "tag1", "color": "#FF0000"}
#[openapi(tag = "address book")]
#[post(
    "/api/ab/tag/add/<ab>",
    format = "application/json",
    data = "<request>"
)]
async fn ab_tag_add(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    ab: &str,
    request: Json<AbTag>,
) -> Result<ActionResponse, Status> {
    require_ab_rule(state, &user, ab, 2).await?;
    state.check_maintenance().await;
    let ab_tag = request.0;
    log::debug!("ab_tag_add: {:?}", ab_tag);
    state.add_ab_tag(ab, ab_tag).await;
    Ok(ActionResponse::Empty)
}

/// # Update a Tag
///
/// This function is an API endpoint that updates a tag in an address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `ab`: The identifier of the address book.  
///
/// - `request`: A JSON object containing the updated tag.  
///
/// ## Returns
///
/// If successful, this function returns an `ActionResponse::Empty` object.  <br>
/// If the tag does not exist or the user is not authorized to update it, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the tag does not exist or the user is not authorized to update it.
///
/// # Example
///
/// PUT /api/ab/tag/update/018fab24-0ae5-731c-be23-88aa4518ea26
/// Content-Type: application/json
///
/// {"name": "tag1", "color": "#FF0000"}
#[openapi(tag = "address book")]
#[put(
    "/api/ab/tag/update/<ab>",
    format = "application/json",
    data = "<request>"
)]
async fn ab_tag_update(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    ab: &str,
    request: Json<AbTag>,
) -> Result<ActionResponse, Status> {
    require_ab_rule(state, &user, ab, 2).await?;
    state.check_maintenance().await;
    let ab_tag = request.0;
    log::debug!("ab_tag_update: {:?}", ab_tag);
    state.add_ab_tag(ab, ab_tag).await;
    Ok(ActionResponse::Empty)
}

/// # Rename a Tag
///
/// This function is an API endpoint that renames a tag in an address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `ab`: The identifier of the address book.
///
/// - `request`: A JSON object containing the old and new names of the tag.
///
/// ## Returns
///
/// If successful, this function returns an `ActionResponse::Empty` object.  <br>
/// If the tag does not exist or the user is not authorized to access it, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the tag does not exist or the user is not authorized to access it.
///
/// # Example
///
/// PUT /api/ab/tag/rename/018fab24-0ae5-731c-be23-88aa4518ea26
/// Content-Type: application/json
///
/// {"old": "tag1", "new": "tag2"}
#[openapi(tag = "address book")]
#[put(
    "/api/ab/tag/rename/<ab>",
    format = "application/json",
    data = "<request>"
)]
async fn ab_tag_rename(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    ab: &str,
    request: Json<AbTagRenameRequest>,
) -> Result<ActionResponse, Status> {
    require_ab_rule(state, &user, ab, 2).await?;
    state.check_maintenance().await;
    let ab_tag_old_name = request.0.old;
    let ab_tag_new_name = request.0.new;

    let ab_tag_old = state.get_ab_tag(ab, ab_tag_old_name.as_str()).await;
    if ab_tag_old.is_none() {
        return Err(Status::Unauthorized);
    }
    let mut ab_tag_new = ab_tag_old.unwrap();
    ab_tag_new.name = ab_tag_new_name;
    state
        .rename_ab_tag(ab, ab_tag_old_name.as_str(), ab_tag_new)
        .await;
    Ok(ActionResponse::Empty)
}

/// # Delete a Tag
///
/// This function is an API endpoint that deletes a tag from an address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `ab`: The identifier of the address book.  
///
/// - `request`: A JSON object containing an array of tag names to be deleted.  
///
/// ## Returns
///
/// If successful, this function returns an `ActionResponse::Empty` object.  <br>
/// If the request is empty or the user is not authorized to access it, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the request is empty or the user is not authorized to access it.
///
/// # Example
///
/// DELETE /api/ab/tag/018fab24-0ae5-731c-be23-88aa4518ea26
/// Content-Type: application/json
///
/// ["tag1", "tag2"]
#[openapi(tag = "address book")]
#[delete("/api/ab/tag/<ab>", format = "application/json", data = "<request>")]
async fn ab_tag_delete(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    ab: &str,
    request: Json<Vec<String>>,
) -> Result<ActionResponse, Status> {
    require_ab_rule(state, &user, ab, 2).await?;
    if request.0.is_empty() {
        return Err(Status::Unauthorized);
    }
    let tags_to_delete = request.0;
    state.check_maintenance().await;
    state.delete_ab_tags(ab, tags_to_delete).await;
    Ok(ActionResponse::Empty)
}

/// # Get Shared Profiles
///
/// This function is an API endpoint that retrieves the shared profiles from an address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - none
///
/// ## Returns
///
/// If successful, this function returns a `Json<AbSharedProfilesResponse>` object containing the shared profiles in the address book.  <br>
/// rule: 1: read, 2: write, 3: full control  <br>
/// If the address book does not exist or the user is not authorized to access it, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the address book does not exist or the user is not authorized to access it.
///
/// # Example
///
/// {"data":[{"guid":"018fab24-0ae5-731c-be23-88aa4518ea26","name":"shared profile","owner":"admin","rule":3}],"total":2}
#[openapi(tag = "address book")]
#[post("/api/ab/shared/profiles")]
async fn ab_shared(
    state: &State<ApiState>,
    user: AuthenticatedUser,
) -> Result<Json<AbSharedProfilesResponse>, status::Unauthorized<()>> {
    state.check_maintenance().await;
    let shared_address_books = state.get_shared_address_books(user.info.user_id).await;
    let mut ab_shared_profiles = AbSharedProfilesResponse::default();
    for ab in shared_address_books.expect("shared_address_books is None") {
        let address_book = AbProfile {
            guid: ab.ab,
            name: ab.name.unwrap_or("".to_string()),
            owner: guid_into_uuid(ab.owner.expect("Invalid owner")).expect("Invalid GUID"),
            rule: ab.rule.unwrap_or(0),
            ..Default::default()
        };
        ab_shared_profiles.data.push(address_book);
    }
    ab_shared_profiles.total = ab_shared_profiles.data.len() as u32;
    Ok(Json(ab_shared_profiles))
}

/// # Settings
///
/// This function is an API endpoint that retrieves the settings for an address book.<br>
/// TODO: Implement the settings for an address book.
#[openapi(tag = "address book")]
#[post("/api/ab/settings")]
async fn ab_settings(
    state: &State<ApiState>,
    _user: AuthenticatedUser,
) -> Result<Json<AbSettingsResponse>, status::Unauthorized<()>> {
    state.check_maintenance().await;
    let ab_settings = AbSettingsResponse {
        error: None,
        max_peer_one_ab: std::u32::MAX,
    };
    Ok(Json(ab_settings))
}

/// # List peers
///
/// This function is an API endpoint that lists the peers in an address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `current`: The current page number for pagination. This parameter is currently unused.
///
/// - `pageSize`: The number of items per page for pagination. This parameter is currently unused.
///
/// - `ab`: The identifier of the address book.
///
/// ## Returns
///
/// If successful, this function returns a `Json<AbPeersResponse>` object containing the peers in the address book.  <br>
/// If the address book does not exist or the user is not authorized to access it, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the address book does not exist or the user is not authorized to access it.
///
#[openapi(tag = "address book")]
#[post("/api/ab/peers?<current>&<pageSize>&<ab>")]
async fn ab_peers(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    #[allow(unused_variables)] current: u32,
    #[allow(non_snake_case, unused_variables)] pageSize: u32,
    ab: &str,
) -> Result<Json<AbPeersResponse>, Status> {
    require_ab_rule(state, &user, ab, 1).await?;
    state.check_maintenance().await;
    let ab_peers = state.get_ab_peers(ab).await;
    if ab_peers.is_none() {
        return Err(Status::Unauthorized);
    }
    let ab_peers = ab_peers.unwrap();
    let ab_peer_response = AbPeersResponse {
        error: None,
        total: ab_peers.len() as u32,
        data: ab_peers,
    };
    Ok(Json(ab_peer_response))
}

/// # Add peer
///
/// This function is an API endpoint that adds a peer to an address book.
///
/// ## Parameters
///
/// - `ab`: The identifier of the address book.
///
/// - `request`: A JSON object containing the new peer information.
///
/// ## Returns
///
/// If successful, this function returns an `ActionResponse::Empty` object.
#[openapi(tag = "address book")]
#[post(
    "/api/ab/peer/add/<ab>",
    format = "application/json",
    data = "<request>"
)]
async fn ab_peer_add(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    request: Json<AbPeer>,
    ab: &str,
) -> Result<ActionResponse, Status> {
    require_ab_rule(state, &user, ab, 2).await?;
    let ab_peer = request.0;
    state.check_maintenance().await;
    state.add_ab_peer(ab, ab_peer).await;
    Ok(ActionResponse::Empty)
}

/// # Update peer
///
/// This function is an API endpoint that updates a peer in an address book.
///
/// ## Parameters
///
/// - `ab`: The identifier of the address book.
///
/// - `request`: A JSON object containing the updated peer information.
///
/// ## Returns
///
/// If successful, this function returns an `ActionResponse::Empty` object.
#[openapi(tag = "address book")]
#[put(
    "/api/ab/peer/update/<ab>",
    format = "application/json",
    data = "<request>"
)]
async fn ab_peer_update(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    request: Json<AbPeer>,
    ab: &str,
) -> Result<ActionResponse, Status> {
    require_ab_rule(state, &user, ab, 2).await?;
    let mut ab_peer = request.0;
    let old_ab_peer = state.get_ab_peer(ab, ab_peer.id.as_str()).await;
    if old_ab_peer.is_none() {
        return Err(Status::Unauthorized);
    }
    let old_ab_peer = old_ab_peer.unwrap();
    ab_peer.hash = ab_peer.hash.or(old_ab_peer.hash);
    ab_peer.password = ab_peer.password.or(old_ab_peer.password);
    ab_peer.username = ab_peer.username.or(old_ab_peer.username);
    ab_peer.hostname = ab_peer.hostname.or(old_ab_peer.hostname);
    ab_peer.platform = ab_peer.platform.or(old_ab_peer.platform);
    ab_peer.alias = ab_peer.alias.or(old_ab_peer.alias);
    ab_peer.tags = ab_peer.tags.or(old_ab_peer.tags);
    ab_peer.force_always_relay = ab_peer
        .force_always_relay
        .or(old_ab_peer.force_always_relay);
    ab_peer.rdp_port = ab_peer.rdp_port.or(old_ab_peer.rdp_port);
    ab_peer.rdp_username = ab_peer.rdp_username.or(old_ab_peer.rdp_username);
    ab_peer.login_name = ab_peer.login_name.or(old_ab_peer.login_name);
    ab_peer.same_server = ab_peer.same_server.or(old_ab_peer.same_server);
    state.check_maintenance().await;
    state.add_ab_peer(ab, ab_peer).await;
    Ok(ActionResponse::Empty)
}

/// # Delete peer
///
/// This function is an API endpoint that deletes a peer from an address book.
///
/// ## Parameters
///
/// - `ab`: The identifier of the address book.
///
/// - `request`: A JSON object containing an array of peer IDs to be deleted.
///
/// ## Returns
///
/// If successful, this function returns an `ActionResponse::Empty` object.
#[openapi(tag = "address book")]
#[delete("/api/ab/peer/<ab>", format = "application/json", data = "<request>")]
async fn ab_peer_delete(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    ab: &str,
    request: Json<Vec<String>>,
) -> Result<ActionResponse, Status> {
    require_ab_rule(state, &user, ab, 2).await?;
    if request.0.is_empty() {
        return Err(Status::Unauthorized);
    }
    let peers_to_delete = request.0;
    state.check_maintenance().await;
    state.delete_ab_peer(ab, peers_to_delete).await;
    Ok(ActionResponse::Empty)
}

/// # List strategies
///
/// This function is an API endpoint that retrieves the list of all strategies. <br>
/// TODO: This function is currently unused.
///
#[openapi(tag = "todo")]
#[get("/api/stategies", format = "application/json")]
async fn strategies(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
) -> Result<Json<UsersResponse>, status::NotFound<()>> {
    log::debug!("peers");
    state.check_maintenance().await;

    let response = UsersResponse {
        msg: "success".to_string(),
        total: 1,
        data: "[{}]".to_string(),
    };

    Ok(Json(response))
}

/// # Add user
///
/// This function is an API endpoint that adds a new user.
///
/// ## Parameters
///
/// - `request`: A JSON object containing the new user information.
///
/// ## Returns
///
/// If successful, this function returns a `Json<UsersResponse>` object containing the updated user information.
#[openapi(tag = "user")]
#[post("/api/user", format = "application/json", data = "<request>")]
async fn user_add(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    request: Json<AddUserRequest>,
) -> Result<Json<UsersResponse>, status::Unauthorized<()>> {
    log::debug!("create_user");
    state.check_maintenance().await;

    let user_parameters = request.0;
    if user_parameters.password != user_parameters.confirm_password {
        return Ok(Json(UsersResponse {
            msg: "error: Passwords mismatch".to_string(),
            total: 0,
            data: "[{}]".to_string(),
        }));
    }
    let res = state.add_user(user_parameters).await;
    if res.is_none() {
        return Err(status::Unauthorized::<()>(()));
    }
    let response = UsersResponse {
        msg: "success".to_string(),
        total: 1,
        data: "[{}]".to_string(),
    };

    Ok(Json(response))
}

/// # Delete user
/// 
/// This function is an API endpoint that deletes a user.
/// 
/// ## Parameters
/// 
/// - `request`: A JSON object containing the list of users to delete.
/// 
/// ## Returns
/// 
/// If successful, this function returns a `Json<UsersResponse>` object containing the number of users deleted.
#[openapi(tag = "user")]
#[delete("/api/user", format = "application/json", data = "<request>")]
async fn user_delete(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    request: Json<DeleteUserRequest>,
) -> Result<Json<UsersResponse>, status::Unauthorized<()>> {
    log::debug!("create_user");
    state.check_maintenance().await;

    let delete_users = request.0;

    let mut count = 0;
    for uuid in delete_users.rows {
        let res = state.user_delete(uuid.as_str()).await;
        if res.is_some() {
            count += 1;
        }
    }
    let response = UsersResponse {
        msg: "success".to_string(),
        total: count,
        data: "[{}]".to_string(),
    };

    Ok(Json(response))
}

/// # Enable users
///
/// This function is an API endpoint that enables or disables users.
///
/// ## Parameters
///
/// - `request`: A JSON object containing the list of users to enable or disable.
///
/// ## Returns
///
/// If successful, this function returns a `Json<UsersResponse>` object containing the updated user information.
#[openapi(tag = "user")]
#[post("/api/enable-users", format = "application/json", data = "<request>")]
async fn user_enable(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    request: Json<EnableUserRequest>,
) -> Result<Json<UsersResponse>, status::Unauthorized<()>> {
    log::debug!("create_user");
    state.check_maintenance().await;

    let enable_users = request.0;

    let mut count = 0;
    for uuid in enable_users.rows {
        let res = state
            .user_change_status(uuid.as_str(), enable_users.disable)
            .await;
        if res.is_some() {
            count += 1;
        }
    }
    let response = UsersResponse {
        msg: "success".to_string(),
        total: count,
        data: "[{}]".to_string(),
    };

    Ok(Json(response))
}

/// # Update user
///
/// This function is an API endpoint that updates a user.<br>
/// Normal user can only update themselves, admin can update any user.<br>
///
/// ## Parameters
///
/// - `request`: A JSON object containing the updated user information.
///
/// ## Returns
///
/// If successful, this function returns a `Json<UsersResponse>` object containing the updated user information.
#[openapi(tag = "user")]
#[put("/api/user", format = "application/json", data = "<request>")]
async fn user_update(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    request: Json<UpdateUserRequest>,
) -> Result<Json<UsersResponse>, status::Unauthorized<()>> {
    log::debug!("update_user");
    state.check_maintenance().await;
    let mut guid = uuid_into_guid(request.0.uuid.as_str());
    if guid.is_none() {
        guid = Some(user.info.user_id.clone());
    }

    let guid = guid.unwrap();
    let is_admin = state
        .is_current_user_admin(&user.info)
        .await
        .unwrap_or(false);

    if !is_admin && user.info.user_id != guid {
        return Err(status::Unauthorized::<()>(()));
    }
    let response = UsersResponse {
        msg: "success".to_string(),
        total: 1,
        data: "[{}]".to_string(),
    };
    let mut user_update = request.0;
    if !is_admin {
        // A non-admin may edit only their own profile fields, never the
        // fields that control identity or privileges.
        user_update.name = None;
        user_update.is_admin = None;
        user_update.group_name = None;
        user_update.status = None;
    }
    state.user_update(guid, user_update).await;
    Ok(Json(response))
}

/// # Add OIDC Provider
///
/// This function is an API endpoint that adds an OIDC provider.
///
/// TODO: This function is currently unused.
#[openapi(tag = "todo")]
#[put("/api/oidc/settings", format = "application/json", data = "<_request>")]
async fn oidc_add(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    _request: Json<EnableUserRequest>,
) -> Result<Json<EnableUserRequest>, status::Unauthorized<()>> {
    log::debug!("Add OIDC Provider");
    state.check_maintenance().await;

    Err(status::Unauthorized::<()>(()))
}

/// # Get OIDC Providers
///
/// This function is an API endpoint that retrieves all OIDC providers.
///
/// TODO: This function is currently unused.
#[openapi(tag = "todo")]
#[get("/api/oidc/settings", format = "application/json")]
async fn oidc_get(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
) -> Result<Json<OidcSettingsResponse>, status::Unauthorized<()>> {
    log::debug!("create_user");
    state.check_maintenance().await;
    Err(status::Unauthorized::<()>(()))
}

/// # Get Users for client
///
/// This function is an API endpoint that retrieves all users.
///
/// ## Parameters
///
/// - `current`: The current page number for pagination. This parameter is currently unused.
///
/// - `pageSize`: The number of items per page for pagination. This parameter is currently unused.
///
/// - `accessible`: A boolean value indicating whether the user is accessible. This parameter is currently unused.
///
/// - `status`: The status of the user. This parameter is currently unused.
///
/// ## Returns
///
/// If successful, this function returns a `Json<UserList>` object containing the users.
#[openapi(tag = "user")]
#[get(
    "/api/users?<current>&<pageSize>&<accessible>&<status>",
    format = "application/json"
)]
async fn users_client(
    state: &State<ApiState>,
    _user: AuthenticatedUser,
    current: u32,
    #[allow(non_snake_case, unused_variables)] pageSize: u32,
    #[allow(unused_variables)] accessible: Option<bool>,
    #[allow(unused_variables)] status: Option<u32>,
) -> Result<Json<UserList>, status::NotFound<()>> {
    log::debug!("users");
    state.check_maintenance().await;

    let res = state.get_all_users(None, None, current, pageSize).await;
    if res.is_none() {
        return Err(status::NotFound::<()>(()));
    }
    let response = UserList {
        msg: "success".to_string(),
        total: res.len() as u32,
        data: res.unwrap(),
    };

    Ok(Json(response))
}

/// Get the software download url
///
/// # Arguments
///
/// * `key` - The key to the software download link, it can be `osx`, `w64` or `ios`
///
/// # Usage
///
/// * it needs a valid S3 configuration file defined with the `S3_CONFIG_FILE` environment variable
///
/// <pre>
/// [s3config]<br>
/// Page = "https://github.com/rustdesk/rustdesk/releases/latest"<br>
/// Endpoint = "https://compat.objectstorage.eu-london-1.oraclecloud.com"<br>
/// Region = "eu-london-1"<br>
/// AccessKey = "c324ead11faa0d87337c07ddc4a1129fab76188d"<br>
/// SecretKey = "GJurV55f/LD36kjZFpchZMj/uvgTqxHyFkBchUUa8KA="<br>
/// Bucket = "aezoz24elapn"<br>
/// Windows64Key = "master/sctgdesk-releases/sctgdesk-1.2.4-x86_64.exe"<br>
/// Windows32Key = "master/sctgdesk-releases/sctgdesk-1.2.4-i686.exe"<br>
/// OSXKey = "master/sctgdesk-releases/sctgdesk-1.2.4.dmg"<br>
/// OSXArm64Key = "master/sctgdesk-releases/sctgdesk-1.2.4.dmg"<br>
/// IOSKey = "master/sctgdesk-releases/sctgdesk-1.2.4.ipa"<br>
/// </pre>
///
#[openapi(tag = "software")]
#[get(
    "/api/software/client-download-link/<key>",
    format = "application/json"
)]
async fn software(key: &str) -> Result<Json<SoftwareResponse>, status::NotFound<()>> {
    log::debug!("software");
    let config = get_s3_config_file()
        .await
        .map_err(|e| status::NotFound(Box::new(e)));

    let config = config.unwrap();
    match key {
        "osx" => {
            let key = config.clone().s3config.osxkey;
            let url = get_signed_release_url_with_config(config, key.as_str())
                .await
                .map_err(|e| status::NotFound(Box::new(e)));
            let url = url.unwrap();
            let response = SoftwareResponse { url };
            Ok(Json(response))
        }
        "w64" => {
            let key = config.clone().s3config.windows64_key;
            let url = get_signed_release_url_with_config(config, key.as_str())
                .await
                .map_err(|e| status::NotFound(Box::new(e)));
            let url = url.unwrap();
            let response = SoftwareResponse { url };
            Ok(Json(response))
        }
        "ios" => {
            let key = config.clone().s3config.ioskey;
            let url = get_signed_release_url_with_config(config, key.as_str())
                .await
                .map_err(|e| status::NotFound(Box::new(e)));
            let url = url.unwrap();
            let response = SoftwareResponse { url };
            Ok(Json(response))
        }
        _ => Err(status::NotFound(())),
    }
}

/// # Retrieve the server version
///
/// This function is an API endpoint that retrieves the version of the server.
/// It is tagged with "software" for OpenAPI documentation.
///
/// ## Returns
///
/// If successful, this function returns a `Json<SoftwareVersionResponse>` object containing the version of the server.
#[openapi(tag = "software")]
#[get("/api/software/version/server", format = "application/json")]
async fn software_version() -> Json<SoftwareVersionResponse> {
    log::debug!("software_version");
    // MAIN_PKG_VERSION is an optional runtime override; nothing sets it by
    // default, so fall back to this crate's version instead of panicking.
    let version = env::var("MAIN_PKG_VERSION").unwrap_or(env!("CARGO_PKG_VERSION").to_string());
    let response = SoftwareVersionResponse {
        server: Some(version),
        client: Some(extract_version().await.unwrap_or("0.0.0".to_string())),
    };
    Json(response)
}

/// # Retrieve the client version
///
/// This function is an API endpoint that retrieves the version of the client.
/// It copies the GitHub method of retrieving the latest release version.
/// It is tagged with "software" for OpenAPI documentation.
///
/// It can be used by replacing the check_software_update() from the client.
/// You can find the client code at rustdesk/src/common.rs
/// ## Returns
///
/// Returns in the location header the URL of the latest release.
/// something like https://api-server/api/releases/tag/1.2.6
///
/// ## Example
///
/// It is easy to modify the client code to use this API endpoint.
/// this is how we can modify the client code to use this API endpoint.
///
/// <pre>
///     // see <a href='https://github.com/sctg-development/sctgdesk/blob/481d3516fef1daa145d8044594187cb11959f8be/src/common.rs#L953L972'>Sample modification on github</a><br>
///     let url=format!("{}/api/software/releases/latest",get_api_server("".to_owned(), "".to_owned())).to_owned();<br>
///     log::info!("URL for checking software updates: {}", url);<br>
/// </pre>
#[openapi(tag = "software")]
#[get("/api/software/releases/latest")]
async fn software_releases_latest(request: ExtendedRequest) -> Redirect {
    log::debug!("software_releases_latest");
    let headers = request.headers;
    let host = get_host(headers);
    let version = extract_version()
        .await
        .map_err(|e| status::NotFound(Box::new(e)));
    if version.is_err() {
        return Redirect::to(format!("{}/api/software/releases/tag/0.0.0", host));
    }
    let version = version.unwrap();
    let url = format!("{}/api/software/releases/tag/{}", host, version);
    Redirect::to(url)
}

/// # Simulate GitHub API for releases
///
/// This function is an API endpoint that simulates the GitHub API for releases.
///
/// ## Parameters
///
/// - `version`: The version of the release.
///
/// ## Returns
///
/// Returns a `Json<SoftwareVersionResponse>` object containing the version of the release.
#[openapi(tag = "software")]
#[get("/api/software/releases/tag/<version>")]
async fn software_releases_tag(
    version: &str,
) -> Result<Json<SoftwareVersionResponse>, status::NotFound<()>> {
    log::debug!("software_releases_tag");
    let response = SoftwareVersionResponse {
        server: None,
        client: Some(version.to_string()),
    };
    Ok(Json(response))
}

/// # Redirect to the software download page
///
/// This function is an API endpoint that redirects to the software download page.
/// You must set the `Page` key in the `s3config` of the S3 configuration file.
///
#[openapi(tag = "software")]
#[get("/api/software/download")]
async fn software_download() -> Redirect {
    let url = get_software_download_page()
        .await
        .unwrap_or("https://github.com/sctg-development/sctgdesk".to_string());
    Redirect::to(url)
}
/// # List the rules
///
/// This function is an API endpoint that lists the rules attached to a shared address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `current`: The current page number for pagination. This parameter is currently unused.
///
/// - `pageSize`: The number of items per page for pagination. This parameter is currently unused.
///
/// - `ab`: The identifier of the shared address book.
///
/// ## Returns
///
/// If successful, this function returns a `Json<AbRulesResponse>` object containing the rules for the address book.  <br>
/// If the address book does not exist or the user is not authorized to access it, this function returns a `status::Unauthorized` error.  <br>
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode, or if the address book does not exist or the user is not authorized to access it.
///
#[openapi(tag = "address book")]
#[get("/api/ab/rules?<current>&<pageSize>&<ab>", format = "application/json")]
async fn ab_rules(
    state: &State<ApiState>,
    user: AuthenticatedUser,
    current: u32,
    #[allow(unused_variables)] pageSize: u32,
    ab: &str,
) -> Result<Json<AbRulesResponse>, Status> {
    require_ab_rule(state, &user, ab, 3).await?;
    state.check_maintenance().await;
    let current = if current < 1 { 0 } else { current - 1 };
    let rules = state.get_ab_rules(current, pageSize, ab).await;
    if rules.is_none() {
        return Err(Status::Unauthorized);
    }
    let rules = rules.unwrap();
    let response = AbRulesResponse {
        msg: "success".to_string(),
        total: rules.len() as u32,
        data: rules,
    };
    Ok(Json(response))
}

/// # Add a Rule
///
/// This function is an API endpoint that adds a new rule to a shared address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `request`: The request containing the details of the rule to be added.
///
/// ## Returns
///
/// If successful, this function returns an `ActionResponse::Empty` indicating that the rule was successfully added. <br>
/// If the system is in maintenance mode, this function returns a `status::Unauthorized` error.
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode.
#[openapi(tag = "address book")]
#[post("/api/ab/rule", format = "application/json", data = "<request>")]
async fn ab_rule_add(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    request: Json<AbRuleAddRequest>,
) -> Result<ActionResponse, status::Unauthorized<()>> {
    state.check_maintenance().await;
    let rule = AbRule {
        guid: request.0.guid,
        user: request.0.user,
        group: request.0.group,
        rule: request.0.rule,
    };
    state.add_ab_rule(rule).await;
    Ok(ActionResponse::Empty)
}

/// # Delete a Rule
///
/// This function is an API endpoint that deletes a rule from a shared address book.
/// It is tagged with "address book" for OpenAPI documentation.
///
/// ## Parameters
///
/// - `request`: The request containing the GUID of the rule to be deleted.
///
/// ## Returns
///
/// If successful, this function returns an `ActionResponse::Empty` indicating that the rule was successfully deleted. <br>
/// If the system is in maintenance mode, this function returns a `status::Unauthorized` error.
///
/// ## Errors
///
/// This function will return an error if the system is in maintenance mode.
#[openapi(tag = "address book")]
#[delete("/api/ab/rule", format = "application/json", data = "<request>")]
async fn ab_rule_delete(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    request: Json<AbRuleDeleteRequest>,
) -> Result<ActionResponse, status::Unauthorized<()>> {
    state.check_maintenance().await;
    let rule = request.0.guid;
    state.delete_ab_rule(rule.as_str()).await;
    Ok(ActionResponse::Empty)
}

/// # Add shared profile
///
/// This function is an API endpoint that adds a shared profile to an address book.
/// It is tagged with "address book" for OpenAPI documentation.
/// 
/// ## Parameters
/// 
/// - `request`: A JSON object containing the shared profile to be added.
/// 
/// ## Returns
/// 
/// If successful, this function returns a `Json<AbSharedProfilesResponse>` object containing the shared profiles in the address book.  <br>
#[openapi(tag = "address book")]
#[post("/api/ab/shared/add", format = "application/json", data = "<request>")]
async fn ab_shared_add(
    state: &State<ApiState>,
    user: AuthenticatedAdmin,
    request: Json<AbSharedAddRequest>,
) -> Result<Json<AbSharedProfilesResponse>, status::Unauthorized<()>> {
    state.check_maintenance().await;
    let name = request.0.name;
    let note = request.0.note;
    let owner = guid_into_uuid(user.info.user_id.clone()).unwrap();
    let ab_uuid = state.add_shared_address_book(name.as_str(),owner.as_str()).await;
    if ab_uuid.is_none() {
        return Err(status::Unauthorized::<()>(()));
    }
    let ab_uuid = ab_uuid.unwrap();
    let shared_profile = AbProfile {
        guid: ab_uuid,
        name: name,
        owner: owner,
        rule: 3,
        note: note,
        ..Default::default()
    };
    let mut ab_shared_profiles = AbSharedProfilesResponse::default();
    ab_shared_profiles.data.push(shared_profile);
    Ok(Json(ab_shared_profiles))
}

/// # Delete shared profiles
///
/// This function is an API endpoint that deletes shared profiles from an address book.
/// It is tagged with "address book" for OpenAPI documentation.
/// 
/// ## Parameters
/// 
/// - `request`: A JSON object containing an array of shared profile GUIDs to be deleted.
/// 
/// ## Returns
/// 
/// If successful, this function returns an `ActionResponse::Empty` object.
#[openapi(tag = "address book")]
#[delete("/api/ab/shared", format = "application/json", data = "<request>")]
async fn ab_shared_delete(
    state: &State<ApiState>,
    _user: AuthenticatedAdmin,
    request: Json<Vec<String>>,
) -> Result<ActionResponse, status::Unauthorized<()>> {
    state.check_maintenance().await;
    let shared_profiles_to_delete = request.0;
    state.delete_shared_address_books(shared_profiles_to_delete).await;
    Ok(ActionResponse::Empty)
}

/// # Update shared profile name
/// 
/// This function is an API endpoint that updates the name of a shared profile in an address book.
/// It is tagged with "address book" for OpenAPI documentation.
/// 
/// ## Parameters
/// 
/// - `request`: A JSON object containing the updated shared profile information.
/// 
/// ## Returns
/// 
/// If successful, this function returns a `Json<AbSharedProfilesResponse>` object containing the updated shared profile information.
#[openapi(tag = "address book")]
#[put("/api/ab/shared/update/profile", format = "application/json", data = "<request>")]
async fn ab_shared_name(
    state: &State<ApiState>,
    user: AuthenticatedAdmin,
    request: Json<AbSharedNameRequest>,
) -> Result<Json<AbSharedProfilesResponse>, status::Unauthorized<()>> {
    state.check_maintenance().await;
    let shared_profile = request.0;
    let name = shared_profile.name.expect("Currently name is required");
    state.update_shared_address_book(shared_profile.guid.as_str(), name.as_str()).await;
    let shared_profiles = state.get_shared_address_books(user.info.user_id).await;
    let mut ab_shared_profiles = AbSharedProfilesResponse::default();
    for ab in shared_profiles.expect("shared_profiles is None") {
        let address_book = AbProfile {
            guid: ab.ab,
            name: ab.name.unwrap_or("".to_string()),
            owner: guid_into_uuid(ab.owner.expect("Invalid owner")).expect("Invalid GUID"),
            rule: 3,
            ..Default::default()
        };
        ab_shared_profiles.data.push(address_book);
    }
    Ok(Json(ab_shared_profiles))
}

async fn webconsole_index_multi() -> Redirect {
    Redirect::to(uri!("/ui/"))
}

#[openapi(tag = "webconsole")]
#[get("/index.html")]
async fn webconsole_index_html() -> Redirect {
    webconsole_index_multi().await
}

#[openapi(tag = "webconsole")]
#[get("/")]
async fn webconsole_index() -> Redirect {
    webconsole_index_multi().await
}

const STATIC_DIR: Dir = include_dir!("webconsole/dist");
#[derive(Debug)]
struct StaticFileResponse(Vec<u8>, ContentType);

#[async_trait]
impl<'r> Responder<'r, 'r> for StaticFileResponse {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .header(self.1)
            .header(Header {
                name: "Cache-Control".into(),
                value: "max-age=604800".into(), // 1 week
            })
            .sized_body(self.0.len(), Cursor::new(self.0))
            .ok()
    }
}

#[get("/js/sctgdesk-server.min.js")]
async fn openapi_snippet() -> Option<StaticFileResponse> {
    let content = include_str!("../rapidoc/dist/sctgdesk-server.min.js");
    Some(StaticFileResponse(
        content.as_bytes().to_vec(),
        ContentType::JavaScript,
    ))
}

#[get("/js/sctgdesk-server.min.js.map")]
async fn openapi_snippet_map() -> Option<StaticFileResponse> {
    let content = include_str!("../rapidoc/dist/sctgdesk-server.min.js.map");
    Some(StaticFileResponse(
        content.as_bytes().to_vec(),
        ContentType::JavaScript,
    ))
}

#[get("/favicon.ico")]
async fn favicon() -> Redirect {
    Redirect::to(uri!("/ui/favicon.ico"))
}

/// Retrieves a static file from the webconsole/dist directory
///
/// # Arguments
///
/// * `path` - the path to the file relative to the webconsole/dist directory
///
/// # Returns
///
/// * `Some(StaticFileResponse)` if the file exists, containing the file data and content type
/// * `None` if the file does not exist
#[get("/ui/<path..>")]
async fn webconsole_vue(path: PathBuf) -> Option<StaticFileResponse> {
    if env::var("VITE_DEVELOPMENT").is_ok() {
        let vite_base = env::var("VITE_DEVELOPMENT").unwrap_or("http://localhost:5173".to_string());
        let url = format!("{}/ui/{}", vite_base, path.to_str().unwrap_or(""));
        let response = reqwest::get(&url).await.unwrap();
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<ContentType>()
            .unwrap();
        let bytes = response.bytes().await.unwrap();
        let response_content: Vec<u8> = bytes.iter().map(|byte| *byte).collect();
        let content = StaticFileResponse(response_content, content_type);
        return Some(content);
    }

    let path = path.to_str().unwrap_or("");
    let file = STATIC_DIR.get_file(path).map(|file| {
        let content_type = ContentType::from_extension(
            file.path()
                .extension()
                .unwrap_or_default()
                .to_str()
                .unwrap(),
        )
        .unwrap_or(ContentType::Binary);
        StaticFileResponse(file.contents().to_vec(), content_type)
    });
    if file.is_some() {
        return file;
    } else {
        let file = STATIC_DIR.get_file("index.html").map(|file| {
            let content_type = ContentType::from_extension(
                file.path()
                    .extension()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap(),
            )
            .unwrap_or(ContentType::Binary);
            StaticFileResponse(file.contents().to_vec(), content_type)
        });
        return file;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::Client;

    #[test]
    fn database_url_is_required() {
        std::env::remove_var("DATABASE_URL");
        let err = database_url_from_env().unwrap_err();
        assert!(err.contains("DATABASE_URL"), "{err}");

        std::env::set_var("DATABASE_URL", "postgres://u:p@h/db");
        assert_eq!(database_url_from_env().unwrap(), "postgres://u:p@h/db");
        std::env::remove_var("DATABASE_URL");
    }

    async fn test_client() -> Client {
        let db_url = state::testing::fresh_database_url().await;
        let figment = rocket::Config::figment()
            .merge(("secret_key", "wJq+s/xvwZjmMX3ev0p4gQTs9Ej5wt0brsk3ZGhoBTg="));
        let rocket = build_rocket_with_db(figment, &db_url).await;
        Client::tracked(rocket).await.unwrap()
    }

    async fn login_admin(client: &Client) -> String {
        let resp = client
            .post("/api/login")
            .header(ContentType::JSON)
            .body(r#"{"username":"admin","password":"Hello,world!","id":"test","uuid":"test-uuid"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        body["access_token"].as_str().unwrap().to_string()
    }

    fn auth_header(token: &str) -> Header<'static> {
        Header::new("Authorization", format!("Bearer {}", token))
    }

    #[rocket::async_test]
    async fn test_login_success() {
        let client = test_client().await;
        let resp = client
            .post("/api/login")
            .header(ContentType::JSON)
            .body(r#"{"username":"admin","password":"Hello,world!","id":"test","uuid":"test-uuid"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert_eq!(body["type"], "access_token");
        assert!(body["access_token"].as_str().is_some());
        assert_eq!(body["user"]["name"], "admin");
    }

    #[rocket::async_test]
    async fn test_login_wrong_password() {
        let client = test_client().await;
        let resp = client
            .post("/api/login")
            .header(ContentType::JSON)
            .body(r#"{"username":"admin","password":"wrong","id":"test","uuid":"test-uuid"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn test_login_nonexistent_user() {
        let client = test_client().await;
        let resp = client
            .post("/api/login")
            .header(ContentType::JSON)
            .body(r#"{"username":"nobody","password":"pass","id":"test","uuid":"test-uuid"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn test_current_user_authenticated() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .post("/api/currentUser")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"id":"test","uuid":"test-uuid"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert_eq!(body["error"], false);
        assert_eq!(body["name"], "admin");
    }

    #[rocket::async_test]
    async fn test_current_user_unauthenticated() {
        let client = test_client().await;
        let resp = client
            .post("/api/currentUser")
            .header(ContentType::JSON)
            .body(r#"{"id":"test","uuid":"test-uuid"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn test_audit_no_auth_required() {
        let client = test_client().await;
        let resp = client
            .post("/api/audit")
            .header(ContentType::JSON)
            .body(r#"{"action":"test","id":"1","ip":"127.0.0.1"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_audit_conn_new() {
        let client = test_client().await;
        let resp = client
            .post("/api/audit/conn")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer1","uuid":"dXVpZA==","conn_id":1,"session_id":100,"nonce":"n1","ip":"10.0.0.1","action":"new"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body = resp.into_string().await.unwrap();
        assert!(!body.is_empty());
        let guid: String = serde_json::from_str(&body).unwrap();
        assert!(!guid.is_empty());
    }

    #[rocket::async_test]
    async fn test_audit_conn_close() {
        let client = test_client().await;
        let resp = client
            .post("/api/audit/conn")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer2","uuid":"dXVpZA==","conn_id":1,"session_id":200,"nonce":"n2","ip":"10.0.0.2","action":"new"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body = resp.into_string().await.unwrap();
        let guid: String = serde_json::from_str(&body).unwrap();

        let resp = client
            .post("/api/audit/conn")
            .header(ContentType::JSON)
            .body(format!(r#"{{"id":"peer2","uuid":"dXVpZA==","conn_id":1,"session_id":200,"nonce":"n3","ip":"10.0.0.2","action":"close","conn_audit_ref":"{}"}}"#, guid))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_audit_conn_active() {
        let client = test_client().await;
        let resp = client
            .post("/api/audit/conn")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer3","uuid":"dXVpZA==","conn_id":1,"session_id":300,"nonce":"n4","ip":"10.0.0.3","action":"new"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body = resp.into_string().await.unwrap();
        let expected_guid: String = serde_json::from_str(&body).unwrap();

        let resp = client
            .get("/api/audit/conn/active?id=peer3&session_id=300&conn_type=0")
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body = resp.into_string().await.unwrap();
        let guid: String = serde_json::from_str(&body).unwrap();
        assert_eq!(guid, expected_guid);
    }

    #[rocket::async_test]
    async fn test_audit_conn_accepts_u64_session_id() {
        // The client's session_id is a random u64; values above i64::MAX must not be rejected.
        let client = test_client().await;
        let resp = client
            .post("/api/audit/conn")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer_u64","uuid":"dXVpZA==","conn_id":1,"session_id":18446744073709551615,"nonce":"n_u64","ip":"10.0.0.9","action":"close"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_audit_file() {
        let client = test_client().await;
        let resp = client
            .post("/api/audit/file")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer4","uuid":"dXVpZA==","peer_id":"remote1","conn_id":1,"type":1,"path":"/tmp/file.txt","is_file":true,"info":"{}","nonce":"nf1"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_audit_alarm() {
        let client = test_client().await;
        let resp = client
            .post("/api/audit/alarm")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer5","uuid":"dXVpZA==","typ":1,"info":"{}","conn_id":1,"nonce":"na1"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_audit_conn_nonce_dedup() {
        let client = test_client().await;
        let resp = client
            .post("/api/audit/conn")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer6","uuid":"dXVpZA==","conn_id":1,"session_id":600,"nonce":"dedup1","ip":"10.0.0.6","action":"new"}"#)
            .dispatch()
            .await;
        let body1 = resp.into_string().await.unwrap();
        let guid1: String = serde_json::from_str(&body1).unwrap();

        let resp = client
            .post("/api/audit/conn")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer6","uuid":"dXVpZA==","conn_id":1,"session_id":600,"nonce":"dedup1","ip":"10.0.0.6","action":"new"}"#)
            .dispatch()
            .await;
        let body2 = resp.into_string().await.unwrap();
        let guid2: String = serde_json::from_str(&body2).unwrap();

        assert_eq!(guid1, guid2);
    }

    #[rocket::async_test]
    async fn test_audit_file_nonce_dedup() {
        let client = test_client().await;
        let resp = client
            .post("/api/audit/file")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer7","uuid":"dXVpZA==","peer_id":"remote7","conn_id":1,"type":1,"path":"/tmp/f.txt","is_file":true,"info":"{}","nonce":"fdedup1"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .post("/api/audit/file")
            .header(ContentType::JSON)
            .body(r#"{"id":"peer7","uuid":"dXVpZA==","peer_id":"remote7","conn_id":1,"type":1,"path":"/tmp/f.txt","is_file":true,"info":"{}","nonce":"fdedup1"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_heartbeat() {
        let client = test_client().await;
        let resp = client
            .post("/api/heartbeat")
            .header(ContentType::JSON)
            .body(r#"{"id":"test-peer","modified_at":0,"uuid":"test-uuid","ver":0}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body = resp.into_string().await.unwrap();
        assert_eq!(body, "OK");
    }

    #[rocket::async_test]
    async fn test_sysinfo_unknown_peer() {
        let client = test_client().await;
        let resp = client
            .post("/api/sysinfo")
            .header(ContentType::JSON)
            .body(r#"{"id":"unknown"}"#)
            .dispatch()
            .await;
        // No uuid means no peer can be matched.
        assert_eq!(resp.status(), Status::Ok);
        assert_eq!(resp.into_string().await.unwrap(), "ID_NOT_FOUND");
    }

    #[rocket::async_test]
    async fn test_logout() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .post("/api/logout")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"id":"device","uuid":"uuid"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_logout_unauthenticated() {
        let client = test_client().await;
        let resp = client
            .post("/api/logout")
            .header(ContentType::JSON)
            .body(r#"{"id":"device","uuid":"uuid"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn test_users_list_as_admin() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/user-list?current=1&pageSize=10")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert_eq!(body["msg"], "success");
        assert!(body["total"].as_u64().unwrap() >= 1);
    }

    #[rocket::async_test]
    async fn test_users_list_unauthenticated() {
        let client = test_client().await;
        let resp = client
            .get("/api/user-list?current=1&pageSize=10")
            .header(ContentType::JSON)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn test_groups_list_as_admin() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/groups?current=1&pageSize=10")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert_eq!(body["msg"], "success");
    }

    #[rocket::async_test]
    async fn test_group_crud() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        let resp = client
            .post("/api/group")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"name":"test-group","note":"a test group","allowed_outgoings":[],"allowed_incomings":[]}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .get("/api/groups?current=1&pageSize=100")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        let groups = body["data"].as_array().unwrap();
        let test_group = groups.iter().find(|g| g["name"] == "test-group");
        assert!(test_group.is_some(), "created group should appear in list");
        let guid = test_group.unwrap()["guid"].as_str().unwrap().to_string();

        let resp = client
            .get(format!("/api/group/{}", guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .put("/api/group")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(format!(
                r#"{{"guid":"{}","name":"renamed-group","note":"updated","allowed_outgoings":[],"allowed_incomings":[]}}"#,
                guid
            ))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .delete(format!("/api/group/{}", guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body("[]")
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_group_get_not_found() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/group/nonexistent-guid")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::NotFound);
    }

    #[rocket::async_test]
    async fn test_user_add_and_login() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        let resp = client
            .post("/api/user")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"name":"testuser","password":"testpass","confirm-password":"testpass","email":"test@example.com","is_admin":false,"group_name":"Default"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let login_resp = client
            .post("/api/login")
            .header(ContentType::JSON)
            .body(r#"{"username":"testuser","password":"testpass","id":"test","uuid":"test-uuid"}"#)
            .dispatch()
            .await;
        assert_eq!(login_resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_user_delete() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        let resp = client
            .post("/api/user")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"name":"deluser","password":"pass","confirm-password":"pass","email":"del@example.com","is_admin":false,"group_name":"Default"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let list_resp = client
            .get("/api/user-list?current=1&pageSize=100")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        let body: serde_json::Value = list_resp.into_json().await.unwrap();
        let users = body["data"].as_array().unwrap();
        let del_user = users.iter().find(|u| u["name"] == "deluser").unwrap();
        let guid = del_user["guid"].as_str().unwrap();

        let resp = client
            .delete("/api/user")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(format!(r#"{{"rows":["{}"]}}"#, guid))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_peers_empty_db() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/peers")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert!(resp.status() == Status::Ok || resp.status() == Status::NotFound);
    }

    #[rocket::async_test]
    async fn test_peers_count() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/peers/count/all")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert!(body["total"].as_u64().is_some());
    }

    #[rocket::async_test]
    async fn test_peers_count_by_platform() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        for platform in &["windows", "macos", "linux", "android"] {
            let resp = client
                .get(format!("/api/peers/count/{}", platform))
                .header(ContentType::JSON)
                .header(auth_header(&token))
                .dispatch()
                .await;
            assert_eq!(resp.status(), Status::Ok);
        }
    }

    #[rocket::async_test]
    async fn test_peers_cpus() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/peers/cpus")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_get_authenticated() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .post("/api/ab/get")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_personal() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .post("/api/ab/personal")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert!(body["guid"].as_str().is_some());
    }

    #[rocket::async_test]
    async fn test_ab_settings() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .post("/api/ab/settings")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_tag_lifecycle() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        let resp = client
            .post("/api/ab/personal")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        let body: serde_json::Value = resp.into_json().await.unwrap();
        let ab_guid = body["guid"].as_str().unwrap().to_string();

        let resp = client
            .post(format!("/api/ab/tag/add/{}", ab_guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"name":"test-tag","color":4278190335}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .put(format!("/api/ab/tag/update/{}", ab_guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"name":"test-tag","color":4294901760}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .put(format!("/api/ab/tag/rename/{}", ab_guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"old":"test-tag","new":"renamed-tag"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .delete(format!("/api/ab/tag/{}", ab_guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"["renamed-tag"]"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_options_cors() {
        let client = test_client().await;
        let resp = client
            .options("/api/login")
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let cors = resp.headers().get_one("Access-Control-Allow-Origin");
        assert_eq!(cors, Some("*"));
    }

    #[rocket::async_test]
    async fn test_login_options() {
        let client = test_client().await;
        let resp = client
            .get("/api/login-options")
            .header(ContentType::JSON)
            .dispatch()
            .await;
        assert!(resp.status() == Status::Ok || resp.status() == Status::Unauthorized);
        if resp.status() == Status::Ok {
            let body: serde_json::Value = resp.into_json().await.unwrap();
            assert!(body.is_array());
        }
    }

    #[rocket::async_test]
    async fn test_strategies() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/stategies")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert_eq!(body["msg"], "success");
    }

    #[rocket::async_test]
    async fn test_ab_legacy_set() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .post("/api/ab")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"data":"{\"tags\":[],\"peers\":[]}"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_legacy_get() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/ab")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_shared_profiles() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .post("/api/ab/shared/profiles")
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_peers_query() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        let ab_resp = client
            .post("/api/ab/personal")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        let body: serde_json::Value = ab_resp.into_json().await.unwrap();
        let ab_guid = body["guid"].as_str().unwrap();

        let resp = client
            .post(format!("/api/ab/peers?current=1&pageSize=10&ab={}", ab_guid))
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_peer_crud() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        let ab_resp = client
            .post("/api/ab/personal")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        let body: serde_json::Value = ab_resp.into_json().await.unwrap();
        let ab_guid = body["guid"].as_str().unwrap().to_string();

        let resp = client
            .post(format!("/api/ab/peer/add/{}", ab_guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"id":"test-peer-1"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .put(format!("/api/ab/peer/update/{}", ab_guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"id":"test-peer-1","alias":"Updated Peer","hostname":"testhost"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .delete(format!("/api/ab/peer/{}", ab_guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"["test-peer-1"]"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_tags_list() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        let ab_resp = client
            .post("/api/ab/personal")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        let body: serde_json::Value = ab_resp.into_json().await.unwrap();
        let ab_guid = body["guid"].as_str().unwrap();

        let resp = client
            .post(format!("/api/ab/tags/{}", ab_guid))
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_rules_crud() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        let ab_resp = client
            .post("/api/ab/personal")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        let body: serde_json::Value = ab_resp.into_json().await.unwrap();
        let ab_guid = body["guid"].as_str().unwrap().to_string();

        let resp = client
            .get(format!("/api/ab/rules?current=1&pageSize=10&ab={}", ab_guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .post("/api/ab/rule")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(format!(r#"{{"guid":"{}","user":null,"group":null,"rule":3}}"#, ab_guid))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let rules_resp = client
            .get(format!("/api/ab/rules?current=1&pageSize=10&ab={}", ab_guid))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        let rules_body: serde_json::Value = rules_resp.into_json().await.unwrap();
        if let Some(rules) = rules_body["data"].as_array() {
            if let Some(rule) = rules.first() {
                let rule_guid = rule["guid"].as_str().unwrap_or("");
                if !rule_guid.is_empty() {
                    let resp = client
                        .delete("/api/ab/rule")
                        .header(ContentType::JSON)
                        .header(auth_header(&token))
                        .body(format!(r#"{{"guid":"{}"}}"#, rule_guid))
                        .dispatch()
                        .await;
                    assert_eq!(resp.status(), Status::Ok);
                }
            }
        }
    }

    /// Create a non-admin user and log in; returns (token, user guid).
    async fn create_user_and_login(client: &Client, admin_token: &str, name: &str) -> (String, String) {
        let resp = client
            .post("/api/user")
            .header(ContentType::JSON)
            .header(auth_header(admin_token))
            .body(format!(r#"{{"name":"{name}","password":"pass","confirm-password":"pass","email":"{name}@example.com","is_admin":false,"group_name":"Default"}}"#))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let resp = client
            .post("/api/login")
            .header(ContentType::JSON)
            .body(format!(r#"{{"username":"{name}","password":"pass","id":"{name}","uuid":"{name}-uuid"}}"#))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        let token = body["access_token"].as_str().unwrap().to_string();
        let resp = client
            .get("/api/user-list?current=1&pageSize=100")
            .header(ContentType::JSON)
            .header(auth_header(admin_token))
            .dispatch()
            .await;
        let body: serde_json::Value = resp.into_json().await.unwrap();
        let guid = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["name"] == name)
            .unwrap()["guid"]
            .as_str()
            .unwrap()
            .to_string();
        (token, guid)
    }

    async fn personal_ab(client: &Client, token: &str) -> String {
        let resp = client
            .post("/api/ab/personal")
            .header(auth_header(token))
            .dispatch()
            .await;
        let body: serde_json::Value = resp.into_json().await.unwrap();
        body["guid"].as_str().unwrap().to_string()
    }

    async fn ab_call(
        client: &Client,
        token: &str,
        method: rocket::http::Method,
        uri: String,
        body: &str,
    ) -> Status {
        client
            .req(method, uri)
            .header(ContentType::JSON)
            .header(auth_header(token))
            .body(body.to_string())
            .dispatch()
            .await
            .status()
    }

    #[rocket::async_test]
    async fn test_ab_other_users_personal_ab_is_forbidden() {
        use rocket::http::Method::*;
        let client = test_client().await;
        let admin = login_admin(&client).await;
        let (owner, _) = create_user_and_login(&client, &admin, "abowner").await;
        let (other, _) = create_user_and_login(&client, &admin, "abother").await;
        let ab = personal_ab(&client, &owner).await;
        assert_eq!(ab_call(&client, &owner, Post, format!("/api/ab/peer/add/{ab}"), r#"{"id":"p1"}"#).await, Status::Ok);
        assert_eq!(ab_call(&client, &owner, Post, format!("/api/ab/tag/add/{ab}"), r#"{"name":"t1","color":1}"#).await, Status::Ok);

        let calls = [
            (Post, format!("/api/ab/peers?current=1&pageSize=10&ab={ab}"), ""),
            (Post, format!("/api/ab/tags/{ab}"), ""),
            (Get, format!("/api/ab/rules?current=1&pageSize=10&ab={ab}"), ""),
            (Post, format!("/api/ab/peer/add/{ab}"), r#"{"id":"intruder"}"#),
            (Put, format!("/api/ab/peer/update/{ab}"), r#"{"id":"p1","alias":"x"}"#),
            (Delete, format!("/api/ab/peer/{ab}"), r#"["p1"]"#),
            (Post, format!("/api/ab/tag/add/{ab}"), r#"{"name":"t2","color":1}"#),
            (Put, format!("/api/ab/tag/update/{ab}"), r#"{"name":"t1","color":2}"#),
            (Put, format!("/api/ab/tag/rename/{ab}"), r#"{"old":"t1","new":"t2"}"#),
            (Delete, format!("/api/ab/tag/{ab}"), r#"["t1"]"#),
        ];
        for (method, uri, body) in calls {
            assert_eq!(ab_call(&client, &other, method, uri.clone(), body).await, Status::Forbidden, "{method} {uri}");
        }
    }

    #[rocket::async_test]
    async fn test_ab_shared_access_follows_rules() {
        use rocket::http::Method::*;
        let client = test_client().await;
        let admin = login_admin(&client).await;
        let (user, user_guid) = create_user_and_login(&client, &admin, "abshareuser").await;
        let resp = client
            .post("/api/ab/shared/add")
            .header(ContentType::JSON)
            .header(auth_header(&admin))
            .body(r#"{"name":"acl-shared"}"#)
            .dispatch()
            .await;
        let body: serde_json::Value = resp.into_json().await.unwrap();
        let ab = body["data"][0]["guid"].as_str().unwrap().to_string();
        let peers = format!("/api/ab/peers?current=1&pageSize=10&ab={ab}");
        let add = format!("/api/ab/peer/add/{ab}");

        assert_eq!(ab_call(&client, &user, Post, peers.clone(), "").await, Status::Forbidden);

        let rule = |r: u32| format!(r#"{{"guid":"{ab}","user":"{user_guid}","rule":{r}}}"#);
        assert_eq!(ab_call(&client, &admin, Post, "/api/ab/rule".into(), &rule(1)).await, Status::Ok);
        assert_eq!(ab_call(&client, &user, Post, peers.clone(), "").await, Status::Ok);
        assert_eq!(ab_call(&client, &user, Post, add.clone(), r#"{"id":"ro"}"#).await, Status::Forbidden);

        assert_eq!(ab_call(&client, &admin, Post, "/api/ab/rule".into(), &rule(2)).await, Status::Ok);
        assert_eq!(ab_call(&client, &user, Post, add, r#"{"id":"rw"}"#).await, Status::Ok);
    }

    #[rocket::async_test]
    async fn test_ab_shared_profiles_report_granted_rule() {
        let client = test_client().await;
        let admin = login_admin(&client).await;
        let (user, user_guid) = create_user_and_login(&client, &admin, "abprofileuser").await;
        let resp = client
            .post("/api/ab/shared/add")
            .header(ContentType::JSON)
            .header(auth_header(&admin))
            .body(r#"{"name":"ro-shared"}"#)
            .dispatch()
            .await;
        let body: serde_json::Value = resp.into_json().await.unwrap();
        let ab = body["data"][0]["guid"].as_str().unwrap().to_string();
        let rule = format!(r#"{{"guid":"{ab}","user":"{user_guid}","rule":1}}"#);
        assert_eq!(ab_call(&client, &admin, rocket::http::Method::Post, "/api/ab/rule".into(), &rule).await, Status::Ok);

        let resp = client
            .post("/api/ab/shared/profiles")
            .header(auth_header(&user))
            .dispatch()
            .await;
        let body: serde_json::Value = resp.into_json().await.unwrap();
        let profile = body["data"].as_array().unwrap().iter().find(|p| p["guid"] == ab.as_str()).unwrap();
        assert_eq!(profile["rule"], 1);
    }

    #[rocket::async_test]
    async fn test_ab_shared_crud() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        let resp = client
            .post("/api/ab/shared/add")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"name":"test-shared-ab"}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        let shared_guid = body["guid"].as_str().unwrap_or("").to_string();

        if !shared_guid.is_empty() {
            let resp = client
                .put("/api/ab/shared/update/profile")
                .header(ContentType::JSON)
                .header(auth_header(&token))
                .body(format!(r#"{{"guid":"{}","name":"renamed-shared-ab"}}"#, shared_guid))
                .dispatch()
                .await;
            assert_eq!(resp.status(), Status::Ok);

            let resp = client
                .delete("/api/ab/shared")
                .header(ContentType::JSON)
                .header(auth_header(&token))
                .body(format!(r#"["{}"]"#, shared_guid))
                .dispatch()
                .await;
            assert_eq!(resp.status(), Status::Ok);
        }
    }

    #[rocket::async_test]
    async fn test_user_enable_disable() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        client
            .post("/api/user")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"name":"toggleuser","password":"pass","confirm-password":"pass","email":"toggle@example.com","is_admin":false,"group_name":"Default"}"#)
            .dispatch()
            .await;

        let list_resp = client
            .get("/api/user-list?current=1&pageSize=100")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        let body: serde_json::Value = list_resp.into_json().await.unwrap();
        let users = body["data"].as_array().unwrap();
        let user = users.iter().find(|u| u["name"] == "toggleuser").unwrap();
        let guid = user["guid"].as_str().unwrap().to_string();

        let resp = client
            .post("/api/enable-users")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(format!(r#"{{"rows":["{}"],"disable":true}}"#, guid))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .post("/api/enable-users")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(format!(r#"{{"rows":["{}"],"disable":false}}"#, guid))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_user_update() {
        let client = test_client().await;
        let token = login_admin(&client).await;

        client
            .post("/api/user")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"name":"updateuser","password":"pass","confirm-password":"pass","email":"upd@example.com","is_admin":false,"group_name":"Default"}"#)
            .dispatch()
            .await;

        let list_resp = client
            .get("/api/user-list?current=1&pageSize=100")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        let body: serde_json::Value = list_resp.into_json().await.unwrap();
        let users = body["data"].as_array().unwrap();
        let user = users.iter().find(|u| u["name"] == "updateuser").unwrap();
        let guid = user["guid"].as_str().unwrap().to_string();

        let resp = client
            .put("/api/user")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(format!(r#"{{"uuid":"{}","name":"updateduser","email":"new@example.com"}}"#, guid))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_users_client_endpoint() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/users?current=1&pageSize=10")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert_eq!(body["msg"], "success");
    }

    #[rocket::async_test]
    async fn test_oidc_settings_add() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .put("/api/oidc/settings")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(r#"{"rows":[],"disable":false}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn test_oidc_settings_get() {
        let client = test_client().await;
        let token = login_admin(&client).await;
        let resp = client
            .get("/api/oidc/settings")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn test_oidc_auth_invalid_uuid() {
        let client = test_client().await;
        let resp = client
            .post("/api/oidc/auth")
            .header(ContentType::JSON)
            .body(r#"{"op":"test","id":"test","uuid":"not-base64!!!","deviceInfo":{"name":"t","os":"t","type":"t"}}"#)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert_eq!(body["code"], "UUID_ERROR");
    }

    #[rocket::async_test]
    async fn test_oidc_auth_no_provider() {
        let client = test_client().await;
        let uuid_b64 = base64::prelude::BASE64_STANDARD.encode("test-uuid-value");
        let resp = client
            .post("/api/oidc/auth")
            .header(ContentType::JSON)
            .body(format!(
                r#"{{"op":"nonexistent","id":"test","uuid":"{}","deviceInfo":{{"name":"t","os":"t","type":"t"}}}}"#,
                uuid_b64
            ))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert!(body["url"].as_str().unwrap().is_empty());
    }

    #[rocket::async_test]
    async fn test_oidc_callback_invalid_session() {
        let client = test_client().await;
        let resp = client
            .get("/api/oidc/callback?code=fake-code&state=fake-state")
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body = resp.into_string().await.unwrap();
        assert!(body.contains("Login failed"));
    }

    #[rocket::async_test]
    async fn test_oidc_state_invalid_session() {
        let client = test_client().await;
        let resp = client
            .get("/api/oidc/auth-query?code=fake&id=fake&uuid=fake")
            .header(ContentType::JSON)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().await.unwrap();
        assert!(body.is_null());
    }

    #[rocket::async_test]
    async fn test_software_no_s3_config() {
        let client = test_client().await;
        let resp = client
            .get("/api/software/client-download-link/windows/x86_64")
            .header(ContentType::JSON)
            .dispatch()
            .await;
        // Without S3 config, this will error
        assert!(resp.status() == Status::NotFound || resp.status() == Status::InternalServerError);
    }

    #[rocket::async_test]
    async fn test_software_version() {
        let client = test_client().await;
        let resp = client
            .get("/api/software/version/server")
            .header(ContentType::JSON)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_webconsole_index_redirect() {
        let client = test_client().await;
        let resp = client.get("/").dispatch().await;
        assert_eq!(resp.status(), Status::SeeOther);
    }

    #[rocket::async_test]
    async fn test_webconsole_index_html_redirect() {
        let client = test_client().await;
        let resp = client.get("/index.html").dispatch().await;
        assert_eq!(resp.status(), Status::SeeOther);
    }

    #[rocket::async_test]
    async fn test_favicon_redirect() {
        let client = test_client().await;
        let resp = client.get("/favicon.ico").dispatch().await;
        assert_eq!(resp.status(), Status::SeeOther);
    }

    #[rocket::async_test]
    async fn test_openapi_json() {
        let client = test_client().await;
        let resp = client.get("/openapi.json").dispatch().await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_webconsole_static_files() {
        let client = test_client().await;
        let resp = client.get("/ui/index.html").dispatch().await;
        // Returns the static file or fallback
        assert!(resp.status() == Status::Ok || resp.status() == Status::NotFound);
    }

    #[rocket::async_test]
    async fn test_openapi_snippet_js() {
        let client = test_client().await;
        let resp = client.get("/js/sctgdesk-server.min.js").dispatch().await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_openapi_snippet_map() {
        let client = test_client().await;
        let resp = client.get("/js/sctgdesk-server.min.js.map").dispatch().await;
        assert_eq!(resp.status(), Status::Ok);
    }
}
