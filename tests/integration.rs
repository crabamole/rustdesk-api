use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use rustdesk_api::build_rocket_with_db;
use serde_json::Value;

async fn test_client() -> (Client, ()) {
    let db_url = state::testing::fresh_database_url().await;
    let figment = rocket::Config::figment()
        .merge(("port", 0))
        .merge(("secret_key", "hPRYyVRiMyxpw5sBB1XeCMN1kFsDCqKvBi2QJxBVHQk="));
    let rocket = build_rocket_with_db(figment, &db_url).await;
    (Client::tracked(rocket).await.unwrap(), ())
}

/// Session for `name` as if it had logged in through OIDC.
async fn oidc_token(client: &Client, name: &str) -> String {
    let state = client.rocket().state::<state::ApiState>().unwrap();
    let (_, token) = state.test_oidc_login(&name.to_string()).await.unwrap();
    token.to_base64()
}

async fn login_admin(client: &Client) -> String {
    let state = client.rocket().state::<state::ApiState>().unwrap();
    state.test_oidc_login(&"admin".to_string()).await;
    state.set_admin("admin@example.org", true).await.unwrap();
    oidc_token(client, "admin").await
}

fn auth_header(token: &str) -> Header<'static> {
    Header::new("Authorization", format!("Bearer {}", token))
}

#[rocket::async_test]
async fn test_password_login_is_rejected_for_the_admin() {
    let (client, _dir) = test_client().await;
    login_admin(&client).await;
    let resp = client
        .post("/api/login")
        .header(ContentType::JSON)
        .body(r#"{"username":"admin","password":"Hello,world!","id":"test","uuid":"test"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_login_wrong_password() {
    let (client, _dir) = test_client().await;
    let resp = client
        .post("/api/login")
        .header(ContentType::JSON)
        .body(r#"{"username":"admin","password":"wrong","id":"test","uuid":"test"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_login_unknown_user() {
    let (client, _dir) = test_client().await;
    let resp = client
        .post("/api/login")
        .header(ContentType::JSON)
        .body(r#"{"username":"nobody","password":"x","id":"test","uuid":"test"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_current_user() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .post("/api/currentUser")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"id":"test","uuid":"test"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["error"], false);
    assert_eq!(body["name"], "admin");
}

#[rocket::async_test]
async fn test_current_user_no_auth() {
    let (client, _dir) = test_client().await;
    let resp = client
        .post("/api/currentUser")
        .header(ContentType::JSON)
        .body(r#"{"id":"test","uuid":"test"}"#)
        .dispatch()
        .await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);
}

#[rocket::async_test]
async fn test_logout() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .post("/api/logout")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"id":"test","uuid":"test"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .post("/api/currentUser")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"id":"test","uuid":"test"}"#)
        .dispatch()
        .await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);
}

const DEFAULT_STRATEGY: &str = "018f2556-2316-7a02-b31c-5599e7cd5b5e";

async fn heartbeat(client: &Client, modified_at: i64) -> Value {
    let resp = client
        .post("/api/heartbeat")
        .header(ContentType::JSON)
        .body(format!(r#"{{"id":"test123","modified_at":{modified_at},"uuid":"abc","ver":1}}"#))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    resp.into_json().await.unwrap()
}

async fn set_policy(client: &Client, options: &[(&str, &str)]) -> i64 {
    let state = client.rocket().state::<state::ApiState>().unwrap();
    let options = options.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    state.set_strategy_options(DEFAULT_STRATEGY, &options).await.unwrap()
}

#[rocket::async_test]
async fn test_heartbeat_accepts_live_connections() {
    let (client, _dir) = test_client().await;
    let resp = client
        .post("/api/heartbeat")
        .header(ContentType::JSON)
        .body(r#"{"id":"test123","modified_at":0,"uuid":"abc","ver":1,"conns":[3,7]}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_heartbeat_sends_policy_when_device_is_behind() {
    let (client, _dir) = test_client().await;
    let m = set_policy(&client, &[("enable-clipboard", "N"), ("enable-audio", "")]).await;
    let body = heartbeat(&client, 0).await;
    assert_eq!(body["modified_at"], m);
    assert_eq!(body["strategy"]["config_options"], serde_json::json!({"enable-clipboard": "N", "enable-audio": ""}));
}

#[rocket::async_test]
async fn test_heartbeat_omits_policy_when_device_is_current() {
    let (client, _dir) = test_client().await;
    let m = set_policy(&client, &[("enable-clipboard", "N")]).await;
    let body = heartbeat(&client, m).await;
    assert_eq!(body, serde_json::json!({"modified_at": m}));
}

#[rocket::async_test]
async fn test_heartbeat_never_sends_keys_outside_the_allow_list() {
    let (client, _dir) = test_client().await;
    let state = client.rocket().state::<state::ApiState>().unwrap();
    // Bypasses API validation, as a hand-edited database would.
    let planted = [("api-server".to_string(), "http://evil".to_string()), ("enable-camera".to_string(), "N".to_string())].into();
    state.set_strategy_options(DEFAULT_STRATEGY, &planted).await.unwrap();
    let body = heartbeat(&client, 0).await;
    assert_eq!(body["strategy"]["config_options"], serde_json::json!({"enable-camera": "N"}));
}

#[rocket::async_test]
async fn test_sysinfo() {
    let (client, _dir) = test_client().await;
    let resp = client
        .post("/api/sysinfo")
        .header(ContentType::JSON)
        .body(r#"{"id":"test123","uuid":"abc","hostname":"testhost","username":"user","os":"linux","cpu":"x86","memory":"8GB","version":"1.0.0","ip":"1.2.3.4"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_string().await.unwrap();
    // "abc" is not valid padded base64, so no peer can match it.
    assert_eq!(body, "ID_NOT_FOUND");
}

#[rocket::async_test]
async fn test_sysinfo_unknown_or_missing_uuid() {
    let (client, _dir) = test_client().await;
    for body in [
        r#"{"id":"x","uuid":"dW5rbm93bi1wZWVy","hostname":"h"}"#,
        r#"{"id":"x","hostname":"h"}"#,
    ] {
        let resp = client
            .post("/api/sysinfo")
            .header(ContentType::JSON)
            .body(body)
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok, "{body}");
        assert_eq!(resp.into_string().await.unwrap(), "ID_NOT_FOUND", "{body}");
    }
}

#[rocket::async_test]
async fn test_audit() {
    let (client, _dir) = test_client().await;
    let resp = client
        .post("/api/audit")
        .header(ContentType::JSON)
        .body(r#"{"action":"test","id":"test","ip":"1.2.3.4","uuid":"abc","conn_id":1}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_audit_file_answers_empty_when_stored() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("d", "dQ==").await;
    let resp = client.post("/api/audit/file").header(ContentType::JSON)
        .body(r#"{"id":"d","uuid":"dQ==","peer_id":"p","conn_id":1,"type":0,"path":"","is_file":false,"info":"{}","nonce":"x1"}"#)
        .dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    assert_eq!(resp.into_string().await.unwrap_or_default(), "");
}

#[rocket::async_test]
async fn test_audit_alarm_answers_empty_when_stored() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("d", "dQ==").await;
    let resp = client.post("/api/audit/alarm").header(ContentType::JSON)
        .body(r#"{"id":"d","uuid":"dQ==","typ":1,"info":"{}","conn_id":1,"nonce":"x2"}"#)
        .dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    assert_eq!(resp.into_string().await.unwrap_or_default(), "");
}

#[rocket::async_test]
async fn test_audit_ref_requires_login() {
    let (client, _dir) = test_client().await;
    let resp = client.post("/api/audit/ref?target=dev1").dispatch().await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);
}

#[rocket::async_test]
async fn test_audit_ref_is_minted_for_the_caller() {
    let (client, _dir) = test_client().await;
    let state = client.rocket().state::<state::ApiState>().unwrap();
    // A plain (non-admin) logged-in user: created inactive, then activated and demoted.
    state.test_oidc_login(&"alice".to_string()).await;
    state.set_admin("alice@example.org", true).await.unwrap();
    state.set_admin("alice@example.org", false).await.unwrap();
    let token = oidc_token(&client, "alice").await;
    let resp = client.post("/api/audit/ref?target=dev1").header(auth_header(&token)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    let r = body["ref"].as_str().unwrap().to_string();
    assert!(state.resolve_audit_conn_ref(&r, "dev1").await.is_some());
    assert!(state.resolve_audit_conn_ref(&r, "dev2").await.is_none(), "bound to its target");
    let resp = client.post("/api/audit/ref").header(auth_header(&token)).dispatch().await;
    assert_eq!(resp.status(), Status::UnprocessableEntity, "the target is required");
    let resp = client.post("/api/audit/ref?target=").header(auth_header(&token)).dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest);
}

#[rocket::async_test]
async fn test_audit_conn_active_requires_auth() {
    let (client, _dir) = test_client().await;
    let resp = client
        .get("/api/audit/conn/active?id=dev&session_id=1&conn_type=0")
        .dispatch()
        .await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);
}

#[rocket::async_test]
async fn test_audit_conn_active_and_note() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devX", "dVg=").await;
    let state = client.rocket().state::<state::ApiState>().unwrap();
    // A plain (non-admin) logged-in user: created inactive, then activated and demoted.
    state.test_oidc_login(&"ivy".to_string()).await;
    state.set_admin("ivy@example.org", true).await.unwrap();
    state.set_admin("ivy@example.org", false).await.unwrap();
    let token = oidc_token(&client, "ivy").await;

    let resp = client.post("/api/audit/ref?target=devX").header(auth_header(&token)).dispatch().await;
    let body: Value = resp.into_json().await.unwrap();
    let conn_ref = body["ref"].as_str().unwrap().to_string();

    let resp = client
        .post("/api/audit/conn")
        .header(ContentType::JSON)
        .body(format!(
            r#"{{"action":"new","id":"devX","uuid":"dVg=","conn_id":1,"session_id":99,"nonce":"nA","conn_audit_ref":"{conn_ref}"}}"#
        ))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let resp = client
        .post("/api/audit/conn")
        .header(ContentType::JSON)
        .body(r#"{"peer":["v1","Viewer"],"type":0,"id":"devX","uuid":"dVg=","conn_id":1,"session_id":99,"nonce":"nB"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .get("/api/audit/conn/active?id=devX&session_id=99&conn_type=0")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let guid: String = resp.into_json().await.unwrap();
    assert!(!guid.is_empty());

    // bad guid -> 400
    let resp = client
        .put("/api/audit")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"guid":"xyz","note":"n"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest);

    // no token -> 401/403
    let resp = client
        .put("/api/audit")
        .header(ContentType::JSON)
        .body(format!(r#"{{"guid":"{guid}","note":"n"}}"#))
        .dispatch()
        .await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);

    // owner -> 200, note lands on the row
    let resp = client
        .put("/api/audit")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(r#"{{"guid":"{guid}","note":"end note"}}"#))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    assert_eq!(state.audit_conn_note_for_test("devX").await.as_deref(), Some("end note"));
}

#[rocket::async_test]
async fn test_users_list() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .get("/api/user-list?current=1&pageSize=10")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["msg"], "success");
    assert!(body["total"].as_u64().unwrap() >= 1);
}

#[rocket::async_test]
async fn test_users_list_no_auth() {
    let (client, _dir) = test_client().await;
    let resp = client
        .get("/api/user-list?current=1&pageSize=10")
        .header(ContentType::JSON)
        .dispatch()
        .await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);
}

#[rocket::async_test]
async fn test_users_client_endpoint() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .get("/api/users?current=1&pageSize=10")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["msg"], "success");
}

#[rocket::async_test]
async fn test_user_add_and_delete() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;

    let resp = client
        .post("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"name":"testuser","password":"Test1234!","confirm-password":"Test1234!","email":"test@test.com","is_admin":false,"group_name":"Default"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["msg"], "success");

    let resp = client
        .get("/api/user-list?current=1&pageSize=10&name=testuser")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert!(body["total"].as_u64().unwrap() >= 1);
    let user_uuid = body["data"][0]["guid"].as_str().unwrap().to_string();

    let resp = client
        .delete("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(r#"{{"rows":["{}"]}}"#, user_uuid))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["msg"], "success");
    assert_eq!(body["total"], 1);
}

#[rocket::async_test]
async fn test_user_add_ignores_legacy_password_fields() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    // Old callers may still send (even mismatched) passwords; they are ignored.
    let resp = client
        .post("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"name":"legacy","password":"a","confirm-password":"b","email":"legacy@example.com","is_admin":false,"group_name":"Default"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["msg"], "success");
    assert!(find_user(&client, &token, "legacy").await.is_some());
}

#[rocket::async_test]
async fn test_enable_disable_user() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;

    client
        .post("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"name":"enabletest","password":"Pass1234!","confirm-password":"Pass1234!","email":"enable@test.com","is_admin":false,"group_name":"Default"}"#)
        .dispatch()
        .await;

    let resp = client
        .get("/api/user-list?current=1&pageSize=10&name=enabletest")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let uuid = body["data"][0]["guid"].as_str().unwrap().to_string();

    let resp = client
        .post("/api/enable-users")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(r#"{{"rows":["{}"],"disable":true}}"#, uuid))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["msg"], "success");
}

#[rocket::async_test]
async fn test_groups_pages_do_not_overlap() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    for i in 0..5 {
        let resp = client
            .post("/api/group")
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .body(format!(r#"{{"name":"G{i}","note":"","allowed_outgoings":[],"allowed_incomings":[]}}"#))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }
    let resp = client
        .get("/api/groups?current=1&pageSize=100")
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let mut all: Vec<String> = body["data"].as_array().unwrap().iter()
        .map(|g| g["guid"].as_str().unwrap().to_string()).collect();
    assert!(all.len() >= 6);

    let mut paged = Vec::new();
    for page in 1..=all.len().div_ceil(2) {
        let resp = client
            .get(format!("/api/groups?current={page}&pageSize=2"))
            .header(auth_header(&token))
            .dispatch()
            .await;
        let body: Value = resp.into_json().await.unwrap();
        let data = body["data"].as_array().unwrap();
        assert!(data.len() <= 2, "page {page} has {} groups", data.len());
        paged.extend(data.iter().map(|g| g["guid"].as_str().unwrap().to_string()));
    }
    all.sort();
    paged.sort();
    assert_eq!(paged, all, "pages must list every group exactly once");
}

#[rocket::async_test]
async fn test_groups_crud() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;

    let resp = client
        .get("/api/groups?current=1&pageSize=10")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["msg"], "success");
    assert!(body["total"].as_u64().unwrap() >= 1);

    let resp = client
        .post("/api/group")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"name":"TestGroup","note":"a test group","allowed_outgoings":[],"allowed_incomings":[]}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .get("/api/groups?current=1&pageSize=10")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let groups = body["data"].as_array().unwrap();
    let test_group = groups.iter().find(|g| g["name"] == "TestGroup");
    assert!(test_group.is_some());
    let group_guid = test_group.unwrap()["guid"].as_str().unwrap().to_string();

    let resp = client
        .get(format!("/api/group/{}", group_guid))
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
            r#"{{"guid":"{}","name":"RenamedGroup","note":"updated","allowed_outgoings":[],"allowed_incomings":[]}}"#,
            group_guid
        ))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .delete(format!("/api/group/{}", group_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"[]"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_peers_list() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .get("/api/peers")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    // Could be Ok or NotFound depending on whether peers exist
    assert!(resp.status() == Status::Ok || resp.status() == Status::NotFound);
}

#[rocket::async_test]
async fn test_peers_count() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    for platform in &["all", "windows", "mac", "linux", "android", "unknown"] {
        let resp = client
            .get(format!("/api/peers/count/{}", platform))
            .header(ContentType::JSON)
            .header(auth_header(&token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body: Value = resp.into_json().await.unwrap();
        assert!(body["total"].as_u64().is_some());
    }
}

#[rocket::async_test]
async fn test_peers_cpus() {
    let (client, _dir) = test_client().await;
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
async fn test_ab_personal() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .post("/api/ab/personal")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert!(body["guid"].as_str().unwrap().len() > 0);
}

#[rocket::async_test]
async fn test_ab_settings() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .post("/api/ab/settings")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert!(body["max_peer_one_ab"].as_u64().unwrap() > 0);
}

#[rocket::async_test]
async fn test_ab_legacy_get_set() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;

    let resp = client
        .get("/api/ab")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .post("/api/ab/get")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .post("/api/ab")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"data":"{\"peers\":[],\"tags\":[]}"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_ab_peer_crud() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;

    let resp = client
        .post("/api/ab/personal")
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let ab_guid = body["guid"].as_str().unwrap();

    let resp = client
        .post(format!("/api/ab/peer/add/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"id":"peer001","hostname":"myhost","platform":"linux","username":"user1"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .post(format!(
            "/api/ab/peers?current=1&pageSize=10&ab={}",
            ab_guid
        ))
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert!(body["total"].as_u64().unwrap() >= 1);

    let resp = client
        .put(format!("/api/ab/peer/update/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"id":"peer001","hostname":"updated-host"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .delete(format!("/api/ab/peer/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"["peer001"]"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_ab_peer_delete_empty() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .post("/api/ab/personal")
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let ab_guid = body["guid"].as_str().unwrap();

    let resp = client
        .delete(format!("/api/ab/peer/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"[]"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_ab_tag_crud() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .post("/api/ab/personal")
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let ab_guid = body["guid"].as_str().unwrap();

    let resp = client
        .post(format!("/api/ab/tag/add/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"name":"testtag","color":16711680}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .post(format!("/api/ab/tags/{}", ab_guid))
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    let tags = body.as_array().unwrap();
    assert!(tags.iter().any(|t| t["name"] == "testtag"));

    let resp = client
        .put(format!("/api/ab/tag/update/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"name":"testtag","color":255}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .put(format!("/api/ab/tag/rename/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"old":"testtag","new":"renamedtag"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .delete(format!("/api/ab/tag/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"["renamedtag"]"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_ab_tag_delete_empty() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .post("/api/ab/personal")
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let ab_guid = body["guid"].as_str().unwrap();

    let resp = client
        .delete(format!("/api/ab/tag/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"[]"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_ab_tag_rename_nonexistent() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .post("/api/ab/personal")
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let ab_guid = body["guid"].as_str().unwrap();

    let resp = client
        .put(format!("/api/ab/tag/rename/{}", ab_guid))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"old":"nonexistent","new":"whatever"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_ab_shared_crud() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;

    let resp = client
        .post("/api/ab/shared/profiles")
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert!(body["total"].as_u64().is_some());

    let resp = client
        .post("/api/ab/shared/add")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"name":"Shared Test AB","note":"test note"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    let shared_guid = body["data"][0]["guid"].as_str().unwrap().to_string();

    let resp = client
        .put("/api/ab/shared/update/profile")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(
            r#"{{"guid":"{}","name":"Renamed Shared AB"}}"#,
            shared_guid
        ))
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

#[rocket::async_test]
async fn test_ab_rules_crud() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;

    let resp = client
        .post("/api/ab/shared/profiles")
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let shared_ab = body["data"]
        .as_array()
        .unwrap()
        .first()
        .unwrap()["guid"]
        .as_str()
        .unwrap();

    let resp = client
        .get(format!(
            "/api/ab/rules?current=1&pageSize=10&ab={}",
            shared_ab
        ))
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .post("/api/ab/rule")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(
            r#"{{"guid":"{}","user":"","group":"","rule":1}}"#,
            shared_ab
        ))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client
        .delete("/api/ab/rule")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(r#"{{"guid":"{}"}}"#, shared_ab))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_strategies() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client.get("/api/strategies").header(ContentType::JSON).header(auth_header(&token)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body[0]["guid"], DEFAULT_STRATEGY);
    assert_eq!(body[0]["name"], "Default");
}

#[rocket::async_test]
async fn test_strategy_get_update_repush() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let path = format!("/api/strategies/{DEFAULT_STRATEGY}");

    let resp = client.get(&path).header(ContentType::JSON).header(auth_header(&token)).dispatch().await;
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["options"], serde_json::json!({}));
    assert_eq!(body["keys"].as_array().unwrap().len(), 15);

    let resp = client.put(&path).header(ContentType::JSON).header(auth_header(&token))
        .body(r#"{"options":{"enable-clipboard":"N","access-mode":""}}"#).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let saved: Value = resp.into_json().await.unwrap();
    assert_eq!(saved["options"], serde_json::json!({"enable-clipboard": "N", "access-mode": ""}));

    let resp = client.post(format!("{path}/repush")).header(ContentType::JSON).header(auth_header(&token)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let pushed: Value = resp.into_json().await.unwrap();
    assert!(pushed["modified_at"].as_i64() > saved["modified_at"].as_i64());
    assert_eq!(pushed["options"], saved["options"]);
}

#[rocket::async_test]
async fn test_strategy_repush_without_content_type() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let path = format!("/api/strategies/{DEFAULT_STRATEGY}");

    // webconsole's axios POST sends no Content-Type on an empty body; Rocket must not 404 it
    let resp = client.post(format!("{path}/repush")).header(auth_header(&token)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_strategy_update_rejects_invalid_options() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let path = format!("/api/strategies/{DEFAULT_STRATEGY}");
    let resp = client.put(&path).header(ContentType::JSON).header(auth_header(&token))
        .body(r#"{"options":{"enable-clipboard":"N","relay-server":"evil"}}"#).dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest);
    assert!(resp.into_string().await.unwrap().contains("relay-server"));
    let resp = client.get(&path).header(ContentType::JSON).header(auth_header(&token)).dispatch().await;
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["options"], serde_json::json!({}), "nothing saved");
}

#[rocket::async_test]
async fn test_strategy_unknown_guid_is_404() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let path = "/api/strategies/00000000-0000-0000-0000-000000000000";
    let get = client.get(path).header(ContentType::JSON).header(auth_header(&token)).dispatch().await;
    assert_eq!(get.status(), Status::NotFound);
    let put = client.put(path).header(ContentType::JSON).header(auth_header(&token)).body(r#"{"options":{}}"#).dispatch().await;
    assert_eq!(put.status(), Status::NotFound);
    let post = client.post(format!("{path}/repush")).header(ContentType::JSON).header(auth_header(&token)).dispatch().await;
    assert_eq!(post.status(), Status::NotFound);
}

#[rocket::async_test]
async fn test_strategy_endpoints_require_admin() {
    let (client, _dir) = test_client().await;
    let admin = login_admin(&client).await;
    let (token, _) = create_and_login_user(&client, &admin, "bob").await;
    let path = format!("/api/strategies/{DEFAULT_STRATEGY}");
    for resp in [
        client.get("/api/strategies").header(ContentType::JSON).header(auth_header(&token)).dispatch().await,
        client.get(&path).header(ContentType::JSON).header(auth_header(&token)).dispatch().await,
        client.put(&path).header(ContentType::JSON).header(auth_header(&token)).body(r#"{"options":{}}"#).dispatch().await,
        client.post(format!("{path}/repush")).header(ContentType::JSON).header(auth_header(&token)).dispatch().await,
    ] {
        assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden, "{}", resp.status());
    }
}

#[rocket::async_test]
async fn test_software_version() {
    let (client, _dir) = test_client().await;
    let resp = client
        .get("/api/software/version/server")
        .header(ContentType::JSON)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    // Without a MAIN_PKG_VERSION override the server reports its own version.
    assert_eq!(body["server"], env!("CARGO_PKG_VERSION"));
}

#[rocket::async_test]
async fn test_software_releases_tag() {
    let (client, _dir) = test_client().await;
    let resp = client
        .get("/api/software/releases/tag/1.2.3")
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["client"], "1.2.3");
}

#[rocket::async_test]
async fn test_options_cors() {
    let (client, _dir) = test_client().await;
    let resp = client.options("/api/login").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let cors = resp
        .headers()
        .get_one("Access-Control-Allow-Origin")
        .unwrap();
    assert_eq!(cors, "*");
}

#[rocket::async_test]
async fn test_webconsole_redirect() {
    let (client, _dir) = test_client().await;
    let resp = client.get("/").dispatch().await;
    assert_eq!(resp.status(), Status::SeeOther);
}

#[rocket::async_test]
async fn test_index_html_redirect() {
    let (client, _dir) = test_client().await;
    let resp = client.get("/index.html").dispatch().await;
    assert_eq!(resp.status(), Status::SeeOther);
}

#[rocket::async_test]
async fn test_favicon_redirect() {
    let (client, _dir) = test_client().await;
    let resp = client.get("/favicon.ico").dispatch().await;
    assert_eq!(resp.status(), Status::SeeOther);
}

#[rocket::async_test]
async fn test_user_update() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;

    client
        .post("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"name":"updateme","password":"Pass1234!","confirm-password":"Pass1234!","email":"update@test.com","is_admin":false,"group_name":"Default"}"#)
        .dispatch()
        .await;

    let resp = client
        .get("/api/user-list?current=1&pageSize=10&name=updateme")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    let uuid = body["data"][0]["guid"].as_str().unwrap();

    let resp = client
        .put("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(
            r#"{{"uuid":"{}","name":"updateme","email":"newemail@test.com"}}"#,
            uuid
        ))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["msg"], "success");
}

#[rocket::async_test]
async fn test_oidc_add_returns_unauthorized() {
    let (client, _dir) = test_client().await;
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
async fn test_oidc_get_returns_unauthorized() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .get("/api/oidc/settings")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
}

/// An IdP that accepts any code and says the user is `sub`.
struct StubIdp {
    sub: String,
}

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
        let sub = self.sub.clone();
        Box::pin(async move {
            Ok(oauth2::oauth_provider::OAuthResponse { access_token: "at".into(), subject: sub.clone(), name: Some(sub.clone()), email: Some(format!("{sub}@example.com")) })
        })
    }
    fn get_provider_type(&self) -> oauth2::Provider {
        oauth2::Provider::Dex
    }
}

/// An IdP that rejects every code.
struct FailingIdp;

impl oauth2::oauth_provider::OAuthProvider for FailingIdp {
    fn get_redirect_url(&self, _callback_url: &str, login: &oauth2::pkce::ProviderLogin) -> String {
        format!("https://idp.example.com/authorize?state={}", login.state)
    }
    fn exchange_code(
        &self,
        _code: &str,
        _callback_url: &str,
        _login: &oauth2::pkce::ProviderLogin,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<oauth2::oauth_provider::OAuthResponse, oauth2::errors::Oauth2Error>> + Send + Sync>> {
        Box::pin(async { Err(oauth2::errors::Oauth2Error::DecodeIdTokenError) })
    }
    fn get_provider_type(&self) -> oauth2::Provider {
        oauth2::Provider::Dex
    }
}

/// A client on a fresh database that keeps no cookies between requests.
async fn untracked_client() -> Client {
    let db_url = state::testing::fresh_database_url().await;
    let figment = rocket::Config::figment()
        .merge(("port", 0))
        .merge(("secret_key", "hPRYyVRiMyxpw5sBB1XeCMN1kFsDCqKvBi2QJxBVHQk="));
    Client::untracked(build_rocket_with_db(figment, &db_url).await).await.unwrap()
}

async fn public_url_client(public_url: &str) -> Client {
    let db_url = state::testing::fresh_database_url().await;
    let figment = rocket::Config::figment()
        .merge(("port", 0))
        .merge(("public_url", public_url))
        .merge(("secret_key", "hPRYyVRiMyxpw5sBB1XeCMN1kFsDCqKvBi2QJxBVHQk="));
    Client::untracked(build_rocket_with_db(figment, &db_url).await).await.unwrap()
}

/// POSTs /api/oidc/auth with the given Host; returns the response body.
async fn oidc_auth_as(client: &Client, host: &str, return_to: &str) -> Value {
    let uuid = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, "device-uuid");
    let challenge = oauth2::pkce::s256_challenge(VERIFIER);
    client
        .post("/api/oidc/auth")
        .header(ContentType::JSON)
        .header(Header::new("Host", host.to_string()))
        .body(format!(r#"{{"op":"dex","id":"123456789","uuid":"{uuid}","deviceInfo":{{"name":"d","os":"windows","type":"client"}},"returnTo":"{return_to}","codeChallenge":"{challenge}"}}"#))
        .dispatch()
        .await
        .into_json()
        .await
        .unwrap()
}

fn idp_redirect_uri(body: &Value) -> String {
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    url.query_pairs().find(|(k, _)| k == "redirect_uri").map(|(_, v)| v.into_owned()).unwrap_or_default()
}

#[rocket::async_test]
async fn test_oidc_callback_url_keeps_host_port() {
    let client = untracked_client().await;
    let body = oidc_auth_as(&client, "rustdesk.example.com:30080", LOOPBACK).await;
    assert_eq!(idp_redirect_uri(&body), "http://rustdesk.example.com:30080/api/oidc/callback");
}

#[rocket::async_test]
async fn test_oidc_callback_url_uses_public_url() {
    let client = public_url_client("https://rustdesk.example.com:8443").await;
    let body = oidc_auth_as(&client, "internal-proxy", LOOPBACK).await;
    assert_eq!(idp_redirect_uri(&body), "https://rustdesk.example.com:8443/api/oidc/callback");
}

#[rocket::async_test]
async fn test_oidc_return_to_checked_against_public_url() {
    let client = public_url_client("https://rustdesk.example.com:8443").await;
    let ok = oidc_auth_as(&client, "internal-proxy", "https://rustdesk.example.com:8443/ui/login").await;
    assert!(!ok["code"].as_str().unwrap().contains("ERROR"), "{ok}");
    let refused = oidc_auth_as(&client, "internal-proxy", "http://internal-proxy/ui/login").await;
    assert_eq!(refused["code"], "RETURN_TO_ERROR");
}

const VERIFIER: &str = "Verifier0123456789Verifier0123456789Verifier0123456789";
const LOOPBACK: &str = "http://127.0.0.1:48123/";

async fn start_login(client: &Client, device_name: &str, return_to: &str) -> String {
    start_login_as(client, device_name, "client", return_to).await
}

/// Starts an OIDC login as a client of `device_type` would; returns the login code.
async fn start_login_as(client: &Client, device_name: &str, device_type: &str, return_to: &str) -> String {
    let uuid = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, "device-uuid");
    let challenge = oauth2::pkce::s256_challenge(VERIFIER);
    let resp = client
        .post("/api/oidc/auth")
        .header(ContentType::JSON)
        .header(Header::new("Host", "rustdesk.example.com"))
        .header(Header::new("X-Forwarded-Proto", "https"))
        .header(Header::new("X-Real-IP", "198.51.100.20"))
        .body(format!(r#"{{"op":"dex","id":"123456789","uuid":"{uuid}","deviceInfo":{{"name":"{device_name}","os":"windows","type":"{device_type}"}},"returnTo":"{return_to}","codeChallenge":"{challenge}"}}"#))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    body["code"].as_str().unwrap().to_string()
}

async fn use_stub_idp(client: &Client, code: &str, sub: &str) {
    let state = client.rocket().state::<state::ApiState>().unwrap();
    assert!(state.test_set_oidc_provider(code, std::sync::Arc::new(StubIdp { sub: sub.into() })).await);
    // New OIDC users start inactive; promoting activates them.
    state.test_oidc_login(&sub.to_string()).await;
    state.set_admin(&format!("{sub}@example.org"), true).await.unwrap();
}

/// The IdP redirecting the browser back; returns the Location header.
async fn callback(client: &Client, code: &str) -> String {
    let resp = client.get(format!("/api/oidc/callback?code=idp-code&state={code}")).dispatch().await;
    resp.headers().get_one("Location").unwrap_or_default().to_string()
}

fn result_of(location: &str) -> String {
    let url = url::Url::parse(location).unwrap();
    url.query_pairs().find(|(k, _)| k == "result").map(|(_, v)| v.into_owned()).expect("result in the return URL")
}

async fn redeem(client: &Client, result: &str, verifier: &str) -> (Status, Value) {
    let uuid = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, "device-uuid");
    let resp = client
        .post("/api/oidc/token")
        .header(ContentType::JSON)
        .body(format!(r#"{{"result":"{result}","codeVerifier":"{verifier}","id":"123456789","uuid":"{uuid}"}}"#))
        .dispatch()
        .await;
    let status = resp.status();
    (status, resp.into_json().await.unwrap_or(Value::Null))
}

/// Full login of `sub` from a native client on `device_name`; returns the bearer token.
async fn native_login(client: &Client, device_name: &str, sub: &str) -> String {
    let code = start_login(client, device_name, LOOPBACK).await;
    use_stub_idp(client, &code, sub).await;
    let (status, body) = redeem(client, &result_of(&callback(client, &code).await), VERIFIER).await;
    assert_eq!(status, Status::Ok, "{body}");
    body["access_token"].as_str().unwrap().to_string()
}

#[rocket::async_test]
async fn test_oidc_pending_logins_expire() {
    let client = untracked_client().await;
    let code = start_login(&client, "PC", LOOPBACK).await;
    use_stub_idp(&client, &code, "alice").await;
    let state = client.rocket().state::<state::ApiState>().unwrap();
    assert!(state.test_age_oidc_session(&code, 3600).await);
    let resp = client.get(format!("/api/oidc/callback?code=idp-code&state={code}")).dispatch().await;
    assert!(resp.headers().get_one("Location").is_none());
    let page = resp.into_string().await.unwrap_or_default();
    assert!(page.contains("Login failed"), "{page}");
}

#[rocket::async_test]
async fn test_oidc_return_to_must_be_on_this_server() {
    let client = untracked_client().await;
    let code = start_login(&client, "PC", "https://evil.example.com/steal").await;
    assert!(code.is_empty() || code.contains("ERROR"), "foreign returnTo accepted: {code}");

    let code = start_login(&client, "PC", "https://rustdesk.example.com/ui/login").await;
    assert!(!code.is_empty() && !code.contains("ERROR"), "{code}");
    use_stub_idp(&client, &code, "alice").await;
    let location = callback(&client, &code).await;
    assert!(location.starts_with("https://rustdesk.example.com/ui/login?result="), "{location}");
}

#[rocket::async_test]
async fn test_oidc_auth_invalid_uuid() {
    let (client, _dir) = test_client().await;
    let resp = client
        .post("/api/oidc/auth")
        .header(ContentType::JSON)
        .body(r#"{"op":"github","uuid":"not-valid-base64!!!","id":"test","deviceInfo":{"name":"test","os":"linux","type":"client"}}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["code"], "UUID_ERROR");
}

#[rocket::async_test]
async fn test_oidc_callback_invalid_session() {
    let (client, _dir) = test_client().await;
    let resp = client
        .get("/api/oidc/callback?code=fake&state=fake")
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_string().await.unwrap();
    assert!(body.contains("Login failed"), "expected login failure message, got: {body}");
}

#[rocket::async_test]
async fn test_oidc_native_login_returns_a_one_time_result_to_the_loopback() {
    let client = untracked_client().await;
    let code = start_login(&client, "MY-LAPTOP", LOOPBACK).await;
    use_stub_idp(&client, &code, "alice").await;
    let location = callback(&client, &code).await;
    assert!(location.starts_with(&format!("{LOOPBACK}?result=")), "{location}");
    assert!(location.contains(&format!("code={code}")));
    let result = result_of(&location);
    let (status, body) = redeem(&client, &result, VERIFIER).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["type"], "access_token");
    assert_eq!(body["user"]["name"], "alice");
    let (again, _) = redeem(&client, &result, VERIFIER).await;
    assert_eq!(again, Status::BadRequest, "a result works once");
}

#[rocket::async_test]
async fn test_oidc_callback_runs_once() {
    let client = untracked_client().await;
    let code = start_login(&client, "MY-LAPTOP", LOOPBACK).await;
    use_stub_idp(&client, &code, "alice").await;
    let result = result_of(&callback(&client, &code).await);
    let replay = callback(&client, &code).await;
    assert!(!replay.starts_with(LOOPBACK), "{replay}");
    let (status, body) = redeem(&client, &result, VERIFIER).await;
    assert_eq!(status, Status::Ok, "{body}");
}

#[rocket::async_test]
async fn test_oidc_result_needs_the_starters_verifier() {
    let client = untracked_client().await;
    let code = start_login(&client, "MY-LAPTOP", LOOPBACK).await;
    use_stub_idp(&client, &code, "alice").await;
    let result = result_of(&callback(&client, &code).await);
    let (status, _) = redeem(&client, &result, "Other0123456789Other0123456789Other0123456789xx").await;
    assert_eq!(status, Status::BadRequest);
    let (status, _) = redeem(&client, &result, VERIFIER).await;
    assert_eq!(status, Status::BadRequest, "a failed redemption burns the result");
}

#[rocket::async_test]
async fn test_oidc_result_is_bound_to_the_starting_id() {
    let client = untracked_client().await;
    let code = start_login(&client, "MY-LAPTOP", LOOPBACK).await;
    use_stub_idp(&client, &code, "alice").await;
    let result = result_of(&callback(&client, &code).await);
    let resp = client.post("/api/oidc/token").header(ContentType::JSON)
        .body(format!(r#"{{"result":"{result}","codeVerifier":"{VERIFIER}","id":"999","uuid":"x"}}"#)).dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest);
}

#[rocket::async_test]
async fn test_oidc_result_expires() {
    let client = untracked_client().await;
    let code = start_login(&client, "MY-LAPTOP", LOOPBACK).await;
    use_stub_idp(&client, &code, "alice").await;
    let result = result_of(&callback(&client, &code).await);
    let state = client.rocket().state::<state::ApiState>().unwrap();
    assert!(state.test_age_oidc_session(&code, state::OIDC_RESULT_TTL_SECS + 1).await);
    let (status, _) = redeem(&client, &result, VERIFIER).await;
    assert_eq!(status, Status::BadRequest);
}

#[rocket::async_test]
async fn test_oidc_return_to_must_be_a_loopback_or_a_login_page() {
    let client = untracked_client().await;
    let challenge = oauth2::pkce::s256_challenge(VERIFIER);
    for bad in ["http://evil.example.com/", "https://127.0.0.1:48123/", "http://127.0.0.1/", "http://127.0.0.1:48123/x", "http://localhost:48123/", "",
        "https://rustdesk.example.com/ui/", "https://rustdesk.example.com/api/user", "/ui/login/x",
        "https://rustdesk.example.com/ui/login?next=/x", "/oidc-callback.html#x", "/ui/../oidc-callback.html"] {
        let resp = client.post("/api/oidc/auth").header(ContentType::JSON)
            .header(Header::new("Host", "rustdesk.example.com")).header(Header::new("X-Forwarded-Proto", "https"))
            .body(format!(r#"{{"op":"dex","id":"1","uuid":"eA==","deviceInfo":{{"name":"n","os":"o","type":"client"}},"returnTo":"{bad}","codeChallenge":"{challenge}"}}"#))
            .dispatch().await;
        let body: Value = resp.into_json().await.unwrap();
        assert_eq!(body["code"], "RETURN_TO_ERROR", "{bad}");
    }
    for ok in ["http://[::1]:48123/", "https://rustdesk.example.com/ui/login", "https://rustdesk.example.com/oidc-callback.html", "/ui/login", "/oidc-callback.html"] {
        let code = start_login(&client, "n", ok).await;
        assert!(!code.is_empty() && code != "RETURN_TO_ERROR", "{ok}");
    }
}

#[rocket::async_test]
async fn test_oidc_auth_requires_an_s256_challenge() {
    let client = untracked_client().await;
    let resp = client.post("/api/oidc/auth").header(ContentType::JSON)
        .header(Header::new("Host", "rustdesk.example.com")).header(Header::new("X-Forwarded-Proto", "https"))
        .body(format!(r#"{{"op":"dex","id":"1","uuid":"eA==","deviceInfo":{{"name":"n","os":"o","type":"client"}},"returnTo":"{LOOPBACK}","codeChallenge":"short"}}"#))
        .dispatch().await;
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["code"], "CODE_CHALLENGE_ERROR");
}

#[rocket::async_test]
async fn test_oidc_polling_and_confirmation_endpoints_are_gone() {
    let client = untracked_client().await;
    let resp = client.get("/api/oidc/auth-query?code=x&id=1&uuid=x").dispatch().await;
    assert_eq!(resp.status(), Status::NotFound);
    let resp = client.post("/api/oidc/confirm").header(ContentType::Form).body("state=x&token=y&approve=true").dispatch().await;
    assert_eq!(resp.status(), Status::NotFound);
}

#[rocket::async_test]
async fn test_oidc_failed_login_returns_an_error_to_the_starter() {
    let client = untracked_client().await;
    let code = start_login(&client, "MY-LAPTOP", LOOPBACK).await;
    let state = client.rocket().state::<state::ApiState>().unwrap();
    assert!(state.test_set_oidc_provider(&code, std::sync::Arc::new(FailingIdp)).await);
    let location = callback(&client, &code).await;
    assert_eq!(location, format!("{LOOPBACK}?error=login_failed&code={code}"));
}

#[test]
fn test_openapi_spec() {
    let (routes, spec) = rustdesk_api::api_routes();
    let body = serde_json::to_value(&spec).unwrap();
    assert!(body["openapi"].as_str().is_some());
    assert!(body["paths"]["/api/login"].is_object());
    assert!(!routes.iter().any(|r| r.uri.path() == "/openapi.json"));
}

/// Create a non-admin user as admin, log in as it, and return (token, guid).
async fn create_and_login_user(client: &Client, admin_token: &str, name: &str) -> (String, String) {
    let resp = client
        .post("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(admin_token))
        .body(format!(r#"{{"name":"{name}","password":"Pass1234!","confirm-password":"Pass1234!","email":"{name}@example.org","is_admin":false,"group_name":"Default"}}"#))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let user = find_user(client, admin_token, name).await.expect("created user not listed");
    (oidc_token(client, name).await, user["guid"].as_str().unwrap().to_string())
}

async fn find_user(client: &Client, admin_token: &str, name: &str) -> Option<Value> {
    let resp = client
        .get(format!("/api/user-list?current=1&pageSize=100&name={name}"))
        .header(ContentType::JSON)
        .header(auth_header(admin_token))
        .dispatch()
        .await;
    let body: Value = resp.into_json().await.unwrap();
    body["data"].as_array().unwrap().iter().find(|u| u["name"] == name).cloned()
}

#[rocket::async_test]
async fn test_non_admin_cannot_escalate_via_user_update() {
    let (client, _dir) = test_client().await;
    let admin = login_admin(&client).await;
    let (token, guid) = create_and_login_user(&client, &admin, "escalate").await;

    let resp = client
        .put("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(r#"{{"uuid":"{guid}","is_admin":true,"group_name":"Default","status":1,"name":"renamed"}}"#))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let user = find_user(&client, &admin, "escalate").await.expect("user renamed or missing");
    assert_eq!(user["is_admin"], false);
}

#[rocket::async_test]
async fn test_non_admin_can_update_own_email() {
    let (client, _dir) = test_client().await;
    let admin = login_admin(&client).await;
    let (token, guid) = create_and_login_user(&client, &admin, "selfedit").await;

    let resp = client
        .put("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(r#"{{"uuid":"{guid}","email":"new-selfedit@test.com"}}"#))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let user = find_user(&client, &admin, "selfedit").await.unwrap();
    assert_eq!(user["email"], "new-selfedit@test.com");
}

#[rocket::async_test]
async fn test_non_admin_cannot_update_other_user() {
    let (client, _dir) = test_client().await;
    let admin = login_admin(&client).await;
    let (token, _) = create_and_login_user(&client, &admin, "attacker").await;
    let (_, victim) = create_and_login_user(&client, &admin, "victim").await;

    let resp = client
        .put("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(format!(r#"{{"uuid":"{victim}","email":"pwned@test.com"}}"#))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
    assert_eq!(find_user(&client, &admin, "victim").await.unwrap()["email"], "victim@example.org");
}

#[rocket::async_test]
async fn test_admin_can_promote_user() {
    let (client, _dir) = test_client().await;
    let admin = login_admin(&client).await;
    let (_, guid) = create_and_login_user(&client, &admin, "promoteme").await;

    let resp = client
        .put("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&admin))
        .body(format!(r#"{{"uuid":"{guid}","is_admin":true}}"#))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    assert_eq!(find_user(&client, &admin, "promoteme").await.unwrap()["is_admin"], true);
}

#[rocket::async_test]
async fn test_malformed_bearer_token_is_unauthorized() {
    let (client, _dir) = test_client().await;
    for token in ["invalid-token", "AAAA", "not base64 !!"] {
        let resp = client
            .get("/api/peers")
            .header(ContentType::JSON)
            .header(auth_header(token))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Unauthorized, "token {token:?}");
    }
}

#[rocket::async_test]
async fn test_user_delete_unknown_guid_counts_zero() {
    let (client, _dir) = test_client().await;
    let token = login_admin(&client).await;
    let resp = client
        .delete("/api/user")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .body(r#"{"rows":["00000000-0000-0000-0000-000000000000"]}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 0);
}

/// A plain (non-admin) logged-in user: created inactive, then activated and demoted.
async fn activated_user_token(client: &Client, name: &str) -> String {
    let state = client.rocket().state::<state::ApiState>().unwrap();
    state.test_oidc_login(&name.to_string()).await;
    state.set_admin(&format!("{name}@example.org"), true).await.unwrap();
    state.set_admin(&format!("{name}@example.org"), false).await.unwrap();
    oidc_token(client, name).await
}

#[rocket::async_test]
async fn test_audits_conn_lists_newest_first_with_viewer_user() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devx", "dXg=").await;
    let admin = login_admin(&client).await;
    let alice = activated_user_token(&client, "alice").await;
    let r: Value = client.post("/api/audit/ref?target=devx").header(auth_header(&alice)).dispatch().await.into_json().await.unwrap();
    let r = r["ref"].as_str().unwrap();
    for (n, conn_id) in [("a", 1), ("b", 2)] {
        client.post("/api/audit/conn").header(ContentType::JSON)
            .body(format!(r#"{{"action":"new","id":"devx","uuid":"dXg=","conn_id":{conn_id},"ip":"203.0.113.9","nonce":"{n}","conn_audit_ref":"{r}"}}"#))
            .dispatch().await;
    }
    let resp = client.get("/api/audits/conn?current=1&pageSize=10&remote=%25devx%25").header(auth_header(&admin)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 2);
    assert_eq!(body["data"][0]["conn_id"], 2);
    assert_eq!(body["data"][0]["user"], "alice");
    assert_eq!(body["data"][0]["ip"], "203.0.113.9");
    assert!(body["data"][0].get("conn_type").is_none());
    assert_eq!(body["data"][0]["active"], true);
}

#[rocket::async_test]
async fn test_audits_conn_requires_admin() {
    let (client, _dir) = test_client().await;
    let resp = client.get("/api/audits/conn?current=1&pageSize=10").dispatch().await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);

    let alice = activated_user_token(&client, "alice").await;
    let resp = client.get("/api/audits/conn?current=1&pageSize=10").header(auth_header(&alice)).dispatch().await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);
}

#[rocket::async_test]
async fn test_audits_conn_pagination_returns_the_older_row_on_page_two() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devpage", "dXBhZ2U=").await;
    let admin = login_admin(&client).await;
    for (n, conn_id) in [("p1", 1), ("p2", 2)] {
        client.post("/api/audit/conn").header(ContentType::JSON)
            .body(format!(r#"{{"action":"new","id":"devpage","uuid":"dXBhZ2U=","conn_id":{conn_id},"ip":"203.0.113.10","nonce":"{n}"}}"#))
            .dispatch().await;
    }
    let resp = client.get("/api/audits/conn?current=2&pageSize=1&remote=%25devpage%25").header(auth_header(&admin)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 2);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["conn_id"], 1);
}

#[rocket::async_test]
async fn test_audits_conn_filters_by_conn_type() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devtype", "dXR5cGU=").await;
    let admin = login_admin(&client).await;
    client.post("/api/audit/conn").header(ContentType::JSON)
        .body(r#"{"action":"new","id":"devtype","uuid":"dXR5cGU=","conn_id":1,"ip":"203.0.113.11","nonce":"nt1"}"#)
        .dispatch().await;
    client.post("/api/audit/conn").header(ContentType::JSON)
        .body(r#"{"peer":["v1","Viewer"],"type":0,"id":"devtype","uuid":"dXR5cGU=","conn_id":1,"session_id":1,"nonce":"nt2"}"#)
        .dispatch().await;

    let resp = client.get("/api/audits/conn?current=1&pageSize=10&remote=%25devtype%25&conn_type=0").header(auth_header(&admin)).dispatch().await;
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 1);

    let resp = client.get("/api/audits/conn?current=1&pageSize=10&remote=%25devtype%25&conn_type=1").header(auth_header(&admin)).dispatch().await;
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 0);
}

#[rocket::async_test]
async fn test_audits_conn_future_created_at_finds_nothing() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devfuture", "dWZ1dHVyZQ==").await;
    let admin = login_admin(&client).await;
    client.post("/api/audit/conn").header(ContentType::JSON)
        .body(r#"{"action":"new","id":"devfuture","uuid":"dWZ1dHVyZQ==","conn_id":1,"ip":"203.0.113.12","nonce":"nf1"}"#)
        .dispatch().await;

    let resp = client
        .get("/api/audits/conn?current=1&pageSize=10&remote=%25devfuture%25&created_at=2099-01-01%2000:00:00.000")
        .header(auth_header(&admin))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 0);
}

#[rocket::async_test]
async fn test_audits_conn_invalid_created_at_is_bad_request() {
    let (client, _dir) = test_client().await;
    let admin = login_admin(&client).await;
    let resp = client
        .get("/api/audits/conn?current=1&pageSize=10&created_at=not-a-date")
        .header(auth_header(&admin))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest);
}

#[rocket::async_test]
async fn test_audits_file_shows_remote_peer_num_and_files() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devfile", "dWZpbGU=").await;
    let admin = login_admin(&client).await;
    let resp = client
        .post("/api/audit/file")
        .header(ContentType::JSON)
        .body(r#"{"id":"devfile","uuid":"dWZpbGU=","peer_id":"viewerfile","conn_id":1,"type":0,"path":"/tmp","is_file":false,"info":"{\"ip\":\"203.0.113.13\",\"name\":\"alice-laptop\",\"num\":2,\"files\":[[\"a.pdf\",10],[\"b.txt\",5]]}","nonce":"filenonce"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client.get("/api/audits/file?current=1&pageSize=10&remote=%25devfile%25").header(auth_header(&admin)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 1);
    assert_eq!(body["data"][0]["remote"], "devfile");
    assert_eq!(body["data"][0]["peer_id"], "viewerfile");
    assert_eq!(body["data"][0]["num"], 2);
    assert_eq!(body["data"][0]["files"][0][0], "a.pdf");
}

#[rocket::async_test]
async fn test_audits_alarm_shows_info_as_an_object() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devalarm", "dWFsYXJt").await;
    let admin = login_admin(&client).await;
    let resp = client
        .post("/api/audit/alarm")
        .header(ContentType::JSON)
        .body(r#"{"id":"devalarm","uuid":"dWFsYXJt","typ":1,"info":"{\"ip\":\"203.0.113.14\",\"id\":\"ctl1\",\"name\":\"alice\"}","conn_id":1,"nonce":"alarmnonce"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client.get("/api/audits/alarm?current=1&pageSize=10&device=%25devalarm%25").header(auth_header(&admin)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 1);
    assert_eq!(body["data"][0]["device"], "devalarm");
    assert!(body["data"][0]["info"].is_object());
    assert_eq!(body["data"][0]["info"]["ip"], "203.0.113.14");
}

#[rocket::async_test]
async fn test_audits_console_is_always_an_empty_page() {
    let (client, _dir) = test_client().await;
    let admin = login_admin(&client).await;
    let resp = client.get("/api/audits/console?current=1&pageSize=10").header(auth_header(&admin)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 0);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
}

/// `POST /api/audit/{file,alarm}` are unauthenticated; a non-JSON `info` string starting with
/// `{` must not 500 every page of `GET /api/audits/{file,alarm}` (fix round 1).
#[rocket::async_test]
async fn test_audits_file_and_alarm_survive_an_unparsable_info_string() {
    let (client, _dir) = test_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devbad", "dWJhZA==").await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devbadalarm", "dWJhZGFsYXJt").await;
    let admin = login_admin(&client).await;

    let resp = client
        .post("/api/audit/file")
        .header(ContentType::JSON)
        .body(r#"{"id":"devbad","uuid":"dWJhZA==","peer_id":"viewerbad","conn_id":1,"type":0,"path":"/tmp","is_file":false,"info":"{x","nonce":"badfilenonce"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let resp = client
        .post("/api/audit/file")
        .header(ContentType::JSON)
        .body(r#"{"id":"devbad","uuid":"dWJhZA==","peer_id":"viewerbad","conn_id":2,"type":0,"path":"/tmp","is_file":false,"info":"{\"ip\":\"203.0.113.15\",\"name\":\"ok\",\"num\":1,\"files\":[]}","nonce":"goodfilenonce"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client.get("/api/audits/file?current=1&pageSize=10&remote=%25devbad%25").header(auth_header(&admin)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 2);
    assert!(body["data"].as_array().unwrap().iter().any(|r| r["ip"] == "203.0.113.15"));

    let resp = client
        .post("/api/audit/alarm")
        .header(ContentType::JSON)
        .body(r#"{"id":"devbadalarm","uuid":"dWJhZGFsYXJt","typ":1,"info":"{x","conn_id":1,"nonce":"badalarmnonce"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let resp = client
        .post("/api/audit/alarm")
        .header(ContentType::JSON)
        .body(r#"{"id":"devbadalarm","uuid":"dWJhZGFsYXJt","typ":1,"info":"{\"ip\":\"203.0.113.16\",\"id\":\"ctl1\",\"name\":\"ok\"}","conn_id":2,"nonce":"goodalarmnonce"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client.get("/api/audits/alarm?current=1&pageSize=10&device=%25devbadalarm%25").header(auth_header(&admin)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert_eq!(body["total"], 2);
    assert!(body["data"].as_array().unwrap().iter().any(|r| r["info"]["ip"] == "203.0.113.16"));
}

#[rocket::async_test]
async fn test_audits_conn_shows_the_viewer_machine_from_its_login() {
    let client = untracked_client().await;
    client.rocket().state::<state::ApiState>().unwrap().test_register_device("devvm", "dXZt").await;
    let alice = native_login(&client, "MY-LAPTOP", "alice").await;
    let admin = login_admin(&client).await;

    let r: Value = client.post("/api/audit/ref?target=devvm").header(auth_header(&alice)).dispatch().await.into_json().await.unwrap();
    let r = r["ref"].as_str().unwrap();
    for body in [
        format!(r#"{{"action":"new","id":"devvm","uuid":"dXZt","conn_id":1,"ip":"203.0.113.20","nonce":"vm-n","conn_audit_ref":"{r}"}}"#),
        r#"{"peer":["123456789","Alice"],"type":0,"id":"devvm","uuid":"dXZt","conn_id":1,"session_id":5,"nonce":"vm-a"}"#.to_string(),
    ] {
        let resp = client.post("/api/audit/conn").header(ContentType::JSON).body(body).dispatch().await;
        assert_eq!(resp.status(), Status::Ok);
    }

    let resp = client.get("/api/audits/conn?current=1&pageSize=10&remote=%25devvm%25").header(auth_header(&admin)).dispatch().await;
    let body: Value = resp.into_json().await.unwrap();
    let row = &body["data"][0];
    assert_eq!((row["peer_hostname"].as_str(), row["peer_os"].as_str()), (Some("MY-LAPTOP"), Some("windows")), "{body}");
    assert_eq!(row["peer_login_ip"], "198.51.100.20");
    assert_eq!(row["ip"], "203.0.113.20");
}

async fn viewers(client: &Client, token: &str) -> Value {
    let resp = client.get("/api/viewers?current=1&pageSize=10").header(auth_header(token)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    resp.into_json().await.unwrap()
}

#[rocket::async_test]
async fn test_native_oidc_login_lists_the_machine_as_a_viewer() {
    let client = untracked_client().await;
    let alice = native_login(&client, "MY-LAPTOP", "alice").await;
    let admin = login_admin(&client).await;

    let body = viewers(&client, &admin).await;
    assert_eq!(body["total"], 1, "{body}");
    let row = &body["data"][0];
    assert_eq!((row["id"].as_str(), row["hostname"].as_str()), (Some("123456789"), Some("MY-LAPTOP")));
    assert_eq!(row["login_ip"], "198.51.100.20");
    assert_eq!((row["os"].as_str(), row["user"].as_str()), (Some("windows"), Some("alice")));
    assert!(row["last_seen"].as_i64().unwrap() >= row["last_login"].as_i64().unwrap());

    // currentUser refreshes a known machine (uuid arrives base64) and never adds one.
    let state = client.rocket().state::<state::ApiState>().unwrap();
    state.test_age_viewer_device("123456789", 3600).await;
    let last_seen = || async { viewers(&client, &admin).await["data"][0]["last_seen"].as_i64().unwrap() };
    let aged = last_seen().await;
    let current_user = |id: &'static str, raw_uuid: &'static str| {
        let (client, alice) = (&client, alice.clone());
        async move {
            let uuid = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, raw_uuid);
            let resp = client
                .post("/api/currentUser")
                .header(ContentType::JSON)
                .header(auth_header(&alice))
                .body(format!(r#"{{"id":"{id}","uuid":"{uuid}"}}"#))
                .dispatch()
                .await;
            assert_eq!(resp.status(), Status::Ok);
        }
    };
    current_user("123456789", "other-uuid").await;
    current_user("987654321", "device-uuid").await;
    assert_eq!(last_seen().await, aged, "a non-matching id or uuid moved last_seen");
    assert_eq!(viewers(&client, &admin).await["total"], 1);
    current_user("123456789", "device-uuid").await;
    assert!(last_seen().await >= aged + 3600, "matching id+uuid did not refresh last_seen");
}

#[rocket::async_test]
async fn test_browser_oidc_login_is_not_a_viewer() {
    let client = untracked_client().await;
    let code = start_login_as(&client, "Netscape", "browser", "/ui/login").await;
    use_stub_idp(&client, &code, "alice").await;
    let location = callback(&client, &code).await;
    let (status, body) = redeem(&client, &result_of(&format!("https://rustdesk.example.com{location}")), VERIFIER).await;
    assert_eq!(status, Status::Ok, "{body}");
    let admin = login_admin(&client).await;
    assert_eq!(viewers(&client, &admin).await["total"], 0);
}

#[rocket::async_test]
async fn test_viewers_requires_admin() {
    let (client, _dir) = test_client().await;
    let resp = client.get("/api/viewers?current=1&pageSize=10").dispatch().await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);

    let alice = activated_user_token(&client, "alice").await;
    let resp = client.get("/api/viewers").header(auth_header(&alice)).dispatch().await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);
}

async fn login_audit(client: &Client, admin: &str, query: &str) -> Value {
    let resp = client.get(format!("/api/audits/login?current=1&pageSize=10{query}")).header(auth_header(admin)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    resp.into_json().await.unwrap()
}

/// The `result` of a callback Location that may be a path on this server.
fn result_of_any(location: &str) -> String {
    let url = url::Url::parse("https://rustdesk.example.com/").unwrap().join(location).unwrap();
    url.query_pairs().find(|(k, _)| k == "result").map(|(_, v)| v.into_owned()).expect("result in the return URL")
}

#[rocket::async_test]
async fn test_login_audit_records_a_successful_login() {
    let client = untracked_client().await;
    let admin = login_admin(&client).await;
    native_login(&client, "MY-LAPTOP", "alice").await;
    let body = login_audit(&client, &admin, "").await;
    assert_eq!(body["total"], 1);
    let row = &body["data"][0];
    assert_eq!(row["outcome"], "ok");
    assert_eq!(row["client"], "native");
    assert_eq!(row["user"], "alice");
    assert_eq!(row["rustdesk_id"], "123456789");
    assert_eq!(row["hostname"], "MY-LAPTOP");
    assert_eq!(row["os"], "windows");
    assert_eq!(row["ip"], "198.51.100.20");
}

#[rocket::async_test]
async fn test_login_audit_names_the_client_from_return_to() {
    let client = untracked_client().await;
    let admin = login_admin(&client).await;
    for return_to in ["/oidc-callback.html", "https://rustdesk.example.com/ui/login"] {
        let code = start_login(&client, "browser", return_to).await;
        use_stub_idp(&client, &code, "alice").await;
        let result = result_of_any(&callback(&client, &code).await);
        assert_eq!(redeem(&client, &result, VERIFIER).await.0, Status::Ok);
    }
    let body = login_audit(&client, &admin, "").await;
    assert_eq!(body["data"][0]["client"], "console");
    assert_eq!(body["data"][1]["client"], "web");
}

#[rocket::async_test]
async fn test_login_audit_records_failures() {
    let client = untracked_client().await;
    let admin = login_admin(&client).await;
    let state = client.rocket().state::<state::ApiState>().unwrap();

    let code = start_login(&client, "PC", LOOPBACK).await;
    let resp = client.get(format!("/api/oidc/callback?error=access_denied&state={code}")).dispatch().await;
    assert_eq!(resp.headers().get_one("Location").unwrap(), format!("{LOOPBACK}?error=login_failed&code={code}"));
    let row = &login_audit(&client, &admin, "&outcome=idp_denied").await["data"][0];
    assert_eq!(row["detail"], "access_denied");
    assert_eq!(row["user"], "");

    let code = start_login(&client, "PC", LOOPBACK).await;
    assert!(state.test_set_oidc_provider(&code, std::sync::Arc::new(FailingIdp)).await);
    callback(&client, &code).await;
    assert_eq!(login_audit(&client, &admin, "&outcome=idp_error").await["total"], 1);

    let code = start_login(&client, "PC", LOOPBACK).await;
    assert!(state.test_set_oidc_provider(&code, std::sync::Arc::new(StubIdp { sub: "bob".into() })).await);
    let result = result_of(&callback(&client, &code).await);
    assert_eq!(redeem(&client, &result, VERIFIER).await.0, Status::BadRequest);
    assert_eq!(login_audit(&client, &admin, "&outcome=inactive").await["data"][0]["user"], "bob");

    let code = start_login(&client, "PC", LOOPBACK).await;
    use_stub_idp(&client, &code, "alice").await;
    let result = result_of(&callback(&client, &code).await);
    assert_eq!(redeem(&client, &result, "wrong-verifier").await.0, Status::BadRequest);
    let row = &login_audit(&client, &admin, "&outcome=refused").await["data"][0];
    assert_eq!(row["detail"], "wrong verifier");
    assert_eq!(row["user"], "alice");

    assert_eq!(login_audit(&client, &admin, "").await["total"], 4);
    assert_eq!(login_audit(&client, &admin, "&user=%25ali%25").await["total"], 1);
}

#[rocket::async_test]
async fn test_login_audit_ignores_unknown_logins() {
    let client = untracked_client().await;
    let admin = login_admin(&client).await;
    client.get("/api/oidc/callback?error=access_denied&state=nope").dispatch().await;
    client.get("/api/oidc/callback?code=x&state=nope").dispatch().await;
    redeem(&client, "nope", VERIFIER).await;
    assert_eq!(login_audit(&client, &admin, "").await["total"], 0);
}

#[rocket::async_test]
async fn test_login_audit_requires_admin() {
    let client = untracked_client().await;
    let resp = client.get("/api/audits/login").dispatch().await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);
    let alice = activated_user_token(&client, "alice").await;
    let resp = client.get("/api/audits/login").header(auth_header(&alice)).dispatch().await;
    assert!(resp.status() == Status::Unauthorized || resp.status() == Status::Forbidden);
}

#[rocket::async_test]
async fn test_login_audit_keeps_the_name_of_a_deleted_user() {
    let client = untracked_client().await;
    let admin = login_admin(&client).await;
    native_login(&client, "PC", "carol").await;
    let users: Value = client.get("/api/user-list?current=1&pageSize=10&name=carol").header(auth_header(&admin)).dispatch().await.into_json().await.unwrap();
    let guid = users["data"][0]["guid"].as_str().unwrap().to_string();
    let resp = client.delete("/api/user").header(ContentType::JSON).header(auth_header(&admin))
        .body(format!(r#"{{"rows":["{guid}"]}}"#)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    assert_eq!(login_audit(&client, &admin, "").await["data"][0]["user"], "carol");
}

#[rocket::async_test]
async fn test_device_lists_do_not_reveal_the_uuid() {
    let (client, _dir) = test_client().await;
    let state = client.rocket().state::<state::ApiState>().unwrap();
    state.test_register_device("devinfo", "dXVpZA==").await;
    let resp = client.post("/api/sysinfo").header(ContentType::JSON)
        .body(r#"{"id":"devinfo","uuid":"dXVpZA==","hostname":"pc-1","os":"Linux"}"#)
        .dispatch().await;
    assert_eq!(resp.into_string().await.unwrap(), "SYSINFO_UPDATED");
    let alice = activated_user_token(&client, "alice").await;
    let body: Value = client.get("/api/peers").header(auth_header(&alice)).dispatch().await.into_json().await.unwrap();
    let peer = body["data"].as_array().unwrap().iter().find(|p| p["id"] == "devinfo").unwrap().clone();
    assert_eq!(peer["info"]["hostname"], "pc-1");
    assert!(peer["info"].get("uuid").is_none(), "{peer}");
    assert!(!state.test_peer_info("devinfo").await.contains("dXVpZA=="), "not stored either");
}
