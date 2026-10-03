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
    let resp = client.post("/api/audit/file").header(ContentType::JSON)
        .body(r#"{"id":"d","uuid":"u","peer_id":"p","conn_id":1,"type":0,"path":"","is_file":false,"info":"{}","nonce":"x1"}"#)
        .dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    assert_eq!(resp.into_string().await.unwrap_or_default(), "");
}

#[rocket::async_test]
async fn test_audit_alarm_answers_empty_when_stored() {
    let (client, _dir) = test_client().await;
    let resp = client.post("/api/audit/alarm").header(ContentType::JSON)
        .body(r#"{"id":"d","uuid":"u","typ":1,"info":"{}","conn_id":1,"nonce":"x2"}"#)
        .dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    assert_eq!(resp.into_string().await.unwrap_or_default(), "");
}

#[rocket::async_test]
async fn test_audit_ref_requires_login() {
    let (client, _dir) = test_client().await;
    let resp = client.post("/api/audit/ref").dispatch().await;
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
    let resp = client.post("/api/audit/ref").header(auth_header(&token)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    let r = body["ref"].as_str().unwrap().to_string();
    assert!(state.resolve_audit_conn_ref(&r).await.is_some());
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
    let state = client.rocket().state::<state::ApiState>().unwrap();
    // A plain (non-admin) logged-in user: created inactive, then activated and demoted.
    state.test_oidc_login(&"ivy".to_string()).await;
    state.set_admin("ivy@example.org", true).await.unwrap();
    state.set_admin("ivy@example.org", false).await.unwrap();
    let token = oidc_token(&client, "ivy").await;

    let resp = client.post("/api/audit/ref").header(auth_header(&token)).dispatch().await;
    let body: Value = resp.into_json().await.unwrap();
    let conn_ref = body["ref"].as_str().unwrap().to_string();

    let resp = client
        .post("/api/audit/conn")
        .header(ContentType::JSON)
        .body(format!(
            r#"{{"action":"new","id":"devX","uuid":"uX","conn_id":1,"session_id":99,"nonce":"nA","conn_audit_ref":"{conn_ref}"}}"#
        ))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let resp = client
        .post("/api/audit/conn")
        .header(ContentType::JSON)
        .body(r#"{"peer":["v1","Viewer"],"type":0,"id":"devX","uuid":"uX","conn_id":1,"session_id":99,"nonce":"nB"}"#)
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
    fn get_redirect_url(&self, _callback_url: &str, state: &str) -> String {
        format!("https://idp.example.com/authorize?state={state}")
    }
    fn exchange_code(
        &self,
        _code: &str,
        _callback_url: &str,
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

/// A client that sends only the cookies a test passes, so two "browsers" can share one server.
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
async fn oidc_auth_as(client: &Client, host: &str, redirect_uri: Option<&str>) -> Value {
    let uuid = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, "device-uuid");
    let redirect = redirect_uri.map(|r| format!(r#","redirectUri":"{r}""#)).unwrap_or_default();
    client
        .post("/api/oidc/auth")
        .header(ContentType::JSON)
        .header(Header::new("Host", host.to_string()))
        .body(format!(r#"{{"op":"dex","id":"123456789","uuid":"{uuid}","deviceInfo":{{"name":"d","os":"windows","type":"client"}}{redirect}}}"#))
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
    let body = oidc_auth_as(&client, "rustdesk.example.com:30080", None).await;
    assert_eq!(idp_redirect_uri(&body), "http://rustdesk.example.com:30080/api/oidc/callback");
}

#[rocket::async_test]
async fn test_oidc_callback_url_uses_public_url() {
    let client = public_url_client("https://rustdesk.example.com:8443").await;
    let body = oidc_auth_as(&client, "internal-proxy", None).await;
    assert_eq!(idp_redirect_uri(&body), "https://rustdesk.example.com:8443/api/oidc/callback");
}

#[rocket::async_test]
async fn test_oidc_redirect_uri_checked_against_public_url() {
    let client = public_url_client("https://rustdesk.example.com:8443").await;
    let ok = oidc_auth_as(&client, "internal-proxy", Some("https://rustdesk.example.com:8443/ui/login")).await;
    assert!(!ok["code"].as_str().unwrap().contains("ERROR"), "{ok}");
    let refused = oidc_auth_as(&client, "internal-proxy", Some("http://internal-proxy/ui/login")).await;
    assert_eq!(refused["code"], "REDIRECT_URI_ERROR");
}

/// Starts an OIDC login as a client would; returns (code, Set-Cookie header if any).
async fn start_login(client: &Client, device_name: &str, redirect_uri: Option<&str>) -> (String, Option<String>) {
    let uuid = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, "device-uuid");
    let redirect = redirect_uri.map(|r| format!(r#","redirectUri":"{r}""#)).unwrap_or_default();
    let resp = client
        .post("/api/oidc/auth")
        .header(ContentType::JSON)
        .header(Header::new("Host", "rustdesk.example.com"))
        .header(Header::new("X-Forwarded-Proto", "https"))
        .body(format!(r#"{{"op":"dex","id":"123456789","uuid":"{uuid}","deviceInfo":{{"name":"{device_name}","os":"windows","type":"client"}}{redirect}}}"#))
        .dispatch()
        .await;
    let cookie = resp.headers().get_one("Set-Cookie").map(str::to_string);
    let body: Value = resp.into_json().await.unwrap();
    let code = body["code"].as_str().unwrap().to_string();
    (code, cookie)
}

async fn use_stub_idp(client: &Client, code: &str, sub: &str) {
    let state = client.rocket().state::<state::ApiState>().unwrap();
    assert!(state.test_set_oidc_provider(code, std::sync::Arc::new(StubIdp { sub: sub.into() })).await);
    // New OIDC users start inactive; promoting activates them.
    state.test_oidc_login(&sub.to_string()).await;
    state.set_admin(&format!("{sub}@example.org"), true).await.unwrap();
}

/// The IdP redirecting the browser back; `cookie` is what that browser holds.
async fn callback(client: &Client, code: &str, cookie: Option<&str>) -> String {
    let mut req = client.get(format!("/api/oidc/callback?code=idp-code&state={code}"));
    if let Some(c) = cookie {
        req = req.cookie(rocket::http::Cookie::parse(c.to_string()).unwrap().into_owned());
    }
    let resp = req.dispatch().await;
    match resp.headers().get_one("Location") {
        Some(loc) => format!("REDIRECT {loc}"),
        None => resp.into_string().await.unwrap_or_default(),
    }
}

async fn poll(client: &Client, code: &str) -> Value {
    let resp = client.get(format!("/api/oidc/auth-query?code={code}&id=123456789&uuid=x")).dispatch().await;
    resp.into_json().await.unwrap()
}

fn confirm_token(page: &str) -> String {
    let at = page.find(r#"name="token" value=""#).expect("confirmation page has a token") + r#"name="token" value=""#.len();
    page[at..at + page[at..].find('"').unwrap()].to_string()
}

async fn confirm(client: &Client, code: &str, token: &str, approve: bool) -> String {
    let resp = client
        .post("/api/oidc/confirm")
        .header(ContentType::Form)
        .body(format!("state={code}&token={token}&approve={approve}"))
        .dispatch()
        .await;
    resp.into_string().await.unwrap_or_default()
}

#[rocket::async_test]
async fn test_oidc_login_sets_a_browser_cookie() {
    let client = untracked_client().await;
    let (_, cookie) = start_login(&client, "PC", None).await;
    let cookie = cookie.expect("login start sets a cookie");
    for attr in ["HttpOnly", "SameSite=Lax", "Path=/api/oidc", "Secure"] {
        assert!(cookie.contains(attr), "{attr} missing in {cookie}");
    }
}

#[rocket::async_test]
async fn test_oidc_login_in_the_starting_browser_needs_no_confirmation() {
    let client = untracked_client().await;
    let (code, cookie) = start_login(&client, "PC", None).await;
    use_stub_idp(&client, &code, "alice").await;
    let page = callback(&client, &code, cookie.as_deref()).await;
    assert!(page.contains("Login successful"), "{page}");
    let r = poll(&client, &code).await;
    assert!(r["access_token"].is_string(), "{r}");
}

#[rocket::async_test]
async fn test_oidc_forwarded_login_link_does_not_log_the_attacker_in() {
    let client = untracked_client().await;
    let (code, _attacker_cookie) = start_login(&client, "ATTACKER-PC", None).await;
    use_stub_idp(&client, &code, "victim").await;
    // The victim's browser never saw the attacker's cookie.
    let page = callback(&client, &code, None).await;
    assert!(page.contains("ATTACKER-PC") && page.contains("Approve"), "{page}");
    assert!(poll(&client, &code).await.is_null(), "token handed out without confirmation");
    // Knowing the code is not enough to approve.
    confirm(&client, &code, "guessed", true).await;
    assert!(poll(&client, &code).await.is_null(), "approved with a wrong token");
}

#[rocket::async_test]
async fn test_oidc_native_login_is_approved_on_the_confirmation_page() {
    let client = untracked_client().await;
    let (code, _) = start_login(&client, "MY-LAPTOP", None).await;
    use_stub_idp(&client, &code, "alice").await;
    let page = callback(&client, &code, None).await;
    let result = confirm(&client, &code, &confirm_token(&page), true).await;
    assert!(result.contains("Login successful"), "{result}");
    assert!(poll(&client, &code).await["access_token"].is_string());
}

#[rocket::async_test]
async fn test_oidc_denied_login_is_dropped() {
    let client = untracked_client().await;
    let (code, _) = start_login(&client, "UNKNOWN-PC", None).await;
    use_stub_idp(&client, &code, "alice").await;
    let page = callback(&client, &code, None).await;
    confirm(&client, &code, &confirm_token(&page), false).await;
    assert!(poll(&client, &code).await.is_null());
    let token = confirm_token(&page);
    let again = confirm(&client, &code, &token, true).await;
    assert!(!again.contains("Login successful"), "{again}");
    assert!(poll(&client, &code).await.is_null());
}

#[rocket::async_test]
async fn test_oidc_confirmation_page_escapes_the_device_name() {
    let client = untracked_client().await;
    let (code, _) = start_login(&client, "<script>x</script>", None).await;
    use_stub_idp(&client, &code, "alice").await;
    let page = callback(&client, &code, None).await;
    assert!(!page.contains("<script>x"), "{page}");
    assert!(page.contains("&lt;script&gt;x"), "{page}");
}

#[rocket::async_test]
async fn test_oidc_pending_logins_expire() {
    let client = untracked_client().await;
    let (code, cookie) = start_login(&client, "PC", None).await;
    use_stub_idp(&client, &code, "alice").await;
    let state = client.rocket().state::<state::ApiState>().unwrap();
    assert!(state.test_age_oidc_session(&code, 3600).await);
    let page = callback(&client, &code, cookie.as_deref()).await;
    assert!(page.contains("Login failed"), "{page}");
    assert!(poll(&client, &code).await.is_null());
}

#[rocket::async_test]
async fn test_oidc_redirect_uri_must_be_on_this_server() {
    let client = untracked_client().await;
    let (code, _) = start_login(&client, "PC", Some("https://evil.example.com/steal")).await;
    assert!(code.is_empty() || code.contains("ERROR"), "foreign redirect accepted: {code}");

    let (code, cookie) = start_login(&client, "PC", Some("https://rustdesk.example.com/ui/login")).await;
    assert!(!code.is_empty() && !code.contains("ERROR"), "{code}");
    use_stub_idp(&client, &code, "alice").await;
    let page = callback(&client, &code, cookie.as_deref()).await;
    assert!(page.starts_with("REDIRECT https://rustdesk.example.com/ui/login?oidc_code="), "{page}");
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
async fn test_oidc_state_invalid_session() {
    let (client, _dir) = test_client().await;
    let resp = client
        .get("/api/oidc/auth-query?code=fake&id=fake&uuid=fake")
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert!(body.is_null());
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
