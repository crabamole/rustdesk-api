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
    state.set_admin("admin", true).await.unwrap();
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

#[rocket::async_test]
async fn test_heartbeat() {
    let (client, _dir) = test_client().await;
    let resp = client
        .post("/api/heartbeat")
        .header(ContentType::JSON)
        .body(r#"{"id":"test123","modified_at":1704067200,"uuid":"abc","ver":1}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_string().await.unwrap();
    assert_eq!(body, "OK");
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
    let resp = client
        .get("/api/stategies")
        .header(ContentType::JSON)
        .header(auth_header(&token))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
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

#[rocket::async_test]
async fn test_openapi_json() {
    let (client, _dir) = test_client().await;
    let resp = client.get("/openapi.json").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = resp.into_json().await.unwrap();
    assert!(body["openapi"].as_str().is_some());
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
