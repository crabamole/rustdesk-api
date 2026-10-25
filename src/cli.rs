//! Command line: `serve` runs the HTTP API; `admin`, `policy` and `peer` work directly on the database, so only someone with access to the host or pod can use them; `openapi` prints the API spec.
use clap::{Parser, Subcommand};
use state::ApiState;

#[derive(Parser, Debug)]
#[command(
    name = "rustdesk-api",
    version,
    about = "RustDesk API server and super admin CLI",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the HTTP API server (needs DATABASE_URL)
    Serve {
        /// Address to listen on
        #[arg(long, default_value = "127.0.0.1")]
        address: String,
        /// Port to listen on
        #[arg(long, default_value_t = 21114)]
        port: u16,
    },
    /// Manage admins directly in the database (needs DATABASE_URL)
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Show or re-push the device policy (needs DATABASE_URL)
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Manage registered devices (needs DATABASE_URL)
    #[command(subcommand)]
    Peer(PeerCommand),
    /// Check the OIDC provider file
    #[command(subcommand)]
    Oidc(OidcCommand),
    /// Print the OpenAPI spec of the HTTP API as JSON
    Openapi,
}

#[derive(Subcommand, Debug)]
pub enum OidcCommand {
    /// Validate the provider file and check each token endpoint is reachable from here
    Check {
        /// Provider file (default: $OAUTH2_CONFIG_FILE, else oauth2.toml)
        #[arg(long)]
        file: Option<String>,
    },
}

/// The OIDC provider file to use: `file`, else `$OAUTH2_CONFIG_FILE`, else `oauth2.toml`.
pub fn providers_file(file: Option<&str>) -> String {
    file.map(str::to_string).unwrap_or_else(oauth2::get_providers_config_file)
}

/// Runs `oidc check`: validates `file` and probes each provider's token endpoint.
pub async fn run_oidc_check(file: &str) -> Result<String, String> {
    let providers = oauth2::validate::load_providers(file)?;
    let mut lines = vec![format!("{file}: {} provider(s), configuration OK", providers.len())];
    let mut ok = true;
    for (op, res) in oauth2::validate::check_reachable(&providers).await {
        match res {
            Ok(status) => lines.push(format!("  {op}: token endpoint reachable (HTTP {status})")),
            Err(e) => {
                ok = false;
                lines.push(format!("  {op}: token endpoint unreachable: {e}"));
            }
        }
    }
    let out = lines.join("\n");
    if ok { Ok(out) } else { Err(out) }
}

/// Runs `openapi`: the spec of the HTTP API, as pretty-printed JSON.
pub fn run_openapi() -> Result<String, String> {
    serde_json::to_string_pretty(&crate::api_routes().1).map_err(|e| e.to_string())
}

#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Make a user an active admin; the user must have logged in through OIDC once
    Promote {
        /// The user's email, as the IdP reports it (case-insensitive)
        email: String,
    },
    /// Take admin rights away from a user
    Demote {
        /// The user's email, as the IdP reports it (case-insensitive)
        email: String,
    },
}

/// Runs an `admin` subcommand and returns the message to print.
pub async fn run_admin(cmd: &AdminCommand, db_url: &str) -> Result<String, String> {
    let (email, admin) = match cmd {
        AdminCommand::Promote { email } => (email, true),
        AdminCommand::Demote { email } => (email, false),
    };
    let state = ApiState::new_with_db(db_url).await;
    let name = state.set_admin(email, admin).await?;
    let iop = if admin { utils::console_log::IOP_PROMOTE_ADMIN } else { utils::console_log::IOP_DEMOTE_ADMIN };
    state.log_console(None, utils::console_log::TYP_USER, iop, serde_json::json!({ "email": email, "via": "cli" })).await;
    Ok(if admin {
        format!("{name} is now an admin")
    } else {
        format!("{name} is no longer an admin")
    })
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Print the managed settings
    Show,
    /// Send the policy to every device again; reverts local changes to managed settings on all devices
    Repush,
}

/// Runs a `policy` subcommand and returns the message to print.
pub async fn run_policy(cmd: &PolicyCommand, db_url: &str) -> Result<String, String> {
    let guid = utils::policy::DEFAULT_STRATEGY_GUID;
    let state = ApiState::new_with_db(db_url).await;
    match cmd {
        PolicyCommand::Show => {
            let (s, options) = state.get_strategy(guid).await.ok_or("cannot read the policy")?;
            let mut lines = vec![format!("modified_at: {}", s.modified_at)];
            if options.is_empty() {
                lines.push("no settings managed".to_string());
            }
            for (k, v) in options {
                lines.push(format!("{k} = {}", if v.is_empty() { "(device default)" } else { &v }));
            }
            Ok(lines.join("\n"))
        }
        PolicyCommand::Repush => {
            let m = state.bump_strategy(guid).await.ok_or("cannot update the policy")?;
            state.log_console(None, utils::console_log::TYP_POLICY, utils::console_log::IOP_REPUSH_POLICY, serde_json::json!({ "guid": guid, "via": "cli" })).await;
            log::info!("policy re-pushed from the CLI");
            Ok(format!("policy re-pushed (modified_at {m}); devices receive it on their next heartbeat"))
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum PeerCommand {
    /// Let device ID take a new key at its next registration, e.g. after a reinstall; also ends its owner
    ResetKey {
        /// The device's RustDesk ID
        id: String,
    },
    /// Let device ID be controlled while DEVICE_ADMISSION=Y
    Admit {
        /// The device's RustDesk ID
        id: String,
    },
    /// Refuse every connection to device ID while DEVICE_ADMISSION=Y
    Reject {
        /// The device's RustDesk ID
        id: String,
    },
    /// Put device ID back to pending
    Pending {
        /// The device's RustDesk ID
        id: String,
    },
}

/// Runs a `peer` subcommand and returns the message to print.
pub async fn run_peer(cmd: &PeerCommand, db_url: &str) -> Result<String, String> {
    let state = ApiState::new_with_db(db_url).await;
    let (id, admission) = match cmd {
        PeerCommand::ResetKey { id } => {
            let had_key = state.reset_device_key(id).await.ok_or("cannot reset the key")?.ok_or(format!("no device {id}"))?;
            if !had_key {
                return Ok(format!("{id}: key already reset; its next registration sets the key"));
            }
            state.log_console(None, utils::console_log::TYP_DEVICE, utils::console_log::IOP_RESET_DEVICE_KEY, serde_json::json!({ "device": id, "via": "cli" })).await;
            return Ok(format!("{id}: key reset; its next registration sets the key"));
        }
        PeerCommand::Admit { id } => (id, utils::Admission::Admitted),
        PeerCommand::Reject { id } => (id, utils::Admission::Rejected),
        PeerCommand::Pending { id } => (id, utils::Admission::Pending),
    };
    let word = serde_json::to_value(admission).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
    let old = state.set_device_admission(id, admission, "cli").await.ok_or("cannot set the admission")?.ok_or(format!("no device {id}"))?;
    if old == admission {
        return Ok(format!("{id}: already {word}"));
    }
    state.log_console(None, utils::console_log::TYP_DEVICE, utils::console_log::iop_for_admission(admission), serde_json::json!({ "device": id, "via": "cli" })).await;
    Ok(format!("{id}: {word}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn no_arguments_shows_help() {
        let err = Cli::try_parse_from(["rustdesk-api"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand);
    }

    #[test]
    fn serve_takes_the_server_flags() {
        let cli = Cli::try_parse_from(["rustdesk-api", "serve", "--address", "0.0.0.0", "--port", "21120"]).unwrap();
        match cli.command {
            Command::Serve { address, port } => {
                assert_eq!((address.as_str(), port), ("0.0.0.0", 21120));
            }
            other => panic!("expected serve, got {other:?}"),
        }
    }

    fn temp_file(content: &str) -> String {
        let path = std::env::temp_dir().join(format!("oauth2-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().into_owned()
    }

    const PROVIDER: &str = r#"
[[provider]]
provider = "Oauth2"
authorization_url = "https://idp.example.com/authorize"
token_exchange_url = "http://127.0.0.1:1/token"
app_id = "rustdesk"
app_secret = "s3cret"
scope = "openid email profile"
op_auth_string = "oidc/corp"
op = "corp"
issuer = "https://idp.example.com"
"#;

    #[test]
    fn oidc_check_takes_an_optional_file() {
        let cli = Cli::try_parse_from(["rustdesk-api", "oidc", "check", "--file", "/x.toml"]).unwrap();
        assert!(matches!(cli.command, Command::Oidc(OidcCommand::Check { file: Some(f) }) if f == "/x.toml"));
        assert_eq!(providers_file(Some("/x.toml")), "/x.toml");
    }

    #[rocket::async_test]
    async fn oidc_check_reports_invalid_files() {
        let err = run_oidc_check(&temp_file("[[provider]]\nprovider = \"Azure\"\n")).await.unwrap_err();
        assert!(err.contains("not a valid provider file"), "{err}");
    }

    #[rocket::async_test]
    async fn oidc_check_reports_unreachable_token_endpoints() {
        let err = run_oidc_check(&temp_file(PROVIDER)).await.unwrap_err();
        assert!(err.contains("configuration OK") && err.contains("corp: token endpoint unreachable"), "{err}");
    }

    #[test]
    fn openapi_prints_the_spec() {
        let cli = Cli::try_parse_from(["rustdesk-api", "openapi"]).unwrap();
        assert!(matches!(cli.command, Command::Openapi));
        let spec: serde_json::Value = serde_json::from_str(&run_openapi().unwrap()).unwrap();
        assert!(spec["paths"]["/api/login"].is_object());
    }

    #[test]
    fn admin_promote_and_demote_take_a_user() {
        let cli = Cli::try_parse_from(["rustdesk-api", "admin", "promote", "alice@example.org"]).unwrap();
        assert!(matches!(cli.command, Command::Admin(AdminCommand::Promote { email }) if email == "alice@example.org"));
        let cli = Cli::try_parse_from(["rustdesk-api", "admin", "demote", "alice@example.org"]).unwrap();
        assert!(matches!(cli.command, Command::Admin(AdminCommand::Demote { email }) if email == "alice@example.org"));
        assert!(Cli::try_parse_from(["rustdesk-api", "admin", "promote"]).is_err());
    }

    #[rocket::async_test]
    async fn promote_then_demote_an_oidc_user() {
        let db_url = state::testing::fresh_database_url().await;
        let state = ApiState::new_with_db(&db_url).await;
        state.test_oidc_login(&"alice".to_string()).await;

        let promote = AdminCommand::Promote { email: "alice@example.org".to_string() };
        assert_eq!(run_admin(&promote, &db_url).await.unwrap(), "alice is now an admin");
        let (info, _) = state.test_oidc_login(&"alice".to_string()).await.unwrap();
        assert!(info.admin);

        let demote = AdminCommand::Demote { email: "alice@example.org".to_string() };
        assert_eq!(run_admin(&demote, &db_url).await.unwrap(), "alice is no longer an admin");
        let (info, _) = state.test_oidc_login(&"alice".to_string()).await.unwrap();
        assert!(!info.admin);

        let q = utils::AuditQuery { offset: 0, limit: 10, created_at: None, pattern: Some("CLI".into()), conn_type: None };
        let (total, rows) = ApiState::new_with_db(&db_url).await.list_audit_consoles(&q).await.unwrap();
        assert_eq!(total, 2);
        assert_eq!((rows[0].iop, rows[1].iop), (24, 23));
    }

    #[rocket::async_test]
    async fn promote_unknown_user_fails() {
        let db_url = state::testing::fresh_database_url().await;
        let err = run_admin(&AdminCommand::Promote { email: "nobody@example.org".to_string() }, &db_url)
            .await
            .unwrap_err();
        assert!(err.contains("no user has email \"nobody@example.org\""), "{err}");
    }

    #[test]
    fn policy_takes_show_and_repush() {
        let cli = Cli::try_parse_from(["rustdesk-api", "policy", "show"]).unwrap();
        assert!(matches!(cli.command, Command::Policy(PolicyCommand::Show)));
        let cli = Cli::try_parse_from(["rustdesk-api", "policy", "repush"]).unwrap();
        assert!(matches!(cli.command, Command::Policy(PolicyCommand::Repush)));
    }

    #[rocket::async_test]
    async fn policy_show_then_repush() {
        let db_url = state::testing::fresh_database_url().await;
        let state = ApiState::new_with_db(&db_url).await;
        let opts = [("enable-clipboard".to_string(), "N".to_string())].into();
        let m = state.set_strategy_options(utils::policy::DEFAULT_STRATEGY_GUID, &opts).await.unwrap();

        let shown = run_policy(&PolicyCommand::Show, &db_url).await.unwrap();
        assert!(shown.contains("enable-clipboard = N") && shown.contains(&m.to_string()), "{shown}");

        let pushed = run_policy(&PolicyCommand::Repush, &db_url).await.unwrap();
        assert!(pushed.starts_with("policy re-pushed"), "{pushed}");
        let (s, _) = state.get_strategy(utils::policy::DEFAULT_STRATEGY_GUID).await.unwrap();
        assert!(s.modified_at > m);
    }

    #[rocket::async_test]
    async fn policy_show_empty() {
        let db_url = state::testing::fresh_database_url().await;
        let shown = run_policy(&PolicyCommand::Show, &db_url).await.unwrap();
        assert!(shown.contains("no settings managed"), "{shown}");
    }

    #[test]
    fn peer_takes_reset_key() {
        let cli = Cli::try_parse_from(["rustdesk-api", "peer", "reset-key", "123456789"]).unwrap();
        assert!(matches!(cli.command, Command::Peer(PeerCommand::ResetKey { id }) if id == "123456789"));
    }

    #[rocket::async_test]
    async fn peer_reset_key_empties_the_key_and_logs_once() {
        let db_url = state::testing::fresh_database_url().await;
        let state = ApiState::new_with_db(&db_url).await;
        state.test_register_device("dev-rk", "ZGV2").await;
        let cmd = PeerCommand::ResetKey { id: "dev-rk".to_string() };
        assert_eq!(run_peer(&cmd, &db_url).await.unwrap(), "dev-rk: key reset; its next registration sets the key");
        assert_eq!(state.device_pk("dev-rk", "ZGV2").await, Some(Vec::new()));
        assert!(run_peer(&cmd, &db_url).await.unwrap().contains("already reset"));
        let q = utils::AuditQuery { offset: 0, limit: 10, created_at: None, pattern: None, conn_type: None };
        let (_, rows) = state.list_audit_consoles(&q).await.unwrap();
        assert_eq!(rows.iter().filter(|r| r.iop == utils::console_log::IOP_RESET_DEVICE_KEY).count(), 1);
        let err = run_peer(&PeerCommand::ResetKey { id: "nobody".to_string() }, &db_url).await.unwrap_err();
        assert_eq!(err, "no device nobody");
    }

    #[test]
    fn peer_takes_admission_commands() {
        let cli = Cli::try_parse_from(["rustdesk-api", "peer", "admit", "123"]).unwrap();
        assert!(matches!(cli.command, Command::Peer(PeerCommand::Admit { id }) if id == "123"));
        let cli = Cli::try_parse_from(["rustdesk-api", "peer", "reject", "123"]).unwrap();
        assert!(matches!(cli.command, Command::Peer(PeerCommand::Reject { id }) if id == "123"));
        let cli = Cli::try_parse_from(["rustdesk-api", "peer", "pending", "123"]).unwrap();
        assert!(matches!(cli.command, Command::Peer(PeerCommand::Pending { id }) if id == "123"));
    }

    #[rocket::async_test]
    async fn peer_admit_sets_the_state_and_logs_once() {
        let db_url = state::testing::fresh_database_url().await;
        let state = ApiState::new_with_db(&db_url).await;
        state.test_register_device("dev-adm", "ZGV2").await;
        let reject = PeerCommand::Reject { id: "dev-adm".to_string() };
        assert_eq!(run_peer(&reject, &db_url).await.unwrap(), "dev-adm: rejected");
        assert_eq!(run_peer(&reject, &db_url).await.unwrap(), "dev-adm: already rejected");
        assert_eq!(state.device_admission("dev-adm", "ZGV2").await, Some(utils::Admission::Rejected));
        let q = utils::AuditQuery { offset: 0, limit: 10, created_at: None, pattern: None, conn_type: None };
        let (_, rows) = state.list_audit_consoles(&q).await.unwrap();
        assert_eq!(rows.iter().filter(|r| r.iop == utils::console_log::IOP_REJECT_DEVICE).count(), 1);
        let err = run_peer(&PeerCommand::Admit { id: "nobody".to_string() }, &db_url).await.unwrap_err();
        assert_eq!(err, "no device nobody");
    }
}
