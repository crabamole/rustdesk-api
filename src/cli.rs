//! Command line: `serve` runs the HTTP API; `admin` manages admins directly in the
//! database, so only someone with access to the host or pod can use it; `openapi` prints the API spec.
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
        /// off, critical, normal or debug
        #[arg(long = "log_level", default_value = "debug")]
        log_level: String,
    },
    /// Manage admins directly in the database (needs DATABASE_URL)
    #[command(subcommand)]
    Admin(AdminCommand),
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
    Ok(if admin {
        format!("{name} is now an admin")
    } else {
        format!("{name} is no longer an admin")
    })
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
            Command::Serve { address, port, log_level } => {
                assert_eq!((address.as_str(), port, log_level.as_str()), ("0.0.0.0", 21120, "debug"));
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
    }

    #[rocket::async_test]
    async fn promote_unknown_user_fails() {
        let db_url = state::testing::fresh_database_url().await;
        let err = run_admin(&AdminCommand::Promote { email: "nobody@example.org".to_string() }, &db_url)
            .await
            .unwrap_err();
        assert!(err.contains("no user has email \"nobody@example.org\""), "{err}");
    }
}
