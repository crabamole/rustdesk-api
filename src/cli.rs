//! Command line: `serve` runs the HTTP API; `admin` manages admins directly in the
//! database, so only someone with access to the host or pod can use it.
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
}

#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Make a user an active admin. The user must have logged in through OIDC once.
    Promote { user: String },
    /// Take admin rights away from a user
    Demote { user: String },
}

/// Runs an `admin` subcommand and returns the message to print.
pub async fn run_admin(cmd: &AdminCommand, db_url: &str) -> Result<String, String> {
    let (user, admin) = match cmd {
        AdminCommand::Promote { user } => (user, true),
        AdminCommand::Demote { user } => (user, false),
    };
    let state = ApiState::new_with_db(db_url).await;
    state
        .set_admin(user, admin)
        .await
        .ok_or_else(|| format!("no user named {user:?}; users are created on their first OIDC login"))?;
    Ok(if admin {
        format!("{user} is now an admin")
    } else {
        format!("{user} is no longer an admin")
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

    #[test]
    fn admin_promote_and_demote_take_a_user() {
        let cli = Cli::try_parse_from(["rustdesk-api", "admin", "promote", "alice"]).unwrap();
        assert!(matches!(cli.command, Command::Admin(AdminCommand::Promote { user }) if user == "alice"));
        let cli = Cli::try_parse_from(["rustdesk-api", "admin", "demote", "alice"]).unwrap();
        assert!(matches!(cli.command, Command::Admin(AdminCommand::Demote { user }) if user == "alice"));
        assert!(Cli::try_parse_from(["rustdesk-api", "admin", "promote"]).is_err());
    }

    #[rocket::async_test]
    async fn promote_then_demote_an_oidc_user() {
        let db_url = state::testing::fresh_database_url().await;
        let state = ApiState::new_with_db(&db_url).await;
        state.test_oidc_login(&"alice".to_string()).await;

        let promote = AdminCommand::Promote { user: "alice".to_string() };
        assert_eq!(run_admin(&promote, &db_url).await.unwrap(), "alice is now an admin");
        let (info, _) = state.test_oidc_login(&"alice".to_string()).await.unwrap();
        assert!(info.admin);

        let demote = AdminCommand::Demote { user: "alice".to_string() };
        assert_eq!(run_admin(&demote, &db_url).await.unwrap(), "alice is no longer an admin");
        let (info, _) = state.test_oidc_login(&"alice".to_string()).await.unwrap();
        assert!(!info.admin);
    }

    #[rocket::async_test]
    async fn promote_unknown_user_fails() {
        let db_url = state::testing::fresh_database_url().await;
        let err = run_admin(&AdminCommand::Promote { user: "nobody".to_string() }, &db_url)
            .await
            .unwrap_err();
        assert!(err.contains("nobody"), "{err}");
    }
}
