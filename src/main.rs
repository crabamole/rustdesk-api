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
use rocket::{
    config::LogLevel,
    data::{Limits, ToByteUnit},
};
use rustdesk_api::cli::{run_admin, Cli, Command};
use rustdesk_api::{build_rocket, database_url_from_env};
use clap::Parser;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use getrandom::getrandom;

fn db_url_or_exit() -> String {
    database_url_from_env().unwrap_or_else(|msg| {
        eprintln!("{msg}");
        std::process::exit(2);
    })
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let (address, port, log_level) = match Cli::parse().command {
        Command::Serve { address, port, log_level } => (address, port, log_level),
        Command::Admin(cmd) => match run_admin(&cmd, &db_url_or_exit()).await {
            Ok(msg) => {
                println!("{msg}");
                return Ok(());
            }
            Err(msg) => {
                eprintln!("{msg}");
                std::process::exit(1);
            }
        },
    };
    let log_level = match log_level.to_lowercase().as_str() {
        "off" => LogLevel::Off,
        "critical" => LogLevel::Critical,
        "normal" => LogLevel::Normal,
        "debug" => LogLevel::Debug,
        _ => LogLevel::Debug,
    };
    let mut key_bytes = [0u8; 32];
    getrandom(&mut key_bytes).expect("failed to generate random secret key");
    let secret_key = BASE64.encode(key_bytes);

    // Configure Rocket
    let figment = rocket::Config::figment()
        .merge(("address", address))
        .merge(("port", port))
        .merge(("log_level", log_level))
        .merge(("secret_key", secret_key))
        .merge(("ident", format!("rustdesk-api/{}", env!("CARGO_PKG_VERSION"))))
        .merge(("limits", Limits::new().limit("json", 2.mebibytes())));

    #[cfg(all(unix, feature = "coverage"))]
    {
        extern "C" {
            fn __llvm_profile_write_file() -> i32;
        }
        unsafe {
            let _ = signal_hook::low_level::register(signal_hook::consts::SIGUSR1, || {
                let _ = __llvm_profile_write_file();
            });
        }
    }

    // Launch Rocket
    let db_url = db_url_or_exit();
    let _rocket = build_rocket(figment, &db_url).await.ignite().await?.launch().await?;
    
    // End of API Server start
    // Other stuff here
    Ok(())
}
