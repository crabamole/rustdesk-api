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
use std::fs;
use std::process::Command;
use std::str;

fn main() {

    println!("cargo:rerun-if-changed=webconsole");

    stamp_webconsole_version(env!("CARGO_PKG_VERSION"));

    let is_windows = cfg!(target_os = "windows");

    let (command, install_args, build_args) = if is_windows {
        ("cmd.exe", &["/C", "npm install --force"], &["/C", "npm run build"])
    } else {
        ("npm", &["install", "--force"], &["run", "build"])
    };

    // Install npm dependencies for webconsole
    let output = Command::new(command)
        .current_dir("webconsole")
        .args(install_args)
        .output()
        .expect("Failed to execute command");
    assert!(
        output.status.success(),
        "Failed to install npm dependencies: {}{}",
        str::from_utf8(&output.stdout).unwrap_or(""),
        str::from_utf8(&output.stderr).unwrap_or("")
    );

    // Build webconsole
    let output = Command::new(command)
        .current_dir("webconsole")
        .args(build_args)
        .output()
        .expect("Failed to execute command");
    assert!(
        output.status.success(),
        "Failed to build webconsole: {}{}",
        str::from_utf8(&output.stdout).unwrap_or(""),
        str::from_utf8(&output.stderr).unwrap_or("")
    );

    // Install npm dependencies for rapidoc
        let output = Command::new(command)
        .current_dir("rapidoc")
        .args(install_args)
        .output()
        .expect("Failed to execute command");
    assert!(
        output.status.success(),
        "Failed to install npm dependencies: {}{}",
        str::from_utf8(&output.stdout).unwrap_or(""),
        str::from_utf8(&output.stderr).unwrap_or("")
    );

    // Build rapidoc
    let output = Command::new(command)
        .current_dir("rapidoc")
        .args(build_args)
        .output()
        .expect("Failed to execute command");
    assert!(
        output.status.success(),
        "Failed to build rapidoc: {}{}",
        str::from_utf8(&output.stdout).unwrap_or(""),
        str::from_utf8(&output.stderr).unwrap_or("")
    );

}

/// Keep the webconsole version in sync with Cargo.toml, the single source of
/// the version. Only the version line is touched, and only when it differs,
/// so builds leave package.json unchanged.
fn stamp_webconsole_version(version: &str) {
    let path = "./webconsole/package.json";
    let data = fs::read_to_string(path).unwrap();
    let package: serde_json::Value = serde_json::from_str(&data).unwrap();
    let current = package["version"].as_str().unwrap_or_default();
    if current == version {
        return;
    }
    let old = format!("\"version\": \"{}\"", current);
    let new = format!("\"version\": \"{}\"", version);
    assert!(data.contains(&old), "webconsole/package.json: version line not found");
    fs::write(path, data.replacen(&old, &new, 1)).unwrap();
}
