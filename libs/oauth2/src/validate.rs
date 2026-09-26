//! Strict loading of `oauth2.toml`, used at startup and by `rustdesk-api oidc check`.
use std::collections::HashSet;

use crate::{Config, Provider, ProviderConfig};

/// Provider types with an implementation; the others are placeholders.
const IMPLEMENTED: [Provider; 3] = [Provider::Oauth2, Provider::Dex, Provider::Github];

/// Reads and validates the OIDC provider file, returning every problem found.
pub fn load_providers(path: &str) -> Result<Vec<ProviderConfig>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read OIDC provider file {path}: {e}"))?;
    let config: Config =
        toml::from_str(&content).map_err(|e| format!("{path} is not a valid provider file: {e}"))?;
    let problems = check(&config.provider);
    if problems.is_empty() {
        Ok(config.provider)
    } else {
        Err(format!("{path} has problems:\n{}", problems.iter().map(|p| format!("  - {p}")).collect::<Vec<_>>().join("\n")))
    }
}

/// Whether each provider's token endpoint answers over HTTP(S) from here: any HTTP
/// status counts, so this catches DNS, network and TLS (e.g. untrusted CA) failures.
pub async fn check_reachable(providers: &[ProviderConfig]) -> Vec<(String, Result<u16, String>)> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("reqwest client");
    let mut results = Vec::new();
    for p in providers {
        let res = client
            .get(&p.token_exchange_url)
            .send()
            .await
            .map(|r| r.status().as_u16())
            .map_err(|e| {
                let mut msg = e.to_string();
                let mut src = std::error::Error::source(&e);
                while let Some(s) = src {
                    msg = format!("{msg}: {s}");
                    src = s.source();
                }
                msg
            });
        results.push((p.op.clone(), res));
    }
    results
}

fn check(providers: &[ProviderConfig]) -> Vec<String> {
    let mut problems = Vec::new();
    if providers.is_empty() {
        problems.push("no [[provider]] defined; login is OIDC-only, so at least one is required".to_string());
    }
    let mut ops = HashSet::new();
    let mut types = HashSet::new();
    for (i, p) in providers.iter().enumerate() {
        let at = format!("provider #{} (op = {:?})", i + 1, p.op);
        if !IMPLEMENTED.contains(&p.provider) {
            problems.push(format!(
                "{at}: provider = {:?} is not implemented; use \"Oauth2\" for a generic OIDC provider (Azure AD, Okta, Keycloak, ...)",
                p.provider
            ));
        }
        for (field, value) in [("app_id", &p.app_id), ("app_secret", &p.app_secret), ("op", &p.op), ("scope", &p.scope)] {
            if value.trim().is_empty() {
                problems.push(format!("{at}: {field} is empty"));
            }
        }
        for (field, value) in [("authorization_url", &p.authorization_url), ("token_exchange_url", &p.token_exchange_url)] {
            match url::Url::parse(value) {
                Ok(u) if u.scheme() == "https" || u.scheme() == "http" => {}
                _ => problems.push(format!("{at}: {field} {value:?} is not an http(s) URL")),
            }
        }
        if p.op_auth_string != format!("oidc/{}", p.op) {
            problems.push(format!("{at}: op_auth_string must be \"oidc/{}\" (clients send op back), got {:?}", p.op, p.op_auth_string));
        }
        if p.provider != Provider::Github && !matches!(url::Url::parse(&p.issuer), Ok(u) if u.scheme() == "https" || u.scheme() == "http") {
            problems.push(format!("{at}: issuer {:?} must be the provider's issuer URL (the iss claim of its ID tokens)", p.issuer));
        }
        if p.provider != Provider::Github && !p.scope.split_whitespace().any(|s| s == "openid") {
            problems.push(format!("{at}: scope must include \"openid\" (users are identified by the ID token's sub)"));
        }
        if !ops.insert(p.op.clone()) {
            problems.push(format!("{at}: duplicate op"));
        }
        if !types.insert(p.provider) {
            problems.push(format!("{at}: only one provider of type {:?} is supported", p.provider));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[[provider]]
provider = "Oauth2"
authorization_url = "https://idp.example.com/authorize"
token_exchange_url = "https://idp.example.com/token"
app_id = "rustdesk"
app_secret = "s3cret"
scope = "openid email profile"
op_auth_string = "oidc/corp"
op = "corp"
issuer = "https://idp.example.com"
"#;

    fn load(toml: &str) -> Result<Vec<ProviderConfig>, String> {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), toml).unwrap();
        load_providers(f.path().to_str().unwrap())
    }

    #[test]
    fn accepts_a_generic_oidc_provider() {
        let p = load(GOOD).unwrap();
        assert_eq!((p.len(), p[0].provider), (1, Provider::Oauth2));
    }

    #[test]
    fn oidc_providers_need_an_issuer() {
        let err = load(&GOOD.replace("issuer = \"https://idp.example.com\"\n", "")).unwrap_err();
        assert!(err.contains("issuer"), "{err}");
        let err = load(&GOOD.replace("https://idp.example.com\"\n", "not a url\"\n")).unwrap_err();
        assert!(err.contains("issuer"), "{err}");
    }

    #[test]
    fn missing_file_is_an_error() {
        let err = load_providers("/nonexistent/oauth2.toml").unwrap_err();
        assert!(err.contains("cannot read"), "{err}");
    }

    #[test]
    fn malformed_toml_is_an_error() {
        assert!(load("[[provider]\nnope").unwrap_err().contains("not a valid provider file"));
        assert!(load("[[provider]]\nprovider = \"Oauth2\"\n").unwrap_err().contains("not a valid provider file"));
    }

    #[test]
    fn no_providers_is_an_error() {
        assert!(load("provider = []\n").unwrap_err().contains("no [[provider]]"));
    }

    #[test]
    fn unimplemented_provider_types_are_rejected_with_a_hint() {
        let err = load(&GOOD.replace("\"Oauth2\"", "\"Azure\"")).unwrap_err();
        assert!(err.contains("Azure") && err.contains("use \"Oauth2\""), "{err}");
    }

    #[test]
    fn reports_every_problem() {
        let bad = GOOD
            .replace("app_secret = \"s3cret\"", "app_secret = \"\"")
            .replace("https://idp.example.com/token", "not a url")
            .replace("oidc/corp", "oidc/other")
            .replace("openid email profile", "email profile");
        let err = load(&bad).unwrap_err();
        for expected in ["app_secret is empty", "token_exchange_url", "op_auth_string must be \"oidc/corp\"", "must include \"openid\""] {
            assert!(err.contains(expected), "missing {expected:?} in {err}");
        }
    }

    #[tokio::test]
    async fn check_reachable_reports_http_status_or_error() {
        // Answers every connection with a 405, like a token endpoint receiving a GET.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for mut stream in listener.incoming().flatten() {
                let _ = stream.read(&mut [0u8; 1024]);
                let _ = stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            }
        });
        let mut providers = load(GOOD).unwrap();
        providers[0].token_exchange_url = format!("http://127.0.0.1:{port}/token");
        let mut closed = providers[0].clone();
        closed.op = "closed".into();
        closed.token_exchange_url = "http://127.0.0.1:1/token".into();
        providers.push(closed);

        let results = check_reachable(&providers).await;
        assert_eq!(results[0], ("corp".to_string(), Ok(405)));
        assert_eq!(results[1].0, "closed");
        assert!(results[1].1.is_err());
    }

    #[test]
    fn duplicate_ops_and_types_are_rejected() {
        let err = load(&format!("{GOOD}{GOOD}")).unwrap_err();
        assert!(err.contains("duplicate op") && err.contains("only one provider of type Oauth2"), "{err}");
    }
}
