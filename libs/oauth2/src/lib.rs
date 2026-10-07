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
pub mod dex_provider;
pub mod github_provider;
pub mod oauth_provider;
pub mod oauth2_provider;
pub mod pkce;
pub mod validate;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
pub mod errors;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ProviderConfig {
    pub provider: Provider,
    pub scope: String,
    pub authorization_url: String,
    pub token_exchange_url: String,
    pub app_id: String,
    pub app_secret: String,
    pub op_auth_string: String,
    pub op: String,
    /// Expected `iss` of the provider's ID tokens; required for OIDC providers.
    #[serde(default)]
    pub issuer: String,
}

#[derive(Deserialize, Serialize, Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Provider {
    Github,
    Gitlab,
    Google,
    Apple,
    Okta,
    Facebook,
    Azure,
    Auth0,
    Dex,
    Oauth2,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    #[serde(deserialize_with = "deserialize_aud")]
    aud: Vec<String>,
    #[serde(default)]
    iss: String,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    exp: u64,
}

fn deserialize_aud<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    struct AudVisitor;
    impl<'de> de::Visitor<'de> for AudVisitor {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or array of strings")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_owned()])
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut aud = Vec::new();
            while let Some(a) = seq.next_element::<String>()? {
                aud.push(a);
            }
            Ok(aud)
        }
    }
    deserializer.deserialize_any(AudVisitor)
}

impl FromStr for Provider {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "github" => Ok(Provider::Github),
            "gitlab" => Ok(Provider::Gitlab),
            "google" => Ok(Provider::Google),
            "apple" => Ok(Provider::Apple),
            "okta" => Ok(Provider::Okta),
            "facebook" => Ok(Provider::Facebook),
            "azure" => Ok(Provider::Azure),
            "auth0" => Ok(Provider::Auth0),
            "custom" => Ok(Provider::Dex),
            "oauth2" => Ok(Provider::Oauth2),
            _ => Err(()),
        }
    }
}

impl Into<String> for Provider {
    fn into(self) -> String {
        match self {
            Provider::Github => "Github".to_string(),
            Provider::Gitlab => "Gitlab".to_string(),
            Provider::Google => "Google".to_string(),
            Provider::Apple => "Apple".to_string(),
            Provider::Okta => "Okta".to_string(),
            Provider::Facebook => "Facebook".to_string(),
            Provider::Azure => "Azure".to_string(),
            Provider::Auth0 => "Auth0".to_string(),
            Provider::Dex => "Dex".to_string(),
            Provider::Oauth2 => "Oauth2".to_string(),
        }
    }
}
#[derive(Deserialize, Serialize)]
pub struct Config {
    pub provider: Vec<ProviderConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

/// Get the providers config from a config file; empty (with the reason logged)
/// if it cannot be used. `serve` validates the file with `validate::load_providers`
/// at startup, so this only fails if the file changes afterwards.
pub fn get_providers_config_from_file(config_file: &str) -> Vec<ProviderConfig> {
    validate::load_providers(config_file).unwrap_or_else(|e| {
        log::error!("{e}");
        Vec::new()
    })
}

/// Get the name of the provider config file
/// from the OAUTH2_CONFIG_FILE environment variable or
/// default to "oauth2.toml"
///
/// # Returns
/// The name of the provider config file
pub fn get_providers_config_file() -> String {
    std::env::var("OAUTH2_CONFIG_FILE").unwrap_or_else(|_| "oauth2.toml".to_string())
}

/// An `ExchangeCodeError` with `context` and the underlying cause.
pub(crate) fn exchange_err(context: &str, cause: impl std::fmt::Display) -> errors::Oauth2Error {
    errors::Oauth2Error::ExchangeCodeError(format!("{}: {}", context, cause))
}

/// Body of a provider response; a non-2xx status becomes an
/// `ExchangeCodeError` carrying the status and the (truncated) body, which
/// is where providers explain what went wrong.
pub(crate) async fn response_text(
    context: &str,
    response: reqwest::Response,
) -> Result<String, errors::Oauth2Error> {
    let status = response.status();
    let text = response.text().await.map_err(|e| exchange_err(context, e))?;
    if !status.is_success() {
        let body: String = text.chars().take(500).collect();
        return Err(exchange_err(context, format!("HTTP {}: {}", status, body)));
    }
    Ok(text)
}

/// One-shot HTTP server for provider tests: answers the first request with
/// `{}` and hands back that request's body. Returns (base url, body receiver).
#[cfg(test)]
pub(crate) fn capture_one_request() -> (String, std::sync::mpsc::Receiver<String>) {
    capture_one_request_with("200 OK", "{}")
}

/// Like [`capture_one_request`], answering with the given status and body.
#[cfg(test)]
pub(crate) fn capture_one_request_with(
    status: &'static str,
    response: &'static str,
) -> (String, std::sync::mpsc::Receiver<String>) {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).unwrap();
        tx.send(String::from_utf8(body).unwrap()).unwrap();
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            )
            .as_bytes(),
        );
    });
    (url, rx)
}

/// The `code` form field of a captured token-exchange request body.
#[cfg(test)]
pub(crate) fn form_code(body: &str) -> String {
    url::form_urlencoded::parse(body.as_bytes())
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth_provider::decode_id_token;

    #[test]
    fn test_get_provider_config_one_provider() {
        let config = r#"
            [[provider]]
            provider = "Github"
            authorization_url = "https://github.com/login/oauth/authorize"
            token_exchange_url = "https://github.com/login/oauth/access_token"
            app_id = "your_github_app_id"
            app_secret = "your_github_app_secret"
            scope = "public_profile"
            op_auth_string = "oidc/facebook"
            op = "facebook"
        "#;

        let config_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(config_file.path(), config).unwrap();

        let providers = get_providers_config_from_file(config_file.path().to_str().unwrap());
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].provider, Provider::Github);
        assert_eq!(
            providers[0].authorization_url,
            "https://github.com/login/oauth/authorize"
        );
        assert_eq!(
            providers[0].token_exchange_url,
            "https://github.com/login/oauth/access_token"
        );
        assert_eq!(providers[0].app_id, "your_github_app_id");
        assert_eq!(providers[0].app_secret, "your_github_app_secret");
    }

    #[test]
    fn test_get_provider_config_two_providers() {
        let config = r#"
            [[provider]]
            provider = "Github"
            authorization_url = "https://github.com/login/oauth/authorize"
            token_exchange_url = "https://github.com/login/oauth/access_token"
            app_id = "your_github_app_id"
            app_secret = "your_github_app_secret"
            scope = "public_profile"
            op_auth_string = "oidc/facebook"
            op = "facebook"

            [[provider]]
            provider = "Oauth2"
            authorization_url = "https://idp.example.com/authorize"
            token_exchange_url = "https://idp.example.com/token"
            app_id = "rustdesk"
            app_secret = "secret"
            scope = "openid email profile"
            op_auth_string = "oidc/corp"
            op = "corp"
            issuer = "https://idp.example.com"
        "#;

        let config_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(config_file.path(), config).unwrap();

        let providers = get_providers_config_from_file(config_file.path().to_str().unwrap());
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn an_invalid_provider_file_loads_as_no_providers() {
        let config_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(config_file.path(), "[[provider]]\nprovider = \"Azure\"\n").unwrap();
        assert!(get_providers_config_from_file(config_file.path().to_str().unwrap()).is_empty());
        assert!(get_providers_config_from_file("/nonexistent/oauth2.toml").is_empty());
    }

    #[test]
    fn test_decode_id_token() {
        let id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhiMjFkMTM0NjExZDQxNWJkMWU2MjUzOGE0ZGRjOTA4NmYxYTZiMjUifQ.eyJpc3MiOiJodHRwczovL2RleC1tb2NrLXNlcnZlci5OT05FL2RleCIsInN1YiI6IkNpUXdPR0U0TmpnMFlpMWtZamc0TFRSaU56TXRPVEJoT1MwelkyUXhOall4WmpVME5qWVNCV3h2WTJGcyIsImF1ZCI6InNjdGdkZXNrLWFwaS1zZXJ2ZXIiLCJleHAiOjE3MTU2NzEwODQsImlhdCI6MTcxNTU4NDY4NCwiYXRfaGFzaCI6IjVvZEdyU3VrMW9lejJkc1NaRXZFM0EiLCJjX2hhc2giOiJfdFZfZFNiU09qTVVmRVdMeVVNSTNnIiwiZW1haWwiOiJhZG1pbkBkZXNrLk5PTkUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImFkbWluIn0.AqOiwBKq2i_AoJcbfxuaVY54PN3GJjnHIn3E2FWoZY2IOu8qxvZevcUb4mjnoUZGf2QaabIcTAIxIg-mpFTRxheOPiQ1c9VSZ0vd-wNGrAG12vdraRq0-evqmFduR2G9k20QMIV8iHiGM7l93k8Fw5_bnTQId044BjepayS98bpUclS4RIIGoOLBM5IenfBCqLhHHv6oYUM6HDU4rCD02U9_Bu597wedeLdYYa7lzBDyb88ab83-eALsDpbFZ90rUnvAhpTQcl9_t51Etx-sP1yWSQ3UZ-QL61cKreqWlMbimM43R4boUWnpQTMF7ZO0EftVixEfaIQvWDRm-TLl8A";
        // A real Dex token from 2024: well-formed, but long expired.
        assert!(decode_id_token(id_token, "https://dex-mock-server.NONE/dex", "sctgdesk-api-server", "").is_err());
    }

    #[test]
    fn test_provider_from_str_all_variants() {
        assert_eq!(Provider::from_str("github").unwrap(), Provider::Github);
        assert_eq!(Provider::from_str("GITHUB").unwrap(), Provider::Github);
        assert_eq!(Provider::from_str("Github").unwrap(), Provider::Github);
        assert_eq!(Provider::from_str("gitlab").unwrap(), Provider::Gitlab);
        assert_eq!(Provider::from_str("google").unwrap(), Provider::Google);
        assert_eq!(Provider::from_str("apple").unwrap(), Provider::Apple);
        assert_eq!(Provider::from_str("okta").unwrap(), Provider::Okta);
        assert_eq!(Provider::from_str("facebook").unwrap(), Provider::Facebook);
        assert_eq!(Provider::from_str("azure").unwrap(), Provider::Azure);
        assert_eq!(Provider::from_str("auth0").unwrap(), Provider::Auth0);
        assert_eq!(Provider::from_str("custom").unwrap(), Provider::Dex);
        assert_eq!(Provider::from_str("oauth2").unwrap(), Provider::Oauth2);
    }

    #[test]
    fn test_provider_from_str_invalid() {
        assert!(Provider::from_str("unknown").is_err());
        assert!(Provider::from_str("").is_err());
    }

    #[test]
    fn test_provider_into_string() {
        let s: String = Provider::Github.into();
        assert_eq!(s, "Github");
        let s: String = Provider::Gitlab.into();
        assert_eq!(s, "Gitlab");
        let s: String = Provider::Google.into();
        assert_eq!(s, "Google");
        let s: String = Provider::Apple.into();
        assert_eq!(s, "Apple");
        let s: String = Provider::Okta.into();
        assert_eq!(s, "Okta");
        let s: String = Provider::Facebook.into();
        assert_eq!(s, "Facebook");
        let s: String = Provider::Azure.into();
        assert_eq!(s, "Azure");
        let s: String = Provider::Auth0.into();
        assert_eq!(s, "Auth0");
        let s: String = Provider::Dex.into();
        assert_eq!(s, "Dex");
        let s: String = Provider::Oauth2.into();
        assert_eq!(s, "Oauth2");
    }

    #[test]
    fn test_provider_serde_roundtrip() {
        let provider = Provider::Github;
        let json = serde_json::to_string(&provider).unwrap();
        let deserialized: Provider = serde_json::from_str(&json).unwrap();
        assert_eq!(provider, deserialized);
    }

    #[test]
    fn test_provider_config_serde_roundtrip() {
        let config = ProviderConfig {
            provider: Provider::Github,
            scope: "read:user".to_string(),
            authorization_url: "https://github.com/login/oauth/authorize".to_string(),
            token_exchange_url: "https://github.com/login/oauth/access_token".to_string(),
            app_id: "test_id".to_string(),
            app_secret: "test_secret".to_string(),
            op_auth_string: "oidc/github".to_string(),
            op: "github".to_string(),
            issuer: "https://idp.example.com".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.provider, Provider::Github);
        assert_eq!(deserialized.app_id, "test_id");
    }

    #[test]
    fn test_deserialize_aud_string() {
        let json = r#"{"aud":"my-app","sub":"user1","name":"Test","email":"test@test.com","exp":9999999999}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.aud, vec!["my-app"]);
    }

    #[test]
    fn test_deserialize_aud_array() {
        let json = r#"{"aud":["my-app","other"],"sub":"user1","name":"Test","email":"test@test.com","exp":9999999999}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.aud, vec!["my-app", "other"]);
    }

    #[test]
    fn test_deserialize_aud_empty_array() {
        let json = r#"{"aud":[],"sub":"user1","name":"Test","email":"test@test.com","exp":9999999999}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert!(claims.aud.is_empty());
    }

    #[test]
    fn test_claims_fields() {
        let json = r#"{"aud":"app","sub":"sub123","name":"Alice","email":"alice@example.com","exp":1234567890}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "sub123");
        assert_eq!(claims.name.as_deref(), Some("Alice"));
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.exp, 1234567890);
    }

    #[test]
    fn test_token_response_serde() {
        let json = r#"{"access_token":"tok123","token_type":"Bearer","expires_in":3600,"id_token":"id_tok","refresh_token":"ref_tok"}"#;
        let tr: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(tr.access_token, "tok123");
        assert_eq!(tr.token_type, "Bearer");
        assert_eq!(tr.expires_in, 3600);
        assert_eq!(tr.id_token.unwrap(), "id_tok");
        assert_eq!(tr.refresh_token.unwrap(), "ref_tok");
    }

    #[test]
    fn test_token_response_optional_fields() {
        let json = r#"{"access_token":"tok","token_type":"Bearer","expires_in":100}"#;
        let tr: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(tr.id_token.is_none());
        assert!(tr.refresh_token.is_none());
    }

    #[test]
    fn test_config_serde() {
        let toml_str = r#"
            [[provider]]
            provider = "Github"
            authorization_url = "https://example.com/auth"
            token_exchange_url = "https://example.com/token"
            app_id = "id"
            app_secret = "secret"
            scope = "read"
            op_auth_string = "oidc/gh"
            op = "gh"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.len(), 1);
    }

    #[test]
    fn test_get_providers_config_file_default() {
        std::env::remove_var("OAUTH2_CONFIG_FILE");
        let file = get_providers_config_file();
        assert_eq!(file, "oauth2.toml");
    }

    #[test]
    fn test_get_providers_config_file_env() {
        std::env::set_var("OAUTH2_CONFIG_FILE", "/tmp/custom-oauth2.toml");
        let file = get_providers_config_file();
        assert_eq!(file, "/tmp/custom-oauth2.toml");
        std::env::remove_var("OAUTH2_CONFIG_FILE");
    }
}
