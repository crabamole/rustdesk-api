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
use serde::{Deserialize, Serialize};
use std::{fs, str::FromStr};
mod errors;

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
}

#[derive(Deserialize, Serialize, Copy, Clone, PartialEq, Eq, Debug)]
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
    aud: String,
    sub: String,
    name: String,
    email: String,
    exp: u64,
}

fn deserialize_aud<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    struct AudVisitor;
    impl<'de> de::Visitor<'de> for AudVisitor {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or array of strings")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<String, E> {
            Ok(v.to_owned())
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<String, A::Error> {
            let first = seq.next_element::<String>()?
                .ok_or_else(|| de::Error::invalid_length(0, &"at least one audience"))?;
            while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(first)
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

/// Get the providers config from a config file
///
/// # Returns  
/// The providers config
pub fn get_providers_config_from_file(config_file: &str) -> Vec<ProviderConfig> {
    // If file does not exist create it
    if !std::path::Path::new(&config_file).exists() {
        log::error!("oauth2 config file does not exist, creating it, we recommend you to fill it with your own values, you can change the file path by setting the OAUTH2_CONFIG_FILE environment variable.");
        let oauth2_config = include_str!("../../../oauth2.toml");
        fs::write(&config_file, oauth2_config).expect("Failed to write oauth2 config file");
    }
    let config_file_content = fs::read_to_string(config_file).expect("Failed to read config file");
    let config: Config = toml::from_str(&config_file_content).expect("Failed to parse config file");
    config.provider
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth_provider::decode_oauth_id_token;

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
            provider = "Gitlab"
            authorization_url = "https://gitlab.com/oauth/authorize"
            token_exchange_url = "https://gitlab.com/oauth/token"
            app_id = "your_gitlab_app_id"
            app_secret = "your_gitlab_app_secret"
            scope = "public_profile"
            op_auth_string = "oidc/facebook"
            op = "facebook"
        "#;

        let config_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(config_file.path(), config).unwrap();

        let providers = get_providers_config_from_file(config_file.path().to_str().unwrap());
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn test_decode_id_token() {
        let id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhiMjFkMTM0NjExZDQxNWJkMWU2MjUzOGE0ZGRjOTA4NmYxYTZiMjUifQ.eyJpc3MiOiJodHRwczovL2RleC1tb2NrLXNlcnZlci5OT05FL2RleCIsInN1YiI6IkNpUXdPR0U0TmpnMFlpMWtZamc0TFRSaU56TXRPVEJoT1MwelkyUXhOall4WmpVME5qWVNCV3h2WTJGcyIsImF1ZCI6InNjdGdkZXNrLWFwaS1zZXJ2ZXIiLCJleHAiOjE3MTU2NzEwODQsImlhdCI6MTcxNTU4NDY4NCwiYXRfaGFzaCI6IjVvZEdyU3VrMW9lejJkc1NaRXZFM0EiLCJjX2hhc2giOiJfdFZfZFNiU09qTVVmRVdMeVVNSTNnIiwiZW1haWwiOiJhZG1pbkBkZXNrLk5PTkUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImFkbWluIn0.AqOiwBKq2i_AoJcbfxuaVY54PN3GJjnHIn3E2FWoZY2IOu8qxvZevcUb4mjnoUZGf2QaabIcTAIxIg-mpFTRxheOPiQ1c9VSZ0vd-wNGrAG12vdraRq0-evqmFduR2G9k20QMIV8iHiGM7l93k8Fw5_bnTQId044BjepayS98bpUclS4RIIGoOLBM5IenfBCqLhHHv6oYUM6HDU4rCD02U9_Bu597wedeLdYYa7lzBDyb88ab83-eALsDpbFZ90rUnvAhpTQcl9_t51Etx-sP1yWSQ3UZ-QL61cKreqWlMbimM43R4boUWnpQTMF7ZO0EftVixEfaIQvWDRm-TLl8A";
        let (name, email) = decode_oauth_id_token(id_token).unwrap();
        assert_eq!(name, "admin");
        assert_eq!(email, "admin@desk.NONE");
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
        assert_eq!(claims.aud, "my-app");
    }

    #[test]
    fn test_deserialize_aud_array() {
        let json = r#"{"aud":["my-app","other"],"sub":"user1","name":"Test","email":"test@test.com","exp":9999999999}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.aud, "my-app");
    }

    #[test]
    fn test_deserialize_aud_empty_array() {
        let json = r#"{"aud":[],"sub":"user1","name":"Test","email":"test@test.com","exp":9999999999}"#;
        let result: Result<Claims, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_claims_fields() {
        let json = r#"{"aud":"app","sub":"sub123","name":"Alice","email":"alice@example.com","exp":1234567890}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "sub123");
        assert_eq!(claims.name, "Alice");
        assert_eq!(claims.email, "alice@example.com");
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
