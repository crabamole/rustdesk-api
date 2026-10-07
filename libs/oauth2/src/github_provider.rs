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
use core::str;
use std::{future::Future, pin::Pin};

use serde::Deserialize;
use url::form_urlencoded;

use crate::{
    errors::Oauth2Error,
    pkce::ProviderLogin,
    oauth_provider::{OAuthProvider, OAuthProviderFactory, OAuthResponse},
    exchange_err, response_text, Provider, ProviderConfig,
};

pub struct GithubProvider {
    provider_config: ProviderConfig,
}

#[derive(Debug, Deserialize)]
pub struct GithubTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct GithubUser {
    pub login: String,
    pub id: u64,
    pub node_id: String,
    pub avatar_url: String,
    pub gravatar_id: String,
    pub url: String,
    pub html_url: String,
    pub followers_url: String,
    pub following_url: String,
    pub gists_url: String,
    pub starred_url: String,
    pub subscriptions_url: String,
    pub organizations_url: String,
    pub repos_url: String,
    pub events_url: String,
    pub received_events_url: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub site_admin: bool,
    pub name: Option<String>,
    pub company: Option<String>,
    pub blog: String,
    pub location: Option<String>,
    pub email: Option<String>,
    pub hireable: Option<bool>,
    pub bio: Option<String>,
    pub twitter_username: Option<String>,
    pub notification_email: Option<String>,
    pub public_repos: u64,
    pub public_gists: u64,
    pub followers: u64,
    pub following: u64,
    pub created_at: String,
    pub updated_at: String,
    pub private_gists: u64,
    pub total_private_repos: u64,
    pub owned_private_repos: u64,
    pub disk_usage: u64,
    pub collaborators: u64,
    pub two_factor_authentication: bool,
    pub plan: Plan,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Plan {
    pub name: String,
    pub space: u64,
    pub collaborators: u64,
    pub private_repos: u64,
}

impl OAuthProviderFactory for GithubProvider {
    fn new() -> Self {
        let provider_config = Self::get_provider_config(Provider::Github);
        Self { provider_config }
    }
}
impl OAuthProvider for GithubProvider {
    fn get_redirect_url(&self, callback_url: &str, login: &ProviderLogin) -> String {
        let redirect_url =
            form_urlencoded::byte_serialize(callback_url.as_bytes()).collect::<String>();
        let scope = form_urlencoded::byte_serialize(self.provider_config.scope.as_bytes())
            .collect::<String>();
        let state = form_urlencoded::byte_serialize(login.state.as_bytes()).collect::<String>();
        let challenge = crate::pkce::s256_challenge(&login.code_verifier);

        format!(
            "{}?client_id={}&redirect_uri={}&scope={}&state={}&allow_signup=true&code_challenge={}&code_challenge_method=S256",
            self.provider_config.authorization_url,
            self.provider_config.app_id,
            redirect_url,
            scope,
            state,
            challenge
        )
    }

    fn exchange_code(
        &self,
        code: &str,
        callback_url: &str,
        login: &ProviderLogin,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthResponse, Oauth2Error>> + Send + Sync>> {
        let code = code.to_string();
        let callback_url = callback_url.to_string();
        let login = login.clone();
        let provider_config = self.provider_config.clone();

        Box::pin(async move {
            let response = reqwest::Client::new()
                .post(provider_config.token_exchange_url.as_str())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .form(&[
                    ("code", code.as_str()),
                    ("redirect_uri", &callback_url),
                    ("client_id", &provider_config.app_id.as_str()),
                    ("code_verifier", login.code_verifier.as_str()),
                    ("client_secret", &provider_config.app_secret.as_str()),
                ])
                .send()
                .await
                .map_err(|e| exchange_err("token request", e))?;
            let body_text = response_text("token request", response).await?;
            let body: GithubTokenResponse = serde_json::from_str(&body_text)
                .map_err(|e| exchange_err("token response", e))?;

            // Get the user info with:
            // Authorization: Bearer OAUTH-TOKEN
            // GET https://api.github.com/user
            let response = reqwest::Client::new()
                .get("https://api.github.com/user")
                .header("Accept", "application/json")
                .header(
                    "User-Agent",
                    format!("rustdesk-api/{}", env!("CARGO_PKG_VERSION")),
                )
                .header("Authorization", format!("Bearer {}", body.access_token))
                .send()
                .await
                .map_err(|e| exchange_err("user info request", e))?;
            let user_info_text = response_text("user info request", response).await?;
            log::debug!("User info:\n {}", user_info_text);
            let user_info: GithubUser = serde_json::from_str(&user_info_text).map_err(|e| {
                log::debug!("Failed to deserialize Github user info\nGithub probably changed its json response\nYou may need to correct the struct GithubUser: {}", e);
                exchange_err("user info response", e)
            })?;

            Ok(OAuthResponse {
                access_token: body.access_token,
                subject: user_info.id.to_string(),
                name: Some(user_info.login),
                email: user_info.email,
            })
        })
    }

    fn get_provider_type(&self) -> Provider {
        Provider::Github
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ProviderConfig {
        ProviderConfig {
            provider: Provider::Github,
            scope: "read:user user:email".to_string(),
            authorization_url: "https://github.com/login/oauth/authorize".to_string(),
            token_exchange_url: "https://github.com/login/oauth/access_token".to_string(),
            app_id: "gh-app-id".to_string(),
            app_secret: "gh-secret".to_string(),
            op_auth_string: "oidc/github".to_string(),
            op: "github".to_string(),
            issuer: "https://idp.example.com".to_string(),
        }
    }

    #[test]
    fn test_get_redirect_url() {
        let provider = GithubProvider {
            provider_config: test_config(),
        };
        let url = provider.get_redirect_url("https://myapp.com/cb", &ProviderLogin::new("xyz"));
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(url.contains("client_id=gh-app-id"));
        assert!(url.contains("allow_signup=true"));
        assert!(url.contains("state=xyz"));
    }

    #[test]
    fn test_get_redirect_url_encodes_callback() {
        let provider = GithubProvider {
            provider_config: test_config(),
        };
        let url = provider.get_redirect_url("https://app.com/cb?p=1&q=2", &ProviderLogin::new("s"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fapp.com%2Fcb%3Fp%3D1%26q%3D2"));
    }

    #[test]
    fn test_redirect_url_has_nonce_and_pkce() {
        let provider = GithubProvider { provider_config: test_config() };
        let login = ProviderLogin::new("st");
        let url = provider.get_redirect_url("https://api.example.com/api/oidc/callback", &login);
        assert!(url.contains("state=st"));
        assert!(url.contains(&format!("code_challenge={}", crate::pkce::s256_challenge(&login.code_verifier))));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn test_get_provider_type() {
        let provider = GithubProvider {
            provider_config: test_config(),
        };
        assert_eq!(provider.get_provider_type(), Provider::Github);
    }

    #[test]
    fn test_github_token_response_deserialize() {
        let json = r#"{"access_token":"gho_abc","token_type":"bearer","scope":"read:user"}"#;
        let tr: GithubTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(tr.access_token, "gho_abc");
        assert_eq!(tr.token_type, "bearer");
        assert_eq!(tr.scope, "read:user");
    }

    #[tokio::test]
    async fn test_exchange_code_sends_code_once_encoded() {
        // Rocket has already decoded the callback query; the token request
        // must carry the code verbatim, not percent-encoded a second time.
        let (url, body) = crate::capture_one_request();
        let mut config = test_config();
        config.token_exchange_url = format!("{url}/token");
        let provider = GithubProvider { provider_config: config };
        let _ = provider.exchange_code("a+b/c=d", "https://example.com/cb", &ProviderLogin::new("s")).await;
        assert_eq!(crate::form_code(&body.recv().unwrap()), "a+b/c=d");
    }


    #[tokio::test]
    async fn test_exchange_code_error_reports_provider_response() {
        let (url, _body) =
            crate::capture_one_request_with("400 Bad Request", r#"{"error":"invalid_grant"}"#);
        let mut config = test_config();
        config.token_exchange_url = format!("{url}/token");
        let provider = GithubProvider { provider_config: config };
        let err = provider
            .exchange_code("code", "https://example.com/cb", &ProviderLogin::new("s"))
            .await
            .err()
            .expect("exchange must fail")
            .to_string();
        assert!(err.contains("400") && err.contains("invalid_grant"), "{err}");
    }

}
