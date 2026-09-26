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
use std::{future::Future, pin::Pin};

use crate::{
    errors::Oauth2Error,
    oauth_provider::{decode_id_token, OAuthProvider, OAuthProviderFactory, OAuthResponse},
    exchange_err, response_text, Provider, ProviderConfig, TokenResponse,
};
use base64::prelude::{Engine as _, BASE64_STANDARD};

use url::form_urlencoded;

pub struct Oauth2Provider {
    provider_config: ProviderConfig,
}

/// Get the authorization header for the provider
///
/// # Arguments
/// * `provider_config` - The provider configuration
///
/// # Returns
/// The authorization header
fn get_authorization_header(provider_config: &ProviderConfig) -> String {
    format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!(
            "{}:{}",
            provider_config.app_id, provider_config.app_secret
        ))
    )
}

impl OAuthProviderFactory for Oauth2Provider {
    fn new() -> Self {
        let provider_config = Self::get_provider_config(Provider::Oauth2);
        Self { provider_config }
    }
}
impl OAuthProvider for Oauth2Provider {
    fn get_redirect_url(&self, callback_url: &str, state: &str) -> String {
        let redirect_url =
            form_urlencoded::byte_serialize(callback_url.as_bytes()).collect::<String>();
        let scope = form_urlencoded::byte_serialize(self.provider_config.scope.as_bytes())
            .collect::<String>();
        let state = form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>();

        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            self.provider_config.authorization_url,
            self.provider_config.app_id,
            redirect_url,
            scope,
            state
        )
    }

    fn exchange_code(
        &self,
        code: &str,
        callback_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthResponse, Oauth2Error>> + Send + Sync>> {
        let code = code.to_string();
        let callback_url = callback_url.to_string();
        let provider_config = self.provider_config.clone();

        Box::pin(async move {
            let authorization_header = get_authorization_header(&provider_config);
            let response = reqwest::Client::new()
                .post(provider_config.token_exchange_url.as_str())
                .header("Authorization", authorization_header)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code.as_str()),
                    ("redirect_uri", &callback_url),
                    ("client_id", &provider_config.app_id.as_str()),
                    ("client_secret", &provider_config.app_secret.as_str()),
                ])
                .send()
                .await
                .map_err(|e| exchange_err("token request", e))?;
            let text = response_text("token request", response).await?;
            let body: TokenResponse = serde_json::from_str(&text)
                .map_err(|e| exchange_err("token response", e))?;

            if let Some(id_token) = body.id_token {
                let id = decode_id_token(&id_token, &provider_config.issuer, &provider_config.app_id)?;
                Ok(OAuthResponse {
                    access_token: body.access_token,
                    subject: id.sub,
                    name: id.name,
                    email: id.email,
                })
            } else {
                Err(exchange_err("token response", "no id_token"))
            }
        })
    }

    fn get_provider_type(&self) -> crate::Provider {
        Provider::Oauth2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ProviderConfig {
        ProviderConfig {
            provider: Provider::Oauth2,
            scope: "openid email".to_string(),
            authorization_url: "https://auth.example.com/authorize".to_string(),
            token_exchange_url: "https://auth.example.com/token".to_string(),
            app_id: "client-id".to_string(),
            app_secret: "client-secret".to_string(),
            op_auth_string: "oidc/generic".to_string(),
            op: "generic".to_string(),
            issuer: "https://idp.example.com".to_string(),
        }
    }

    #[test]
    fn test_get_authorization_header() {
        let config = test_config();
        let header = get_authorization_header(&config);
        assert!(header.starts_with("Basic "));
        let decoded = base64::prelude::BASE64_STANDARD
            .decode(header.strip_prefix("Basic ").unwrap())
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "client-id:client-secret");
    }

    #[test]
    fn test_get_redirect_url() {
        let provider = Oauth2Provider {
            provider_config: test_config(),
        };
        let url = provider.get_redirect_url("https://app.com/callback", "abc123");
        assert!(url.starts_with("https://auth.example.com/authorize?"));
        assert!(url.contains("client_id=client-id"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=abc123"));
    }

    #[test]
    fn test_get_provider_type() {
        let provider = Oauth2Provider {
            provider_config: test_config(),
        };
        assert_eq!(provider.get_provider_type(), Provider::Oauth2);
    }

    #[tokio::test]
    async fn test_exchange_code_sends_code_once_encoded() {
        // Rocket has already decoded the callback query; the token request
        // must carry the code verbatim, not percent-encoded a second time.
        let (url, body) = crate::capture_one_request();
        let mut config = test_config();
        config.token_exchange_url = format!("{url}/token");
        let provider = Oauth2Provider { provider_config: config };
        let _ = provider.exchange_code("a+b/c=d", "https://example.com/cb").await;
        assert_eq!(crate::form_code(&body.recv().unwrap()), "a+b/c=d");
    }


    #[tokio::test]
    async fn test_exchange_code_error_reports_provider_response() {
        let (url, _body) =
            crate::capture_one_request_with("400 Bad Request", r#"{"error":"invalid_grant"}"#);
        let mut config = test_config();
        config.token_exchange_url = format!("{url}/token");
        let provider = Oauth2Provider { provider_config: config };
        let err = provider
            .exchange_code("code", "https://example.com/cb")
            .await
            .err()
            .expect("exchange must fail")
            .to_string();
        assert!(err.contains("400") && err.contains("invalid_grant"), "{err}");
    }

}
