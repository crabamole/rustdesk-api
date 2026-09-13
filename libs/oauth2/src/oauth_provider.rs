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
use crate::{
    errors::Oauth2Error, get_providers_config_file, get_providers_config_from_file, Claims, Provider, ProviderConfig
};
use std::{future::Future, pin::Pin};
use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};

pub struct OAuthResponse {
    pub access_token: String,
    pub username: String,
    pub email: String,
}
pub trait OAuthProviderFactory {
    fn new() -> Self;
    /// Get the provider config for the given provider name
    ///
    /// # Arguments
    /// * `provider_name` - The name of the provider
    ///
    /// # Returns
    /// The provider config
    fn get_provider_config(tprovider: Provider) -> ProviderConfig {
        let provider_config = get_providers_config_from_file(get_providers_config_file().as_str());
        provider_config
            .iter()
            .find(|&provider| provider.provider == tprovider)
            .expect("Provider not found")
            .clone()
    }
}

pub trait OAuthProvider: Send + Sync{
    /// Get redirect url for the provider
    ///
    /// # Arguments
    /// * `callback_url` - The callback url
    /// * `state` - The state code
    ///
    /// # Returns  
    /// The redirect url
    fn get_redirect_url(&self, callback_url: &str, state: &str) -> String;
    fn exchange_code(
        &self,
        code: &str,
        callback_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthResponse, Oauth2Error>> + Send + Sync>>;

    /// Get the provider type
    fn get_provider_type(&self) -> Provider;
}

/// Decode the Oauth id token
/// # Arguments
/// * `id_token` - The jwt id token
///
/// # Returns
/// the username and email
pub fn decode_oauth_id_token(id_token: &str) -> Result<(String, String), Oauth2Error> {
    let parts: Vec<&str> = id_token.split('.').collect();
    let claims = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| Oauth2Error::DecodeIdTokenError)?;
    let claims: Claims =
        serde_json::from_slice(&claims).map_err(|_| Oauth2Error::DecodeIdTokenError)?;
    Ok((claims.name, claims.email))
}

/// Decode the standard Oauth2 id token
pub fn decode_oauth2_id_token(id_token: &str) -> Result<(String, String), Oauth2Error> {
    let parts: Vec<&str> = id_token.split('.').collect();
    let claims = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| Oauth2Error::DecodeIdTokenError)?;
    let claims: serde_json::Value =
        serde_json::from_slice(&claims).map_err(|_| Oauth2Error::DecodeIdTokenError)?;
    Ok((claims["name"].as_str().unwrap().to_string(), claims["email"].as_str().unwrap().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};

    fn make_jwt(claims_json: &str) -> String {
        let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = BASE64_URL_SAFE_NO_PAD.encode(claims_json);
        format!("{}.{}.sig", header, payload)
    }

    #[test]
    fn test_decode_oauth_id_token_valid() {
        let claims = r#"{"aud":"app","sub":"u1","name":"Alice","email":"alice@test.com","exp":9999999999}"#;
        let token = make_jwt(claims);
        let (name, email) = decode_oauth_id_token(&token).unwrap();
        assert_eq!(name, "Alice");
        assert_eq!(email, "alice@test.com");
    }

    #[test]
    fn test_decode_oauth2_id_token_valid() {
        let claims = r#"{"name":"Bob","email":"bob@test.com"}"#;
        let token = make_jwt(claims);
        let (name, email) = decode_oauth2_id_token(&token).unwrap();
        assert_eq!(name, "Bob");
        assert_eq!(email, "bob@test.com");
    }

    #[test]
    fn test_decode_oauth_id_token_invalid_base64() {
        let token = "header.!!!invalid!!!.sig";
        let result = decode_oauth_id_token(token);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_oauth_id_token_invalid_json() {
        let payload = BASE64_URL_SAFE_NO_PAD.encode("not json");
        let token = format!("header.{}.sig", payload);
        let result = decode_oauth_id_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_oauth_id_token_aud_as_array() {
        let claims = r#"{"aud":["app1","app2"],"sub":"u1","name":"Test","email":"t@t.com","exp":9999999999}"#;
        let token = make_jwt(claims);
        let (name, email) = decode_oauth_id_token(&token).unwrap();
        assert_eq!(name, "Test");
        assert_eq!(email, "t@t.com");
    }

    #[test]
    fn test_decode_oauth2_id_token_invalid_base64() {
        let token = "h.@@@.s";
        let result = decode_oauth2_id_token(token);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_oauth2_id_token_invalid_json() {
        let payload = BASE64_URL_SAFE_NO_PAD.encode("{bad}");
        let token = format!("h.{}.s", payload);
        let result = decode_oauth2_id_token(&token);
        assert!(result.is_err());
    }
}