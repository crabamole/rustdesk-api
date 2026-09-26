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
    /// Stable, unique user id at the provider (the OIDC `sub`).
    pub subject: String,
    pub name: Option<String>,
    pub email: Option<String>,
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

/// Who an ID token says the user is. `sub` is the identity; the rest is display data.
#[derive(Debug, Clone, PartialEq)]
pub struct IdTokenIdentity {
    pub sub: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Reads the claims of an ID token received directly from the provider's token endpoint.
/// Only `sub` is required; `name` falls back to `preferred_username`.
pub fn decode_id_token(id_token: &str) -> Result<IdTokenIdentity, Oauth2Error> {
    let payload = id_token.split('.').nth(1).ok_or(Oauth2Error::DecodeIdTokenError)?;
    let claims = BASE64_URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Oauth2Error::DecodeIdTokenError)?;
    let claims: Claims =
        serde_json::from_slice(&claims).map_err(|_| Oauth2Error::DecodeIdTokenError)?;
    let non_empty = |v: Option<String>| v.filter(|v| !v.trim().is_empty());
    let sub = non_empty(Some(claims.sub)).ok_or(Oauth2Error::DecodeIdTokenError)?;
    Ok(IdTokenIdentity {
        sub,
        name: non_empty(claims.name).or_else(|| non_empty(claims.preferred_username)),
        email: non_empty(claims.email),
    })
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
    fn decodes_sub_name_and_email() {
        let token = make_jwt(r#"{"aud":"app","sub":"u1","name":"Alice","email":"alice@test.com","exp":9999999999}"#);
        let id = decode_id_token(&token).unwrap();
        assert_eq!(id, IdTokenIdentity { sub: "u1".into(), name: Some("Alice".into()), email: Some("alice@test.com".into()) });
    }

    #[test]
    fn name_and_email_are_optional() {
        let id = decode_id_token(&make_jwt(r#"{"aud":"app","sub":"u1"}"#)).unwrap();
        assert_eq!(id, IdTokenIdentity { sub: "u1".into(), name: None, email: None });
    }

    #[test]
    fn name_falls_back_to_preferred_username() {
        let id = decode_id_token(&make_jwt(r#"{"aud":"app","sub":"u1","preferred_username":"jsmith"}"#)).unwrap();
        assert_eq!(id.name.as_deref(), Some("jsmith"));
    }

    #[test]
    fn missing_or_empty_sub_is_an_error() {
        assert!(decode_id_token(&make_jwt(r#"{"aud":"app","name":"No Sub"}"#)).is_err());
        assert!(decode_id_token(&make_jwt(r#"{"aud":"app","sub":""}"#)).is_err());
    }

    #[test]
    fn aud_may_be_an_array() {
        let id = decode_id_token(&make_jwt(r#"{"aud":["app1","app2"],"sub":"u1"}"#)).unwrap();
        assert_eq!(id.sub, "u1");
    }

    #[test]
    fn malformed_tokens_are_errors() {
        assert!(decode_id_token("no-dots").is_err());
        assert!(decode_id_token("header.!!!invalid!!!.sig").is_err());
        let payload = BASE64_URL_SAFE_NO_PAD.encode("not json");
        assert!(decode_id_token(&format!("header.{}.sig", payload)).is_err());
    }
}