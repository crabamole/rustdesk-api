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
    errors::Oauth2Error, pkce::ProviderLogin, get_providers_config_file, get_providers_config_from_file, Claims, Provider, ProviderConfig
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
    /// * `login` - The state, nonce and PKCE verifier of this login
    ///
    /// # Returns  
    /// The redirect url
    fn get_redirect_url(&self, callback_url: &str, login: &ProviderLogin) -> String;
    fn exchange_code(
        &self,
        code: &str,
        callback_url: &str,
        login: &ProviderLogin,
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

/// Tolerated clock difference between us and the provider when checking `exp`.
const EXP_LEEWAY_SECS: u64 = 60;

/// Reads the claims of an ID token received directly from the provider's token endpoint.
/// The signature is not checked (allowed for tokens from the token endpoint over TLS),
/// but `iss`, `aud`, `exp` and `nonce` must match. `name` falls back to `preferred_username`.
pub fn decode_id_token(id_token: &str, issuer: &str, client_id: &str, nonce: &str) -> Result<IdTokenIdentity, Oauth2Error> {
    let payload = id_token.split('.').nth(1).ok_or(Oauth2Error::DecodeIdTokenError)?;
    let claims = BASE64_URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Oauth2Error::DecodeIdTokenError)?;
    let claims: Claims =
        serde_json::from_slice(&claims).map_err(|_| Oauth2Error::DecodeIdTokenError)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Oauth2Error::DecodeIdTokenError)?
        .as_secs();
    if claims.iss != issuer
        || !claims.aud.iter().any(|a| a == client_id)
        || claims.exp.saturating_add(EXP_LEEWAY_SECS) < now
        || claims.nonce.as_deref() != Some(nonce)
    {
        log::warn!(
            "rejected ID token: iss {:?} (want {issuer:?}), aud {:?} (want {client_id:?}), exp {}, nonce ok {}",
            claims.iss, claims.aud, claims.exp, claims.nonce.as_deref() == Some(nonce)
        );
        return Err(Oauth2Error::DecodeIdTokenError);
    }
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

    const ISS: &str = "https://idp.example.com";
    const APP: &str = "app";
    const NONCE: &str = "n-123";

    fn make_jwt(claims_json: &str) -> String {
        let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = BASE64_URL_SAFE_NO_PAD.encode(claims_json);
        format!("{}.{}.sig", header, payload)
    }

    /// A token with valid iss/aud/exp plus `extra` claims (a JSON fragment without braces).
    fn valid(extra: &str) -> String {
        make_jwt(&format!(r#"{{"iss":"{ISS}","aud":"{APP}","exp":9999999999,"nonce":"{NONCE}",{extra}}}"#))
    }

    fn decode(token: &str) -> Result<IdTokenIdentity, Oauth2Error> {
        decode_id_token(token, ISS, APP, NONCE)
    }

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn decodes_sub_name_and_email() {
        let id = decode(&valid(r#""sub":"u1","name":"Alice","email":"alice@test.com""#)).unwrap();
        assert_eq!(id, IdTokenIdentity { sub: "u1".into(), name: Some("Alice".into()), email: Some("alice@test.com".into()) });
    }

    #[test]
    fn name_and_email_are_optional() {
        let id = decode(&valid(r#""sub":"u1""#)).unwrap();
        assert_eq!(id, IdTokenIdentity { sub: "u1".into(), name: None, email: None });
    }

    #[test]
    fn name_falls_back_to_preferred_username() {
        let id = decode(&valid(r#""sub":"u1","preferred_username":"jsmith""#)).unwrap();
        assert_eq!(id.name.as_deref(), Some("jsmith"));
    }

    #[test]
    fn missing_or_empty_sub_is_an_error() {
        assert!(decode(&valid(r#""name":"No Sub""#)).is_err());
        assert!(decode(&valid(r#""sub":"""#)).is_err());
    }

    #[test]
    fn aud_may_be_an_array_containing_the_client_id() {
        let t = make_jwt(&format!(r#"{{"iss":"{ISS}","aud":["other","{APP}"],"exp":9999999999,"nonce":"{NONCE}","sub":"u1"}}"#));
        assert_eq!(decode(&t).unwrap().sub, "u1");
    }

    #[test]
    fn another_audience_is_rejected() {
        for aud in [r#""other""#, r#"["x","y"]"#, r#"[]"#] {
            let t = make_jwt(&format!(r#"{{"iss":"{ISS}","aud":{aud},"exp":9999999999,"nonce":"{NONCE}","sub":"u1"}}"#));
            assert!(decode(&t).is_err(), "aud {aud} accepted");
        }
    }

    #[test]
    fn another_or_missing_issuer_is_rejected() {
        let t = make_jwt(&format!(r#"{{"iss":"https://evil.example.com","aud":"{APP}","exp":9999999999,"nonce":"{NONCE}","sub":"u1"}}"#));
        assert!(decode(&t).is_err());
        let t = make_jwt(&format!(r#"{{"aud":"{APP}","exp":9999999999,"nonce":"{NONCE}","sub":"u1"}}"#));
        assert!(decode(&t).is_err());
    }

    #[test]
    fn expired_or_missing_exp_is_rejected() {
        let t = make_jwt(&format!(r#"{{"iss":"{ISS}","aud":"{APP}","exp":{},"nonce":"{NONCE}","sub":"u1"}}"#, now() - 3600));
        assert!(decode(&t).is_err());
        let t = make_jwt(&format!(r#"{{"iss":"{ISS}","aud":"{APP}","sub":"u1"}}"#));
        assert!(decode(&t).is_err());
    }

    #[test]
    fn another_or_missing_nonce_is_rejected() {
        let t = |nonce: &str| make_jwt(&format!(r#"{{"iss":"{ISS}","aud":"{APP}","exp":9999999999,{nonce}"sub":"u1"}}"#));
        assert!(decode(&t(r#""nonce":"n-123","#)).is_ok());
        assert!(decode(&t(r#""nonce":"other","#)).is_err());
        assert!(decode(&t("")).is_err());
    }

    #[test]
    fn small_clock_skew_is_tolerated() {
        let t = make_jwt(&format!(r#"{{"iss":"{ISS}","aud":"{APP}","exp":{},"nonce":"{NONCE}","sub":"u1"}}"#, now() - 30));
        assert!(decode(&t).is_ok());
    }

    #[test]
    fn malformed_tokens_are_errors() {
        assert!(decode("no-dots").is_err());
        assert!(decode("header.!!!invalid!!!.sig").is_err());
        let payload = BASE64_URL_SAFE_NO_PAD.encode("not json");
        assert!(decode(&format!("header.{}.sig", payload)).is_err());
    }
}
