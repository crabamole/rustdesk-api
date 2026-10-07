use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};

/// 64 random alphanumerics: a valid PKCE verifier, nonce or one-time value.
pub fn random_secret() -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect()
}

/// PKCE `S256` challenge of `verifier` (RFC 7636 §4.2).
pub fn s256_challenge(verifier: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// What one login sends to the identity provider and must see back.
#[derive(Clone, Debug)]
pub struct ProviderLogin {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
}

impl ProviderLogin {
    pub fn new(state: &str) -> Self {
        Self { state: state.to_string(), nonce: random_secret(), code_verifier: random_secret() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_matches_rfc7636_appendix_b() {
        assert_eq!(s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn secrets_are_long_random_and_distinct() {
        let (a, b) = (random_secret(), random_secret());
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
    }

    #[test]
    fn provider_login_keeps_the_state() {
        let l = ProviderLogin::new("abc");
        assert_eq!(l.state, "abc");
        assert_ne!(l.nonce, l.code_verifier);
    }
}
