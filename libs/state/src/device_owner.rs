//! Proof that a cRustDesk login runs on the device it names (design-same-user-access.md).
use base64::prelude::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// The bytes the device signs; rustdesk `same_user::owner_login_message` builds the same.
pub fn owner_login_message(code: &str, id: &str, uuid: &str) -> Vec<u8> {
    [b"owner-login".as_slice(), code.as_bytes(), id.as_bytes(), uuid.as_bytes()].join(&0u8)
}

/// Whether `signature_b64` is `pk`'s signature of the proof for login `code`.
pub fn verify(pk: &[u8], code: &str, id: &str, uuid: &str, signature_b64: &str) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(pk) else { return false };
    let Ok(key) = VerifyingKey::from_bytes(&pk) else { return false };
    let Some(signature) = BASE64_STANDARD.decode(signature_b64).ok().and_then(|s| Signature::from_slice(&s).ok()) else {
        return false;
    };
    key.verify(&owner_login_message(code, id, uuid), &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";
    const SIG: &str = "CHBQueEnh5risrgJk9BCNDWL4oY4avo0EvOsri+0BfgkiMu+jojKu7M6fL+fwmb9AYJayOiGO/dh3LezDdeXAg==";

    fn pk() -> Vec<u8> {
        BASE64_STANDARD.decode(PK).unwrap()
    }

    #[test]
    fn message_matches_the_device() {
        assert_eq!(owner_login_message("code1", "123456789", "dXVpZA=="), b"owner-login\0code1\0123456789\0dXVpZA==".to_vec());
    }

    #[test]
    fn accepts_the_device_signature() {
        assert!(verify(&pk(), "code1", "123456789", "dXVpZA==", SIG));
    }

    #[test]
    fn refuses_another_login_key_or_garbage() {
        assert!(!verify(&pk(), "code2", "123456789", "dXVpZA==", SIG));
        assert!(!verify(&[0u8; 32], "code1", "123456789", "dXVpZA==", SIG));
        assert!(!verify(&pk(), "code1", "123456789", "dXVpZA==", "bm90IGEgc2ln"));
        assert!(!verify(&pk(), "code1", "123456789", "dXVpZA==", ""));
        assert!(!verify(&[1u8; 5], "code1", "123456789", "dXVpZA==", SIG));
    }
}
