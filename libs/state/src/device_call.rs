//! Device calls signed with the device key (rustdesk docs/design-signed-device-calls.md).
use base64::prelude::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// The header a device call carries: `<ts>.<base64 signature>`.
pub const HEADER: &str = "X-Device-Signature";
/// How far the device's `ts` may be from the server's clock.
pub const MAX_SKEW_SECS: i64 = 300;

/// The bytes the device signs; rustdesk `device_call::message` builds the same.
pub fn message(ts: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let digest: String = Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect();
    [b"device-call".as_slice(), ts.as_bytes(), path.as_bytes(), digest.as_bytes()].join(&0u8)
}

/// Whether `header` is `pk`'s signature of the call to `path` with `body`, made within
/// `MAX_SKEW_SECS` of `now` (Unix seconds).
pub fn verify(pk: &[u8], header: &str, path: &str, body: &[u8], now: i64) -> bool {
    let Some((ts, sig)) = header.split_once('.') else { return false };
    let Ok(t) = ts.parse::<i64>() else { return false };
    if (now - t).abs() > MAX_SKEW_SECS {
        return false;
    }
    let Ok(pk) = <[u8; 32]>::try_from(pk) else { return false };
    let Ok(key) = VerifyingKey::from_bytes(&pk) else { return false };
    let Some(signature) = BASE64_STANDARD.decode(sig).ok().and_then(|s| Signature::from_slice(&s).ok()) else {
        return false;
    };
    key.verify(&message(ts, path, body), &signature).is_ok()
}

/// Signing as the test device key, for tests that post device calls.
#[cfg(any(test, feature = "test-util"))]
pub mod testing {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    /// The public key `test_register_device` gives every test device.
    pub fn test_pk() -> [u8; 32] {
        key().verifying_key().to_bytes()
    }

    /// The `X-Device-Signature` value the test device sends with `body` to `path`, now.
    pub fn test_header(path: &str, body: &[u8]) -> String {
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default().to_string();
        format!("{ts}.{}", BASE64_STANDARD.encode(key().sign(&message(&ts, path, body)).to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: i64 = 1_800_000_000;
    const BODY: &[u8] = br#"{"id":"123456789","uuid":"dXVpZA==","conns":[]}"#;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn header(ts: i64, path: &str, body: &[u8]) -> String {
        let sig = key().sign(&message(&ts.to_string(), path, body));
        format!("{ts}.{}", BASE64_STANDARD.encode(sig.to_bytes()))
    }

    #[test]
    fn message_matches_the_device() {
        assert_eq!(
            message("1800000000", "/api/heartbeat", b"{}"),
            b"device-call\x001800000000\x00/api/heartbeat\x0044136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_vec()
        );
    }

    #[test]
    fn accepts_a_fresh_signature() {
        let pk = key().verifying_key().to_bytes();
        assert!(verify(&pk, &header(NOW, "/api/heartbeat", BODY), "/api/heartbeat", BODY, NOW));
        assert!(verify(&pk, &header(NOW - MAX_SKEW_SECS, "/api/heartbeat", BODY), "/api/heartbeat", BODY, NOW));
    }

    #[test]
    fn refuses_other_path_body_key_time_or_garbage() {
        let pk = key().verifying_key().to_bytes();
        let h = header(NOW, "/api/heartbeat", BODY);
        assert!(!verify(&pk, &h, "/api/audit/conn", BODY, NOW));
        assert!(!verify(&pk, &h, "/api/heartbeat", b"{}", NOW));
        assert!(!verify(&SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(), &h, "/api/heartbeat", BODY, NOW));
        assert!(!verify(&pk, &header(NOW - MAX_SKEW_SECS - 1, "/api/heartbeat", BODY), "/api/heartbeat", BODY, NOW));
        assert!(!verify(&pk, &header(NOW + MAX_SKEW_SECS + 1, "/api/heartbeat", BODY), "/api/heartbeat", BODY, NOW));
        assert!(!verify(&pk, "", "/api/heartbeat", BODY, NOW));
        assert!(!verify(&pk, "x.y", "/api/heartbeat", BODY, NOW));
        assert!(!verify(&[0; 5], &h, "/api/heartbeat", BODY, NOW));
    }
}
