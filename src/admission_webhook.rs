//! Device admission webhook (rustdesk docs/design-device-admission.md §5): asks a deployment-owned
//! service to admit or reject a pending device. Requests are signed with a key used only for this.
use base64::prelude::*;
use ed25519_dalek::{Signer, SigningKey};
use state::admission::AdmissionStore;
use std::time::Duration;
use utils::Admission;

pub const SIGNATURE_HEADER: &str = "X-Admission-Signature";
const TIMEOUT: Duration = Duration::from_secs(10);

pub struct AdmissionWebhook {
    url: String,
    key: SigningKey,
    client: reqwest::Client,
}

#[derive(Debug, PartialEq)]
pub enum CheckOutcome {
    NotPending,
    Decided(Admission),
    StillPending,
    Failed(String),
}

#[derive(serde::Deserialize)]
struct Answer {
    decision: String,
    #[serde(default)]
    reason: String,
}

/// A new keypair as `(private, public)` base64: 64-byte seed‖public key, and the 32-byte public key.
pub fn generate_key_b64() -> (String, String) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS randomness");
    let key = SigningKey::from_bytes(&seed);
    let public = key.verifying_key().to_bytes();
    (BASE64_STANDARD.encode([seed.as_slice(), public.as_slice()].concat()), BASE64_STANDARD.encode(public))
}

/// `t=<t>,ed25519=<signature of "<t>.<body>">`.
pub fn signature_header(key: &SigningKey, t: i64, body: &[u8]) -> String {
    let sig = key.sign(&[t.to_string().as_bytes(), b".", body].concat());
    format!("t={t},ed25519={}", BASE64_STANDARD.encode(sig.to_bytes()))
}

impl AdmissionWebhook {
    pub fn new(url: &str, key_b64: &str) -> Result<Self, String> {
        let raw = BASE64_STANDARD.decode(key_b64.trim()).map_err(|_| "ADMISSION_WEBHOOK_KEY is not base64".to_string())?;
        let raw: [u8; 64] = raw.try_into().map_err(|_| "ADMISSION_WEBHOOK_KEY must be 64 bytes (seed and public key)".to_string())?;
        let key = SigningKey::from_bytes(raw[..32].try_into().expect("32 bytes"));
        if key.verifying_key().to_bytes() != raw[32..] {
            return Err("ADMISSION_WEBHOOK_KEY: the public key does not belong to the seed".to_string());
        }
        let client = reqwest::Client::builder().timeout(TIMEOUT).build().map_err(|e| format!("webhook client: {e}"))?;
        Ok(Self { url: url.to_string(), key, client })
    }

    /// From `ADMISSION_WEBHOOK_URL` / `ADMISSION_WEBHOOK_KEY`; `Ok(None)` when the URL is empty.
    pub fn from_env() -> Result<Option<Self>, String> {
        let url = std::env::var("ADMISSION_WEBHOOK_URL").unwrap_or_default();
        if url.trim().is_empty() {
            return Ok(None);
        }
        let key = std::env::var("ADMISSION_WEBHOOK_KEY").map_err(|_| "ADMISSION_WEBHOOK_URL is set but ADMISSION_WEBHOOK_KEY is not".to_string())?;
        Self::new(url.trim(), &key).map(Some)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn public_key_b64(&self) -> String {
        BASE64_STANDARD.encode(self.key.verifying_key().to_bytes())
    }

    /// Asks the webhook about device `id` if it is pending, stores the result, applies a decision.
    pub async fn check(&self, store: &AdmissionStore, id: &str) -> CheckOutcome {
        let Some(device) = store.pending_device(id).await else {
            return CheckOutcome::NotPending;
        };
        let outcome = self.call(&device).await;
        let stored = match &outcome {
            Ok((decision, _)) => decision.clone(),
            Err(e) => e.clone(),
        };
        store.record_result(id, &stored).await;
        match outcome {
            Ok((decision, reason)) => match decision.as_str() {
                "admit" | "reject" => {
                    let a = if decision == "admit" { Admission::Admitted } else { Admission::Rejected };
                    store.apply_decision(id, a, &reason).await;
                    CheckOutcome::Decided(a)
                }
                _ => CheckOutcome::StillPending,
            },
            Err(e) => {
                log::warn!("admission webhook for {id}: {e}");
                CheckOutcome::Failed(e)
            }
        }
    }

    async fn call(&self, device: &state::admission::WebhookDevice) -> Result<(String, String), String> {
        let body = serde_json::to_vec(device).map_err(|e| format!("error: {e}"))?;
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default();
        let resp = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header(SIGNATURE_HEADER, signature_header(&self.key, t, &body))
            .body(body)
            .send()
            .await
            .map_err(|e| if e.is_timeout() { "timeout".to_string() } else { format!("error: {}", short(&e.to_string())) })?;
        if resp.status() != reqwest::StatusCode::OK {
            return Err(format!("HTTP {}", resp.status().as_u16()));
        }
        let answer: Answer = resp.json().await.map_err(|e| if e.is_timeout() { "timeout".to_string() } else { "invalid response".to_string() })?;
        match answer.decision.as_str() {
            "admit" | "reject" | "pending" => Ok((answer.decision, answer.reason)),
            _ => Err("invalid response".to_string()),
        }
    }
}

fn short(s: &str) -> &str {
    match s.char_indices().nth(120) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use utils::Admission;

    /// One-request-at-a-time HTTP stub: answers `status`/`body` after `delay`, records the last request.
    async fn stub(status: u16, body: &'static str, delay: std::time::Duration) -> (String, Arc<Mutex<Option<(String, Vec<u8>)>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/admission", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(None));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 { break; }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        let len = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            *seen2.lock().unwrap() = Some((head, buf[end + 4..end + 4 + len].to_vec()));
                            break;
                        }
                    }
                }
                tokio::time::sleep(delay).await;
                let resp = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        (url, seen)
    }

    async fn pending(id: &str) -> (state::ApiState, AdmissionStore) {
        let state = state::ApiState::new_with_db(&state::testing::fresh_database_url().await).await;
        state.test_register_device(id, "dXVpZA==").await;
        state.set_device_admission(id, Admission::Pending, "cli").await;
        let store = state.admission_store();
        (state, store)
    }

    fn webhook(url: &str) -> AdmissionWebhook {
        AdmissionWebhook::new(url, &generate_key_b64().0).unwrap()
    }

    #[test]
    fn key_format_and_signature_verify() {
        let (private, public) = generate_key_b64();
        let w = AdmissionWebhook::new("https://x/y", &private).unwrap();
        assert_eq!(w.public_key_b64(), public);
        let header = signature_header(&w.key, 1_800_000_000, b"{}");
        let sig = header.strip_prefix("t=1800000000,ed25519=").expect(&header);
        let sig = ed25519_dalek::Signature::from_slice(&BASE64_STANDARD.decode(sig).unwrap()).unwrap();
        w.key.verifying_key().verify(b"1800000000.{}", &sig).unwrap();
        assert!(AdmissionWebhook::new("https://x/y", "not-base64").is_err());
        let mut bad = BASE64_STANDARD.decode(&private).unwrap();
        bad[40] ^= 1;
        assert!(AdmissionWebhook::new("https://x/y", &BASE64_STANDARD.encode(bad)).is_err(), "public half must match");
    }

    #[rocket::async_test]
    async fn admit_answer_admits_and_request_is_signed() {
        let (url, seen) = stub(200, r#"{"decision":"admit","reason":"in CMDB"}"#, Default::default()).await;
        let (state, store) = pending("wa1").await;
        let w = webhook(&url);
        assert_eq!(w.check(&store, "wa1").await, CheckOutcome::Decided(Admission::Admitted));
        assert_eq!(state.device_admission("wa1", "dXVpZA==").await, Some(Admission::Admitted));
        let (head, body) = seen.lock().unwrap().clone().unwrap();
        let header = head.lines().find_map(|l| l.strip_prefix("x-admission-signature: ").or_else(|| l.strip_prefix("X-Admission-Signature: "))).expect(&head).to_string();
        let (t, sig) = header.strip_prefix("t=").unwrap().split_once(",ed25519=").unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&BASE64_STANDARD.decode(sig).unwrap()).unwrap();
        w.key.verifying_key().verify(&[t.as_bytes(), b".", &body].concat(), &sig).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], "wa1");
        assert!(json.get("first_seen").is_some() && json.get("owner").is_some());
    }

    #[rocket::async_test]
    async fn reject_pending_and_errors() {
        for (status, body, expected, stored) in [
            (200, r#"{"decision":"reject"}"#, CheckOutcome::Decided(Admission::Rejected), "reject"),
            (200, r#"{"decision":"pending"}"#, CheckOutcome::StillPending, "pending"),
            (500, "{}", CheckOutcome::Failed("HTTP 500".into()), "HTTP 500"),
            (200, r#"{"decision":"maybe"}"#, CheckOutcome::Failed("invalid response".into()), "invalid response"),
        ] {
            let (url, _) = stub(status, body, Default::default()).await;
            let (state, store) = pending("we1").await;
            assert_eq!(webhook(&url).check(&store, "we1").await, expected, "{body}");
            let (_, peers) = state.get_peers(Some("we1"), None, None, 0, 10).await.unwrap();
            assert_eq!(peers[0].admission_webhook_result.as_deref(), Some(stored));
        }
    }

    #[rocket::async_test]
    async fn timeout_is_recorded_and_not_pending_is_skipped() {
        let (url, seen) = stub(200, r#"{"decision":"admit"}"#, std::time::Duration::from_secs(12)).await;
        let (state, store) = pending("wt1").await;
        assert_eq!(webhook(&url).check(&store, "wt1").await, CheckOutcome::Failed("timeout".into()));
        assert_eq!(state.device_admission("wt1", "dXVpZA==").await, Some(Admission::Pending));
        state.set_device_admission("wt1", Admission::Rejected, "cli").await;
        *seen.lock().unwrap() = None;
        assert_eq!(webhook(&url).check(&store, "wt1").await, CheckOutcome::NotPending);
        assert!(seen.lock().unwrap().is_none(), "no call for a device that is not pending");
    }
}
