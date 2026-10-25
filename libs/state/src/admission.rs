//! Device admission webhook data (rustdesk docs/design-device-admission.md §5).
use crate::database::Database;
use serde::Serialize;
use utils::Admission;

/// What the webhook learns about a pending device.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WebhookDevice {
    pub id: String,
    pub hostname: String,
    pub os: String,
    pub username: String,
    pub ip: String,
    pub owner: Option<WebhookOwner>,
    pub first_seen: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WebhookOwner {
    pub name: String,
    pub email: String,
    pub group: String,
}

/// The admission data the webhook check needs; cheap to clone into a background task.
#[derive(Clone)]
pub struct AdmissionStore {
    pub(crate) db: Database,
}

impl AdmissionStore {
    pub async fn pending_device(&self, id: &str) -> Option<WebhookDevice> {
        self.db.webhook_pending_device(id).await
    }

    pub async fn record_result(&self, id: &str, result: &str) {
        self.db.record_webhook_result(id, result).await;
    }

    pub async fn apply_decision(&self, id: &str, admission: Admission, reason: &str) -> bool {
        if !self.db.apply_webhook_decision(id, admission.code()).await {
            return false;
        }
        let info = serde_json::json!({ "device": id, "via": "webhook", "reason": reason });
        let iop = utils::console_log::iop_for_admission(admission);
        if self.db.insert_audit_console(None, utils::console_log::TYP_DEVICE, iop, &info.to_string()).await.is_none() {
            log::error!("console log row not written: webhook decision for {id}");
        }
        true
    }

    pub async fn is_registered(&self, id: &str) -> bool {
        self.db.peer_exists(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{testing, ApiState};
    use utils::Admission;

    async fn store_with(id: &str) -> (ApiState, AdmissionStore) {
        let state = ApiState::new_with_db(&testing::fresh_database_url().await).await;
        state.test_register_device(id, "dXVpZA==").await;
        let store = state.admission_store();
        (state, store)
    }

    #[rocket::async_test]
    async fn pending_device_only_for_pending() {
        let (state, store) = store_with("wh1").await;
        assert_eq!(store.pending_device("wh1").await, None, "admitted by default");
        state.set_device_admission("wh1", Admission::Pending, "cli").await;
        let d = store.pending_device("wh1").await.expect("pending");
        assert_eq!((d.id.as_str(), d.hostname.as_str(), d.owner.is_none()), ("wh1", "", true));
        assert!(!d.first_seen.is_empty());
        assert_eq!(store.pending_device("nobody").await, None);
    }

    #[rocket::async_test]
    async fn apply_decision_changes_only_pending_devices() {
        let (state, store) = store_with("wh2").await;
        state.set_device_admission("wh2", Admission::Pending, "cli").await;
        assert!(store.apply_decision("wh2", Admission::Admitted, "in CMDB").await);
        assert_eq!(state.device_admission("wh2", "dXVpZA==").await, Some(Admission::Admitted));
        assert!(!store.apply_decision("wh2", Admission::Rejected, "late").await, "no longer pending");
        assert_eq!(state.device_admission("wh2", "dXVpZA==").await, Some(Admission::Admitted));
        let q = utils::AuditQuery { offset: 0, limit: 10, created_at: None, pattern: None, conn_type: None };
        let (_, rows) = state.list_audit_consoles(&q).await.unwrap();
        let row = rows.iter().find(|r| r.iop == utils::console_log::IOP_ADMIT_DEVICE).expect("console row");
        let info = row.info.to_string();
        assert!(info.contains("\"via\":\"webhook\"") && info.contains("in CMDB"), "{info}");
    }

    #[rocket::async_test]
    async fn record_result_is_listed() {
        let (state, store) = store_with("wh3").await;
        store.record_result("wh3", "timeout").await;
        let (_, peers) = state.get_peers(Some("wh3"), None, None, 0, 10).await.unwrap();
        assert_eq!(peers[0].admission_webhook_result.as_deref(), Some("timeout"));
        assert!(peers[0].admission_webhook_at.is_some());
        assert!(store.is_registered("wh3").await && !store.is_registered("nobody").await);
    }
}
