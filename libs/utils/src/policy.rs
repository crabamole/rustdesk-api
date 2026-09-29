//! Device settings an admin may push to every device through the heartbeat.
use std::collections::BTreeMap;

use crate::PolicyKeyInfo;

/// The seeded "Default" row of the `strategy` table; the global policy until named policies exist.
pub const DEFAULT_STRATEGY_GUID: &str = "018f2556-2316-7a02-b31c-5599e7cd5b5e";

struct PolicyKey {
    key: &'static str,
    label: &'static str,
    values: &'static [&'static str],
}

const YN: &[&str] = &["Y", "N"];

// Only settings the client enforces for incoming sessions; connection settings must never be pushable.
const POLICY_KEYS: &[PolicyKey] = &[
    PolicyKey { key: "enable-keyboard", label: "Keyboard and mouse", values: YN },
    PolicyKey { key: "enable-clipboard", label: "Clipboard", values: YN },
    PolicyKey { key: "enable-file-transfer", label: "File transfer", values: YN },
    PolicyKey { key: "enable-file-copy-paste", label: "File copy and paste", values: YN },
    PolicyKey { key: "enable-audio", label: "Audio", values: YN },
    PolicyKey { key: "enable-camera", label: "Camera", values: YN },
    PolicyKey { key: "enable-terminal", label: "Terminal", values: YN },
    PolicyKey { key: "enable-tunnel", label: "TCP tunneling", values: YN },
    PolicyKey { key: "enable-remote-restart", label: "Remote restart", values: YN },
    PolicyKey { key: "enable-record-session", label: "Session recording", values: YN },
    PolicyKey { key: "enable-block-input", label: "Blocking user input", values: YN },
    PolicyKey { key: "enable-privacy-mode", label: "Privacy mode", values: YN },
    PolicyKey { key: "enable-remote-printer", label: "Remote printer", values: YN },
    PolicyKey { key: "allow-remote-config-modification", label: "Remote configuration modification", values: YN },
    PolicyKey { key: "access-mode", label: "Permission type", values: &["custom", "full", "view"] },
];

fn find(key: &str) -> Option<&'static PolicyKey> {
    POLICY_KEYS.iter().find(|k| k.key == key)
}

fn is_allowed(key: &str, value: &str) -> bool {
    find(key).is_some_and(|k| value.is_empty() || k.values.contains(&value))
}

/// `Err` names the first key that is not a policy setting or has a value outside its list.
/// `""` (device default) is always valid.
pub fn validate_options(options: &BTreeMap<String, String>) -> Result<(), String> {
    for (key, value) in options {
        let Some(k) = find(key) else {
            return Err(format!("{key} is not a policy setting"));
        };
        if !is_allowed(key, value) {
            return Err(format!("{key}: {value:?} is not one of {}", k.values.join(", ")));
        }
    }
    Ok(())
}

/// The valid entries of `options`; applied again on the way out in case the database was edited by hand.
pub fn allowed_options(options: BTreeMap<String, String>) -> BTreeMap<String, String> {
    options.into_iter().filter(|(k, v)| is_allowed(k, v)).collect()
}

pub fn key_info() -> Vec<PolicyKeyInfo> {
    POLICY_KEYS
        .iter()
        .map(|k| PolicyKeyInfo {
            key: k.key.to_string(),
            label: k.label.to_string(),
            values: k.values.iter().map(|v| v.to_string()).collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn accepts_allowed_values_and_device_default() {
        let opts = map(&[("enable-clipboard", "N"), ("access-mode", "view"), ("enable-audio", "")]);
        assert_eq!(validate_options(&opts), Ok(()));
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = validate_options(&map(&[("custom-rendezvous-server", "evil:21116")])).unwrap_err();
        assert!(err.contains("custom-rendezvous-server"), "{err}");
    }

    #[test]
    fn rejects_values_outside_the_list() {
        let err = validate_options(&map(&[("access-mode", "admin")])).unwrap_err();
        assert!(err.contains("access-mode") && err.contains("custom, full, view"), "{err}");
        assert!(validate_options(&map(&[("enable-clipboard", "yes")])).is_err());
    }

    #[test]
    fn allowed_options_drops_everything_else() {
        let opts = map(&[("enable-clipboard", "N"), ("api-server", "http://x"), ("access-mode", "bogus"), ("enable-audio", "")]);
        assert_eq!(allowed_options(opts), map(&[("enable-clipboard", "N"), ("enable-audio", "")]));
    }

    #[test]
    fn key_info_lists_every_key_once() {
        let info = key_info();
        assert_eq!(info.len(), 15);
        let access = info.iter().find(|k| k.key == "access-mode").unwrap();
        assert_eq!(access.values, vec!["custom", "full", "view"]);
    }
}
