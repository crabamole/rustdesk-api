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
use std::collections::HashMap;

pub fn get_host(headers: HashMap<String, String>) -> String {
    // Default to http
    let mut proto = "http".to_string(); 

    // Check if the headers contain the X-Forwarded-Proto header
    if let Some(proto_in_headers) = headers.get("x-forwarded-proto") {
        proto = proto_in_headers.to_string();
    }

    // Check if the headers contain the X-Forwarded-Host header
    if let Some(host_in_headers) = headers.get("x-forwarded-host") {
        return format!("{}://{}", proto, host_in_headers);
    }

    // Default to the host header
    if let Some(host) = headers.get("host") {
        return format!("{}://{}",proto, host.to_string());
    }

    "".to_string()
}

/// Parses `PUBLIC_URL`: an http(s) origin without path, query or fragment.
pub fn parse_public_url(value: &str) -> Result<String, String> {
    let err = |why: &str| format!("PUBLIC_URL {value:?} {why}; expected e.g. https://rustdesk.example.com");
    let url = url::Url::parse(value).map_err(|e| err(&e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(err("is not an http(s) URL"));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
        return Err(err("must not have a path, query, fragment or credentials"));
    }
    Ok(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn empty_headers_returns_empty() {
        assert_eq!(get_host(HashMap::new()), "");
    }

    #[test]
    fn host_header_only() {
        let h = headers(&[("host", "example.com")]);
        assert_eq!(get_host(h), "http://example.com");
    }

    #[test]
    fn forwarded_host_takes_priority_over_host() {
        let h = headers(&[
            ("host", "backend.local"),
            ("x-forwarded-host", "example.com"),
        ]);
        assert_eq!(get_host(h), "http://example.com");
    }

    #[test]
    fn forwarded_proto_with_host() {
        let h = headers(&[
            ("x-forwarded-proto", "https"),
            ("host", "example.com"),
        ]);
        assert_eq!(get_host(h), "https://example.com");
    }

    #[test]
    fn forwarded_proto_with_forwarded_host() {
        let h = headers(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "example.com"),
        ]);
        assert_eq!(get_host(h), "https://example.com");
    }

    #[test]
    fn forwarded_host_without_proto_defaults_http() {
        let h = headers(&[("x-forwarded-host", "example.com")]);
        assert_eq!(get_host(h), "http://example.com");
    }

    #[test]
    fn host_with_port() {
        let h = headers(&[("host", "example.com:8080")]);
        assert_eq!(get_host(h), "http://example.com:8080");
    }

    #[test]
    fn public_url_keeps_origin_and_port() {
        assert_eq!(parse_public_url("https://rustdesk.example.com").unwrap(), "https://rustdesk.example.com");
        assert_eq!(parse_public_url("https://rustdesk.example.com/").unwrap(), "https://rustdesk.example.com");
        assert_eq!(parse_public_url("http://10.0.0.5:30080").unwrap(), "http://10.0.0.5:30080");
        assert_eq!(parse_public_url("https://rustdesk.example.com:443").unwrap(), "https://rustdesk.example.com");
    }

    #[test]
    fn public_url_rejects_non_origins() {
        for bad in ["", "rustdesk.example.com", "ftp://rustdesk.example.com", "https://rustdesk.example.com/rd",
            "https://rustdesk.example.com/?a=1", "https://rustdesk.example.com/#x", "https://u:p@rustdesk.example.com"] {
            assert!(parse_public_url(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn proto_only_returns_empty() {
        let h = headers(&[("x-forwarded-proto", "https")]);
        assert_eq!(get_host(h), "");
    }
}