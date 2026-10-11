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
}
