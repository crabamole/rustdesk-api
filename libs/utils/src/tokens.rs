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
use rand::{thread_rng, Rng};
use rocket_okapi::okapi::schemars;
use rocket_okapi::okapi::schemars::JsonSchema;
use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
const TOKEN_LENGTH: usize = 32;

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
pub struct Token([u8; TOKEN_LENGTH]);

impl Token {
    pub fn new_random() -> Self {
        let mut random_bytes = [0u8; TOKEN_LENGTH];
        thread_rng().fill(&mut random_bytes);
        Self(random_bytes)
    }

    /// Convert into base64.
    pub fn to_base64(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(&self.0)
    }

    pub fn from_str<S: AsRef<str>>(str: S) -> Result<Self, base64::DecodeError> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(str.as_ref()).unwrap();
        let mut buf = [0u8; TOKEN_LENGTH];
        buf.copy_from_slice(&bytes);
        Ok(Self(buf))
    }
}

impl serde::Serialize for Token {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_base64().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Token {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let token = Self::from_str(&s).map_err(serde::de::Error::custom)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_random_produces_unique_tokens() {
        let t1 = Token::new_random();
        let t2 = Token::new_random();
        assert_ne!(t1, t2);
    }

    #[test]
    fn to_base64_produces_nonempty_string() {
        let token = Token::new_random();
        let b64 = token.to_base64();
        assert!(!b64.is_empty());
    }

    #[test]
    fn from_str_roundtrip() {
        let token = Token::new_random();
        let b64 = token.to_base64();
        let recovered = Token::from_str(&b64).unwrap();
        assert_eq!(token, recovered);
    }

    #[test]
    #[should_panic]
    fn from_str_invalid_base64_panics() {
        let _ = Token::from_str("not-valid-base64!!!");
    }

    #[test]
    fn serde_roundtrip() {
        let token = Token::new_random();
        let json = serde_json::to_string(&token).unwrap();
        let recovered: Token = serde_json::from_str(&json).unwrap();
        assert_eq!(token, recovered);
    }

    #[test]
    fn serde_serializes_as_base64_string() {
        let token = Token::new_random();
        let json = serde_json::to_string(&token).unwrap();
        // Should be a quoted string, not an array
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        let b64 = token.to_base64();
        assert_eq!(json, format!("\"{}\"", b64));
    }

    #[test]
    fn token_base64_length() {
        let token = Token::new_random();
        let b64 = token.to_base64();
        // 32 bytes in base64url no-pad = ceil(32*4/3) = 43 chars
        assert_eq!(b64.len(), 43);
    }
}

