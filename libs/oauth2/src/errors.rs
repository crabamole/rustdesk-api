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
use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub enum Oauth2Error {
    ExchangeCodeError,
    VerifyTokenError,
    DecodeIdTokenError,
}

impl fmt::Display for Oauth2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Oauth2Error::ExchangeCodeError => write!(f, "Exchange code error"),
            Oauth2Error::VerifyTokenError => write!(f, "Verify token error"),
            Oauth2Error::DecodeIdTokenError => write!(f, "Decode id token error"),
        }
    }
}

impl Error for Oauth2Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_exchange_code_error() {
        assert_eq!(Oauth2Error::ExchangeCodeError.to_string(), "Exchange code error");
    }

    #[test]
    fn test_display_verify_token_error() {
        assert_eq!(Oauth2Error::VerifyTokenError.to_string(), "Verify token error");
    }

    #[test]
    fn test_display_decode_id_token_error() {
        assert_eq!(Oauth2Error::DecodeIdTokenError.to_string(), "Decode id token error");
    }

    #[test]
    fn test_error_is_error_trait() {
        let err: Box<dyn Error> = Box::new(Oauth2Error::ExchangeCodeError);
        assert_eq!(err.to_string(), "Exchange code error");
    }

    #[test]
    fn test_debug_format() {
        let err = Oauth2Error::ExchangeCodeError;
        let debug = format!("{:?}", err);
        assert!(debug.contains("ExchangeCodeError"));
    }
}