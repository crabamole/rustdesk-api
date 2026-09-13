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
use crate::database::DatabaseUserPasswordInfo;
use bcrypt::{hash, verify, DEFAULT_COST};

pub struct UserPasswordInfo<'s> {
    password: &'s str,
}

impl<'s> UserPasswordInfo<'s> {
    pub fn from_password( password: &'s str ) -> Self {
        Self { 
            password
        }
    }

    pub fn check( &self, db_password_info: DatabaseUserPasswordInfo ) -> bool {
        let is_valid = verify(self.password, db_password_info.password.as_str()).unwrap();
        is_valid
    }

    pub fn check_with_string( &self, password_string: String) -> bool {
        let hashed_password = hash(self.password, DEFAULT_COST).unwrap();
        let is_valid = verify(password_string, &hashed_password).unwrap();
        is_valid
    }

    pub fn hash_password( given_password: &str) -> String {
        hash(given_password, DEFAULT_COST).unwrap()
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_correct_password() {
        let hashed = UserPasswordInfo::hash_password("mysecret");
        let info = UserPasswordInfo::from_password("mysecret");
        let db_info = DatabaseUserPasswordInfo {
            password: hashed,
            username: "user".to_string(),
            user_id: vec![1],
        };
        assert!(info.check(db_info));
    }

    #[test]
    fn verify_wrong_password_fails() {
        let hashed = UserPasswordInfo::hash_password("correct");
        let info = UserPasswordInfo::from_password("wrong");
        let db_info = DatabaseUserPasswordInfo {
            password: hashed,
            username: "user".to_string(),
            user_id: vec![1],
        };
        assert!(!info.check(db_info));
    }

    #[test]
    fn hash_password_produces_bcrypt_format() {
        let hashed = UserPasswordInfo::hash_password("test");
        assert!(hashed.starts_with("$2b$"));
    }

    #[test]
    fn hash_password_is_not_deterministic() {
        let h1 = UserPasswordInfo::hash_password("same");
        let h2 = UserPasswordInfo::hash_password("same");
        assert_ne!(h1, h2);
    }

    #[test]
    fn check_with_string_correct() {
        let info = UserPasswordInfo::from_password("Hello,world!");
        assert!(info.check_with_string("Hello,world!".to_string()));
    }

    #[test]
    fn check_with_string_wrong() {
        let info = UserPasswordInfo::from_password("Hello,world!");
        assert!(!info.check_with_string("wrong".to_string()));
    }

    #[test]
    fn empty_password_hashes_and_verifies() {
        let hashed = UserPasswordInfo::hash_password("");
        let info = UserPasswordInfo::from_password("");
        let db_info = DatabaseUserPasswordInfo {
            password: hashed,
            username: "user".to_string(),
            user_id: vec![],
        };
        assert!(info.check(db_info));
    }
}

