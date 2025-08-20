//! ## User
//! This module defines the main user type that is used for authentication. It also handles all
//! password hashing and comparing.

use bcrypt::{self, BcryptError};
use std::collections::HashMap;

/// This is the main user object that is stored for authentication. Note that the User has two primary identifiers:
/// username and user_id. Username can be an assigned identifier, which can be changed later on, but user id SHOULD NOT be changed.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct User {
    pub username: String,
    pub hashed_password: String,
    pub user_id: String,
    pub data: HashMap<String, String>,
}

impl User {
    /// Returns a new user from a given username, user id, and hashed password
    pub fn new(
        username: impl Into<String>,
        user_id: impl Into<String>,
        hashed_password: impl Into<String>,
    ) -> Self {
        User {
            username: username.into(),
            hashed_password: hashed_password.into(),
            user_id: user_id.into(),
            data: HashMap::new(),
        }
    }

    /// Returns a new user from a given username, user id, and password, and hashes the password before assigning it to the user.hashed_password field
    pub fn new_and_hash_password(
        username: impl Into<String>,
        user_id: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, BcryptError> {
        let hashed_password_result = hash_password(&password.into());
        match hashed_password_result {
            Ok(hashed_password) => Ok(User {
                username: username.into(),
                hashed_password,
                user_id: user_id.into(),
                data: HashMap::new(),
            }),
            Err(e) => Err(e),
        }
    }

    /// Returns whether the user and the input password are equivilent after using Bcrypt to hash the input password
    pub fn has_equivilent_hashed_password(
        &self,
        password: impl Into<String>,
    ) -> Result<bool, BcryptError> {
        password_is_equivilent(password.into(), &self.hashed_password)
    }

    /// Sets data in a User.data hashmap
    pub fn set<T: Into<String>>(&mut self, key: T, value: T) {
        self.data.insert(key.into(), value.into());
    }

    /// Get data in a User.data hashmap
    pub fn get(&mut self, key: &str) -> Option<&String> {
        self.data.get(key)
    }

    /// Removes data in a User.data hashmap
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.data.remove(key)
    }
}

/// Hashes a password
pub fn hash_password(password: &String) -> Result<String, BcryptError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
}

/// Compares a password against a hashed password
pub fn password_is_equivilent(
    password: String,
    hashed_password: &String,
) -> Result<bool, BcryptError> {
    bcrypt::verify(password, hashed_password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_user() {
        let new_user = User::new_and_hash_password("johnny", "123", "password").unwrap();
        assert_eq!(new_user.user_id, "123".to_string());
    }

    #[test]
    fn test_user_data() {
        let mut new_user = User::new_and_hash_password("johnny", "123", "password").unwrap();
        new_user.set("role", "guest");
        let user_data_result = new_user.get("role");
        match user_data_result {
            Some(role) => {
                assert_eq!(role, &"guest".to_string())
            }
            None => {
                panic!("Error getting user data")
            }
        }
        let user_data_result2 = new_user.get("favorite_color");
        match user_data_result2 {
            Some(_) => {
                panic!("Got an unexpected return")
            }
            None => {
                assert!(true)
            }
        }
    }

    #[test]
    fn password_eq() {
        let new_user = User::new_and_hash_password("johnny", "123", "password").unwrap();
        let password_comp_result = new_user.has_equivilent_hashed_password("password").unwrap();
        assert_eq!(password_comp_result, true);
        let password_comp_result = new_user
            .has_equivilent_hashed_password("wrong-password")
            .unwrap();
        assert_eq!(password_comp_result, false);
    }
}
