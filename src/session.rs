//! ## Session
//! This module defines the session object that's used to track if a user is authenticated.

use crate::session_id::SessionId;
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashMap;

/// Session stores the relevant information for any given client's session.
/// This is what is also stored in an AuthStore. Note that the only thing
/// needed for creating and verifying a cookie is the Session.id (which is a
/// SessionId which can be verified using verify_signed_session_id(signed_session_id_from_cookie, secrey_key))
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub data: HashMap<String, String>,
}

impl Session {
    /// Returns a new session with a new SessionId inside
    pub fn new(user_id: String, duration: TimeDelta) -> Self {
        let now: DateTime<Utc> = Utc::now();
        let expires_at: DateTime<Utc> = now + duration;
        Session {
            id: SessionId::new(),
            user_id,
            created_at: now,
            expires_at,
            data: HashMap::new(),
        }
    }

    /// Returns a new Session from a user id, SessionId and cookie duration.
    pub fn new_with_session_id(
        user_id: String,
        session_id: SessionId,
        duration: TimeDelta,
    ) -> Self {
        let now: DateTime<Utc> = Utc::now();
        let expires_at: DateTime<Utc> = now + duration;
        Session {
            id: session_id,
            user_id,
            created_at: now,
            expires_at,
            data: HashMap::new(),
        }
    }

    /// Sets the data in a Session.data hashmap
    pub fn set<T: Into<String>>(&mut self, key: T, value: T) {
        self.data.insert(key.into(), value.into());
    }

    /// Gets the data in a Session.data hashmap
    pub fn get(&mut self, key: &str) -> Option<&String> {
        self.data.get(key)
    }

    /// Removes the data in a Session.data hashmap
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.data.remove(key)
    }

    /// Returns true if the session is expired.
    pub fn is_expired(&self) -> bool {
        let now: DateTime<Utc> = Utc::now();
        if self.expires_at <= now {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session() {
        let new_session = Session::new("123".into(), chrono::TimeDelta::days(7));
        assert_eq!(new_session.user_id, "123");
        assert_eq!(new_session.is_expired(), false);
    }

    #[test]
    fn test_is_expired() {
        let new_session = Session::new("123".into(), chrono::TimeDelta::days(0));
        assert_eq!(new_session.is_expired(), true);
    }

    #[test]
    fn test_session_data() {
        let mut new_session = Session::new("123".into(), chrono::TimeDelta::days(0));
        new_session.set("role", "guest");
        let session_data_result = new_session.get("role");
        match session_data_result {
            Some(role) => {
                assert_eq!(role, &"guest".to_string())
            }
            None => {
                panic!("Error getting user data")
            }
        }
        let session_data_result2 = new_session.get("favorite_color");
        match session_data_result2 {
            Some(_) => {
                panic!("Got an unexpected return")
            }
            None => {
                assert!(true)
            }
        }
    }
}
