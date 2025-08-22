use crate::{
    auth_store::{AuthStore, AuthStoreError},
    session::Session,
    session_id::SessionId,
    user::User,
};
use async_trait::async_trait;
use chrono::TimeDelta;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// This is an in-memory implementation of the AuthStore and should only be used for testing and development scenarios.
/// It does not rely on anything persistent like a SQLite file or remote db (like MongoDB or Postgres)
#[derive(Debug)]
pub struct InMemoryAuthStore {
    /// This is used to store users in the in-memory store
    user_id_map: RwLock<HashMap<String, User>>,
    /// This is used to look up the user id of a given user from their username. This is used when a login request comes in
    /// and that username needs to be used to look up the user object by their user id.
    username_map: RwLock<HashMap<String, String>>,
    /// Stores the sessions
    session_map: RwLock<HashMap<SessionId, Session>>,
    secret_key: String,
    cookie_duration: TimeDelta,
}

impl InMemoryAuthStore {
    pub fn new(secret: &str, d: TimeDelta) -> Self {
        let user_id_map: HashMap<String, User> = HashMap::new();
        let username_map: HashMap<String, String> = HashMap::new();
        let session_map: HashMap<SessionId, Session> = HashMap::new();
        Self {
            user_id_map: RwLock::new(user_id_map),
            username_map: RwLock::new(username_map),
            session_map: RwLock::new(session_map),
            secret_key: secret.to_string(),
            cookie_duration: d,
        }
    }
}

#[async_trait]
impl AuthStore for InMemoryAuthStore {
    async fn load_session(&self, session_id: &SessionId) -> Result<Session, AuthStoreError> {
        let sessions = self.session_map.read().await; // This gets the RwLockReadGuard
        match sessions.get(session_id) {
            Some(session) => {
                if session.is_expired() {
                    return Err(AuthStoreError::SessionExpired);
                };
                Ok(session.clone())
            }
            None => Err(AuthStoreError::SessionNotFound),
        }
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthStoreError> {
        let mut sessions = self.session_map.write().await;
        sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn delete_session(&self, session_id: &SessionId) -> Result<(), AuthStoreError> {
        let mut sessions = self.session_map.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    async fn load_user(&self, user_id: &String) -> Result<User, AuthStoreError> {
        let users = self.user_id_map.read().await;
        match users.get(user_id) {
            Some(u) => Ok(u.clone()),
            None => return Err(AuthStoreError::UserNotFound),
        }
    }

    async fn load_user_by_username(&self, username: &String) -> Result<User, AuthStoreError> {
        let usernames = self.username_map.read().await;
        let user_ids = self.user_id_map.read().await;
        let user_id = usernames
            .get(username)
            .ok_or(AuthStoreError::UserNotFound)?;
        let user = user_ids.get(user_id).ok_or(AuthStoreError::UserNotFound)?;
        Ok(user.clone())
    }

    async fn save_user(&self, user: &User) -> Result<(), AuthStoreError> {
        let usernames_read_guard = self.username_map.read().await;
        let user_ids_read_guard = self.user_id_map.read().await;

        if user_ids_read_guard.contains_key(&user.user_id) {
            return Err(AuthStoreError::UserAlreadyExists);
        }
        if usernames_read_guard.contains_key(&user.username) {
            return Err(AuthStoreError::UserAlreadyExists);
        }

        drop(usernames_read_guard);
        drop(user_ids_read_guard);

        let mut usernames_write_guard = self.username_map.write().await;
        let mut user_ids_write_guard = self.user_id_map.write().await;

        usernames_write_guard.insert(user.username.clone(), user.user_id.clone());
        user_ids_write_guard.insert(user.user_id.clone(), user.clone());

        Ok(())
    }

    async fn delete_user(&self, user_id: &String) -> Result<(), AuthStoreError> {
        let user_to_delete = match self.load_user(user_id).await {
            Ok(u) => Some(u),
            Err(AuthStoreError::UserNotFound) => None,
            Err(e) => {
                return Err(AuthStoreError::StoreError(format!(
                    "Error looking up user while deleting: {e}"
                )));
            }
        };

        let mut usernames_write_guard = self.username_map.write().await;
        let mut user_ids_write_guard = self.user_id_map.write().await;

        if let Some(user) = user_to_delete {
            usernames_write_guard.remove(&user.username);
            user_ids_write_guard.remove(user_id);
        }

        Ok(())
    }

    fn get_key(&self) -> String {
        self.secret_key.clone()
    }

    fn get_duration(&self) -> chrono::TimeDelta {
        self.cookie_duration
    }
}
