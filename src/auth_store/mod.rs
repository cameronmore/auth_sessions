//! ## Auth Store
//! This module is designed to be the main authentication store for defining an authentication
//! manager. It contains everything for managing sessions and users in a database.
//! It can be extended to other datastores by implementing the AuthStore trait for those
//! datastores.

use crate::{session::Session, session_id::SessionId, user::User};
use async_trait::async_trait;
use std::{
    error::Error,
    fmt::{self, Display},
};
// Ensure only the minimum API surface is exported here
pub mod sqlite_auth_store;
pub use sqlite_auth_store::SqliteAuthStore;
pub mod pg_auth_store;
pub use pg_auth_store::PgAuthStore;
pub mod mongo_auth_store;
pub use mongo_auth_store::MongoAuthStore;
pub mod in_memory_auth_store;
pub use in_memory_auth_store::InMemoryAuthStore;
pub mod mysql_auth_store;
pub use mysql_auth_store::MySQLAuthStore;
pub mod redis_auth_store;
pub use redis_auth_store::RedisAuthStore;
// TODO, implement other auth stores and export them

/// Main error type for working with the auth store
#[derive(Debug)]
pub enum AuthStoreError {
    UserNotFound,
    SerializationError(serde_json::Error),
    DeserializationError(serde_json::Error),
    PasswordsDontMatch,
    StoreError(String),
    UserAlreadyExists,
    SessionNotFound,
    SessionExpired,
}

impl Display for AuthStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthStoreError::UserNotFound => write!(f, "User not found"),
            AuthStoreError::SerializationError(e) => {
                write!(f, "Session serialization error: {e}")
            }
            AuthStoreError::DeserializationError(e) => {
                write!(f, "Session deserialization error: {e}")
            }
            AuthStoreError::StoreError(e) => write!(f, "Auth store error: {e}"),
            AuthStoreError::PasswordsDontMatch => write!(f, "Passwords don't match"),
            AuthStoreError::UserAlreadyExists => write!(f, "The user already exists"),
            AuthStoreError::SessionNotFound => write!(f, "Session not found"),
            AuthStoreError::SessionExpired => write!(f, "Session expired"),
        }
    }
}

impl Error for AuthStoreError {}

impl From<serde_json::Error> for AuthStoreError {
    fn from(value: serde_json::Error) -> Self {
        AuthStoreError::SerializationError(value)
    }
}

/// This is the main trait for defining and working with auth stores. To extend this library to use other stores,
/// implement this trait.
#[async_trait]
pub trait AuthStore: Send + Sync + 'static {
    /// This function should first verify the session signature, then if valid, retrieve the session from the datastore,
    /// and, if it exists, check if it's expired, and, if not, returh the session. This ensures that only valid and non-expired sessions
    /// are returned, otherwise return an AuthStoreError
    async fn load_session(&self, session_id: &SessionId) -> Result<Session, AuthStoreError>;
    /// This function saves a session to the store and overwrites the session if it already exists.
    async fn save_session(&self, session: &Session) -> Result<(), AuthStoreError>;
    /// Deletes a session by session id
    async fn delete_session(&self, session_id: &SessionId) -> Result<(), AuthStoreError>;
    /// Loads a user by user id.
    async fn load_user(&self, user_id: &String) -> Result<User, AuthStoreError>;
    /// Loads a user by username, which is useful when a user uses their username and not user id to sign in. From there,
    /// the user's user id can be used to create a session and the load_user function can be used in an authentication middleware.
    async fn load_user_by_username(&self, username: &String) -> Result<User, AuthStoreError>;
    /// This function should first check if the user already exists in the database and return an error if the user already exists.
    /// This function is meant for creating users, not updating them or their attributes like username.
    async fn save_user(&self, user: &User) -> Result<(), AuthStoreError>;
    /// Deletes a user
    async fn delete_user(&self, user_id: &String) -> Result<(), AuthStoreError>;
    // TODO add an update_user
    /// This ensures that the AuthStore holds a secret key for signing the session ids.
    fn get_key(&self) -> String;
    /// This ensures that the AuthStore can set the duration validity of new sessions.
    fn get_duration(&self) -> chrono::TimeDelta;
}
