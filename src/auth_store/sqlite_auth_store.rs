use std::collections::HashMap;

use crate::auth_store::{AuthStore, AuthStoreError};
use crate::{session::Session, session_id::SessionId, user::User};
use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use sqlx::{Row, query_scalar};
use sqlx::{
    query,
    sqlite::{SqlitePool, SqliteRow},
};

/// SQLx/SQLite struct that implements the AuthStore trait
pub struct SqliteAuthStore {
    pool: SqlitePool,
    secret_key: String,
    cookie_duration: chrono::TimeDelta,
}

impl SqliteAuthStore {
    /// Returns a new SQLite AuthStore
    pub async fn new(
        database_url: &str,
        secret_key: String,
        cookie_duration: chrono::TimeDelta,
    ) -> Result<Self, AuthStoreError> {
        // Changed to SessionStoreError for consistency with example
        let pool = SqlitePool::connect(database_url)
            .await
            .map_err(|e| AuthStoreError::StoreError(format!("Failed to connect to SQLite: {e}")))?;

        // Create sessions table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY NOT NULL,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL -- Unix timestamp (seconds)
            );
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("Failed to create sessions table: {e}")))?;

        // Create users table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY NOT NULL,
                username TEXT NOT NULL UNIQUE,
                hashed_password TEXT NOT NULL,
                data TEXT NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("Failed to create users table: {e}")))?;

        Ok(Self {
            pool,
            secret_key,
            cookie_duration,
        })
    }
}

#[async_trait]
impl AuthStore for SqliteAuthStore {
    async fn load_session(&self, session_id: &SessionId) -> Result<Session, AuthStoreError> {
        let current_timestamp = Utc::now().timestamp();

        let row: Option<SqliteRow> = query(
            r#"
            SELECT data, expires_at FROM sessions WHERE id = ?
            "#,
        )
        .bind(session_id.to_string())
        .bind(current_timestamp)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("SQLite SELECT error: {e}")))?;

        match row {
            Some(row) => {
                let data_json: String = row.get("data");
                let session: Session = serde_json::from_str(&data_json)
                    .map_err(AuthStoreError::DeserializationError)?;
                if session.is_expired() {
                    return Err(AuthStoreError::SessionExpired);
                }
                Ok(session)
            }
            None => {
                // Also clean up expired sessions that weren't found due to expiration
                self.delete_session(session_id).await.ok(); // Ignore error on cleanup attempt
                Err(AuthStoreError::SessionNotFound)
            }
        }
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthStoreError> {
        let session_json =
            serde_json::to_string(session).map_err(AuthStoreError::SerializationError)?;

        let expires_at_timestamp = session.expires_at.timestamp();

        query(
            r#"
            INSERT OR REPLACE INTO sessions (id, data, expires_at)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(session.id.to_string())
        .bind(session_json)
        .bind(expires_at_timestamp)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("SQLite INSERT/REPLACE error: {e}")))?;
        Ok(())
    }

    async fn delete_session(&self, session_id: &SessionId) -> Result<(), AuthStoreError> {
        query(
            r#"
            DELETE FROM sessions WHERE id = ?
            "#,
        )
        .bind(session_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("SQLite DELETE error: {e}")))?;
        Ok(())
    }

    async fn load_user(&self, user_id: &String) -> Result<User, AuthStoreError> {
        let row = query(
            r#"
            SELECT username, hashed_password, user_id, data FROM users WHERE user_id = ?
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("SQLite SELECT error: {e}")))?;
        match row {
            Some(row) => {
                let username: String = row.get("username");
                let hashed_password: String = row.get("hashed_password");
                let user_id: String = row.get("user_id");
                let user_data_json: String = row.get("data");
                let user_data: HashMap<String, String> = serde_json::from_str(&user_data_json)
                    .map_err(AuthStoreError::DeserializationError)?;

                Ok(User {
                    username,
                    hashed_password,
                    user_id,
                    data: user_data,
                })
            }
            None => Err(AuthStoreError::UserNotFound),
        }
    }

    async fn load_user_by_username(&self, username: &String) -> Result<User, AuthStoreError> {
        let row = query(
            r#"
            SELECT username, hashed_password, user_id, data FROM users WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("SQLite SELECT error: {e}")))?;
        match row {
            Some(row) => {
                let user_id: String = row.get("user_id");
                let hashed_password: String = row.get("hashed_password");
                let username: String = row.get("username");
                let user_data_json: String = row.get("data");
                let user_data: HashMap<String, String> = serde_json::from_str(&user_data_json)
                    .map_err(AuthStoreError::DeserializationError)?;

                Ok(User {
                    username,
                    hashed_password,
                    user_id,
                    data: user_data,
                })
            }
            None => Err(AuthStoreError::UserNotFound),
        }
    }

    async fn save_user(&self, user: &User) -> Result<(), AuthStoreError> {
        // First, check if a user with this user_id or username already exists
        let existing_user_count: i64 = query_scalar(
            r#"
            SELECT COUNT(*) FROM users WHERE user_id = ? OR username = ?
            "#,
        )
        .bind(&user.user_id)
        .bind(&user.username)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("SQLite SELECT error: {e}")))?;

        if existing_user_count > 0 {
            return Err(AuthStoreError::UserAlreadyExists);
        }

        let user_data_string = match serde_json::to_string(&user.data) {
            Ok(u) => u,
            Err(e) => return Err(AuthStoreError::SerializationError(e)),
        };

        // If no existing user, proceed with insertion
        query(
            r#"
            INSERT INTO users (username, hashed_password, user_id, data)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&user.username)
        .bind(&user.hashed_password)
        .bind(&user.user_id)
        .bind(user_data_string)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("SQLite INSERT error: {e}")))?;
        Ok(())
    }

    async fn delete_user(&self, user_id: &String) -> Result<(), AuthStoreError> {
        query(
            r#"
            DELETE FROM users WHERE user_id = ?
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("SQLite DELETE error: {e}")))?;
        Ok(())
    }

    fn get_key(&self) -> String {
        self.secret_key.clone()
    }

    fn get_duration(&self) -> TimeDelta {
        self.cookie_duration
    }
}
