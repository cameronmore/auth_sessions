use crate::auth_store::{AuthStore, AuthStoreError};
use crate::{session::Session, session_id::SessionId, user::User};
use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use sqlx::{Row, query_scalar};
use sqlx::{
    postgres::{PgPool, PgRow},
    query,
};
use std::collections::HashMap;

/// SQLx/Postgres implementation of the AuthStore trait
pub struct PgAuthStore {
    pool: PgPool,
    secret_key: String,
    cookie_duration: TimeDelta,
}

impl PgAuthStore {
    /// Returns a new Postgres AuthStore
    pub async fn new(
        database_url: &str,
        secret_key: String,
        cookie_duration: TimeDelta,
    ) -> Result<Self, AuthStoreError> {
        let pool = PgPool::connect(database_url).await.map_err(|e| {
            AuthStoreError::StoreError(format!("Failed to connect to Postgres: {e}"))
        })?;

        // Create sessions table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY NOT NULL,
                data TEXT NOT NULL,
                expires_at BIGINT NOT NULL -- Unix timestamp (seconds)
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
impl AuthStore for PgAuthStore {
    async fn load_session(&self, session_id: &SessionId) -> Result<Session, AuthStoreError> {
        let current_timestamp = Utc::now().timestamp();

        let row: Option<PgRow> = query(
            r#"
            SELECT data, expires_at FROM sessions WHERE id = $1 AND expires_at > $2
            "#,
        )
        .bind(session_id.to_string())
        .bind(current_timestamp)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("PostgreSQL SELECT error: {e}")))?;

        match row {
            Some(row) => {
                let data_json: String = row.get("data");
                let session: Session = serde_json::from_str(&data_json)
                    .map_err(AuthStoreError::DeserializationError)?;
                // The query already filters by expires_at, so no need to check again if it was found
                Ok(session)
            }
            None => {
                // If not found, it could be expired or never existed. Clean up anyway.
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
            INSERT INTO sessions (id, data, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (id) DO UPDATE SET
                data = EXCLUDED.data,
                expires_at = EXCLUDED.expires_at;
            "#,
        )
        .bind(session.id.to_string())
        .bind(session_json)
        .bind(expires_at_timestamp)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("PostgreSQL INSERT/UPDATE error: {e}")))?;
        Ok(())
    }

    async fn delete_session(&self, session_id: &SessionId) -> Result<(), AuthStoreError> {
        query(
            r#"
            DELETE FROM sessions WHERE id = $1
            "#,
        )
        .bind(session_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("PostgreSQL DELETE error: {e}")))?;
        Ok(())
    }

    async fn load_user(&self, user_id: &String) -> Result<User, AuthStoreError> {
        let row: Option<PgRow> = query(
            r#"
            SELECT username, hashed_password, user_id, data FROM users WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("PostgreSQL SELECT error: {e}")))?;

        match row {
            Some(row) => {
                let username: String = row.get("username");
                let hashed_password: String = row.get("hashed_password");
                let user_id: String = row.get("user_id"); // Assuming user_id is always present in DB
                let data_json: String = row.get("data");
                let user_data: HashMap<String, String> = match serde_json::from_str(&data_json) {
                    Ok(u) => u,
                    Err(e) => return Err(AuthStoreError::DeserializationError(e)),
                };
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
        let row: Option<PgRow> = query(
            r#"
            SELECT username, hashed_password, user_id, data FROM users WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("PostgreSQL SELECT error: {e}")))?;

        match row {
            Some(row) => {
                let username: String = row.get("username");
                let hashed_password: String = row.get("hashed_password");
                let user_id: String = row.get("user_id"); // Assuming user_id is always present in DB
                let data_json: String = row.get("data");
                let user_data: HashMap<String, String> = match serde_json::from_str(&data_json) {
                    Ok(u) => u,
                    Err(e) => return Err(AuthStoreError::DeserializationError(e)),
                };
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
            SELECT COUNT(*) FROM users WHERE user_id = $1 OR username = $2
            "#,
        )
        .bind(&user.user_id)
        .bind(&user.username)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("PostgreSQL SELECT error: {e}")))?;

        if existing_user_count > 0 {
            return Err(AuthStoreError::UserAlreadyExists);
        }

        //let user_data_string: String = &user.data.serialize(serializer);

        let user_data_string = match serde_json::to_string(&user.data) {
            Ok(u) => u,
            Err(e) => return Err(AuthStoreError::SerializationError(e)),
        };

        // If no existing user, proceed with insertion
        query(
            r#"
            INSERT INTO users (username, hashed_password, user_id, data)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(&user.username)
        .bind(&user.hashed_password)
        .bind(&user.user_id)
        .bind(user_data_string)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("PostgreSQL INSERT error: {e}")))?;
        Ok(())
    }

    async fn delete_user(&self, user_id: &String) -> Result<(), AuthStoreError> {
        query(
            r#"
            DELETE FROM users WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthStoreError::StoreError(format!("PostgreSQL DELETE error: {e}")))?;
        Ok(())
    }

    fn get_key(&self) -> String {
        self.secret_key.clone()
    }

    fn get_duration(&self) -> TimeDelta {
        self.cookie_duration
    }
}
