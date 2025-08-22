use redis::AsyncCommands;
use redis::{Client, RedisError, aio::MultiplexedConnection};

use crate::auth_store::{AuthStore, AuthStoreError};
use crate::{session::Session, session_id::SessionId, user::User};
use async_trait::async_trait;
use chrono::{TimeDelta, Utc};

#[derive(Debug)]
pub struct RedisAuthStore {
    conn: MultiplexedConnection,
    secret_key: String,
    cookie_duration: TimeDelta,
}

impl RedisAuthStore {
    /// Returns a new Redis AuthStore
    pub async fn new(
        redis_url: String,
        secret_key: String,
        cookie_duration: TimeDelta,
    ) -> Result<Self, RedisError> {
        let redis_client = Client::open(redis_url)?;
        let con = redis_client.get_multiplexed_async_connection().await?;
        Ok(Self {
            conn: con,
            secret_key,
            cookie_duration,
        })
    }
}

#[async_trait]
impl AuthStore for RedisAuthStore {
    async fn load_session(&self, session_id: &SessionId) -> Result<Session, AuthStoreError> {
        let mut con = self.conn.clone();
        let session_key = format!("session:{}", session_id.to_string());

        let session_json: Option<String> = con.get(&session_key).await.map_err(|e| {
            AuthStoreError::StoreError(format!(
                "Redis GET error for session {}: {}",
                session_key, e
            ))
        })?;

        if let Some(s_json) = session_json {
            let loaded_session: Session =
                serde_json::from_str(&s_json).map_err(AuthStoreError::DeserializationError)?;

            if loaded_session.is_expired() {
                self.delete_session(session_id).await.ok();
                return Err(AuthStoreError::SessionExpired);
            }
            Ok(loaded_session)
        } else {
            Err(AuthStoreError::SessionNotFound)
        }
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthStoreError> {
        let mut con = self.conn.clone();
        let session_key = format!("session:{}", session.id.to_string());
        let session_json_string =
            serde_json::to_string(session).map_err(AuthStoreError::SerializationError)?;

        let expires_in_seconds = (session.expires_at - Utc::now()).num_seconds();
        let ttl_seconds: u64 = if expires_in_seconds > 0 {
            expires_in_seconds
        } else {
            0
        } as u64;

        let _: () = con.set_ex(&session_key, session_json_string, ttl_seconds)
            .await
            .map_err(|e| {
                AuthStoreError::StoreError(format!(
                    "Redis SETEX error for session {}: {}",
                    session_key, e
                ))
            })?;
        Ok(())
    }

    async fn delete_session(&self, session_id: &SessionId) -> Result<(), AuthStoreError> {
        let mut con = self.conn.clone();
        let session_key = format!("session:{}", session_id.to_string());

        let _: () = con.del(&session_key).await.map_err(|e| {
            AuthStoreError::StoreError(format!(
                "Redis DEL error for session {}: {}",
                session_key, e
            ))
        })?;
        Ok(())
    }

    async fn load_user(&self, user_id: &String) -> Result<User, AuthStoreError> {
        let mut con = self.conn.clone();
        let user_key = format!("user:{}", user_id);

        let user_json: Option<String> = con.get(&user_key).await.map_err(|e| {
            AuthStoreError::StoreError(format!("Redis GET error for user {}: {}", user_key, e))
        })?;

        if let Some(u_json) = user_json {
            let new_user: User =
                serde_json::from_str(&u_json).map_err(AuthStoreError::DeserializationError)?;
            Ok(new_user)
        } else {
            Err(AuthStoreError::UserNotFound)
        }
    }

    async fn load_user_by_username(&self, username: &String) -> Result<User, AuthStoreError> {
        let mut con = self.conn.clone();
        let username_to_id_key = format!("username_to_userid:{}", username);

        let user_id: Option<String> = con.get(&username_to_id_key).await.map_err(|e| {
            AuthStoreError::StoreError(format!(
                "Redis GET error for username index {}: {}",
                username_to_id_key, e
            ))
        })?;

        match user_id {
            Some(id) => self.load_user(&id).await,
            None => Err(AuthStoreError::UserNotFound),
        }
    }

    async fn save_user(&self, user: &User) -> Result<(), AuthStoreError> {
        let mut con = self.conn.clone();
        let user_key = format!("user:{}", user.user_id);
        let username_to_id_key = format!("username_to_userid:{}", user.username);

        let existing_user_json: Option<String> = con.get(&user_key).await.map_err(|e| {
            AuthStoreError::StoreError(format!(
                "Redis GET error checking for existing user by ID {}: {}",
                user_key, e
            ))
        })?;
        if existing_user_json.is_some() {
            return Err(AuthStoreError::UserAlreadyExists);
        }

        let existing_username_id: Option<String> =
            con.get(&username_to_id_key).await.map_err(|e| {
                AuthStoreError::StoreError(format!(
                    "Redis GET error checking for existing user by username {}: {}",
                    username_to_id_key, e
                ))
            })?;
        if existing_username_id.is_some() {
            return Err(AuthStoreError::UserAlreadyExists);
        }

        let user_json = serde_json::to_string(user).map_err(AuthStoreError::SerializationError)?;
        let _: () = redis::pipe()
            .atomic()
            .set(&user_key, user_json)
            .set(&username_to_id_key, &user.user_id)
            .query_async(&mut con)
            .await
            .map_err(|e| {
                AuthStoreError::StoreError(format!("Redis transaction SET user error: {}", e))
            })?;

        Ok(())
    }

    async fn delete_user(&self, user_id: &String) -> Result<(), AuthStoreError> {
        let mut con = self.conn.clone();
        let user_key = format!("user:{}", user_id);
        let user_to_delete: Option<User> = self.load_user(user_id).await.ok();

        let mut pipe = redis::pipe();
        pipe.atomic();

        pipe.del(&user_key);

        if let Some(u) = user_to_delete {
            let username_to_id_key = format!("username_to_userid:{}", u.username);
            pipe.del(&username_to_id_key);
        }

        let _: () = pipe.query_async(&mut con).await.map_err(|e| {
            AuthStoreError::StoreError(format!("Redis transaction DEL user error: {}", e))
        })?;

        Ok(())
    }

    fn get_key(&self) -> String {
        self.secret_key.clone()
    }

    fn get_duration(&self) -> chrono::TimeDelta {
        self.cookie_duration
    }
}
