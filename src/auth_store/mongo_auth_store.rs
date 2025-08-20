//! MongoDB implementation of the AuthStore trait

use crate::auth_store::{AuthStore, AuthStoreError};
use crate::{session::Session, session_id::SessionId, user::User};
use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use mongodb::{Client, Collection, bson::doc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Struct to represent a session document in MongoDB
#[derive(Debug, Serialize, Deserialize)]
struct MongoSession {
    #[serde(rename = "_id")] // Map BSON ObjectId to String
    id: String,
    data: String,
    expires_at: i64, // Unix timestamp (seconds)
}

/// Struct to represent a user document in MongoDB
#[derive(Debug, Serialize, Deserialize)]
struct MongoUser {
    #[serde(rename = "_id")] // Map BSON ObjectId to String
    user_id: String,
    username: String,
    hashed_password: String,
    data: HashMap<String, String>,
}

/// MongoDB implementation of the AuthStore trait
pub struct MongoAuthStore {
    sessions_collection: Collection<MongoSession>,
    users_collection: Collection<MongoUser>,
    secret_key: String,
    cookie_duration: TimeDelta,
}

impl MongoAuthStore {
    /// Returns a new MongoDB AuthStore. This function also required a database name to connect (it will make the necessary collection if they don't exist but not overwrite the existing).
    pub async fn new(
        database_url: &str,
        database_name: &str,
        secret_key: String,
        cookie_duration: TimeDelta,
    ) -> Result<Self, AuthStoreError> {
        let client = Client::with_uri_str(database_url).await.map_err(|e| {
            AuthStoreError::StoreError(format!("Failed to connect to MongoDB: {e}"))
        })?;

        let db = client.database(database_name);

        let sessions_collection = db.collection::<MongoSession>("sessions");
        let users_collection = db.collection::<MongoUser>("users");

        Ok(Self {
            sessions_collection,
            users_collection,
            secret_key,
            cookie_duration,
        })
    }
}

#[async_trait]
impl AuthStore for MongoAuthStore {
    async fn load_session(&self, session_id: &SessionId) -> Result<Session, AuthStoreError> {
        let current_timestamp = Utc::now().timestamp();
        let filter = doc! {
            "_id": session_id.to_string(),
            "expires_at": { "$gt": current_timestamp },
        };

        let mongo_session = self
            .sessions_collection
            .find_one(filter)
            .await
            .map_err(|e| AuthStoreError::StoreError(format!("MongoDB find error: {e}")))?;

        match mongo_session {
            Some(ms) => {
                let session: Session =
                    serde_json::from_str(&ms.data).map_err(AuthStoreError::DeserializationError)?;
                Ok(session)
            }
            None => {
                // If not found, it could be expired or never existed. Clean up anyway.
                // This might result in a SessionNotFound being returned even if cleanup fails,
                // which is fine
                self.delete_session(session_id).await.ok();
                Err(AuthStoreError::SessionNotFound)
            }
        }
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthStoreError> {
        let session_json =
            serde_json::to_string(session).map_err(AuthStoreError::SerializationError)?;

        let expires_at_timestamp = session.expires_at.timestamp();

        let mongo_session_to_insert = MongoSession {
            id: session.id.to_string(),
            data: session_json,
            expires_at: expires_at_timestamp,
        };

        // Check if a session with this ID already exists
        let existing_session = self
            .sessions_collection
            .find_one(doc! { "_id": &mongo_session_to_insert.id })
            .await
            .map_err(|e| AuthStoreError::StoreError(format!("MongoDB find error: {e}")))?;

        if existing_session.is_some() {
            return Err(AuthStoreError::StoreError(
                "Session with this ID already exists.".to_string(),
            ));
        }

        // If no existing session, proceed with insertion
        self.sessions_collection
            .insert_one(mongo_session_to_insert)
            .await
            .map_err(|e| {
                if e.to_string().contains("E11000 duplicate key error") {
                    AuthStoreError::StoreError(
                        "Session with this ID already exists (duplicate key).".to_string(),
                    )
                } else {
                    AuthStoreError::StoreError(format!("MongoDB insert error: {e}"))
                }
            })?;
        Ok(())
    }

    async fn delete_session(&self, session_id: &SessionId) -> Result<(), AuthStoreError> {
        let filter = doc! { "_id": session_id.to_string() };
        self.sessions_collection
            .delete_one(filter)
            .await
            .map_err(|e| AuthStoreError::StoreError(format!("MongoDB delete error: {e}")))?;
        Ok(())
    }

    async fn load_user(&self, user_id: &String) -> Result<User, AuthStoreError> {
        let filter = doc! { "_id": user_id };

        let mongo_user = self
            .users_collection
            .find_one(filter)
            .await
            .map_err(|e| AuthStoreError::StoreError(format!("MongoDB find error: {e}")))?;

        match mongo_user {
            Some(mu) => Ok(User {
                username: mu.username,
                hashed_password: mu.hashed_password,
                user_id: mu.user_id,
                data: mu.data,
            }),
            None => Err(AuthStoreError::UserNotFound),
        }
    }

    async fn load_user_by_username(&self, username: &String) -> Result<User, AuthStoreError> {
        let filter = doc! { "username": username };

        let mongo_user = self
            .users_collection
            .find_one(filter)
            .await
            .map_err(|e| AuthStoreError::StoreError(format!("MongoDB find error: {e}")))?;

        match mongo_user {
            Some(mu) => Ok(User {
                username: mu.username,
                hashed_password: mu.hashed_password,
                user_id: mu.user_id,
                data: mu.data,
            }),
            None => Err(AuthStoreError::UserNotFound),
        }
    }

    async fn save_user(&self, user: &User) -> Result<(), AuthStoreError> {
        // Check if user_id or username already exists
        let filter_id_or_username = doc! {
            "$or": [
                { "_id": &user.user_id },
                { "username": &user.username },
            ],
        };

        let existing_user = self
            .users_collection
            .find_one(filter_id_or_username)
            .await
            .map_err(|e| AuthStoreError::StoreError(format!("MongoDB find error: {e}")))?;

        if existing_user.is_some() {
            return Err(AuthStoreError::UserAlreadyExists);
        }

        let mongo_user_to_insert = MongoUser {
            user_id: user.user_id.clone(),
            username: user.username.clone(),
            hashed_password: user.hashed_password.clone(),
            data: user.data.clone(),
        };

        self.users_collection
            .insert_one(mongo_user_to_insert)
            .await
            .map_err(|e| {
                if e.to_string().contains("E11000 duplicate key error") {
                    AuthStoreError::UserAlreadyExists
                } else {
                    AuthStoreError::StoreError(format!("MongoDB insert error: {e}"))
                }
            })?;
        Ok(())
    }

    async fn delete_user(&self, user_id: &String) -> Result<(), AuthStoreError> {
        let filter = doc! { "_id": user_id };
        self.users_collection
            .delete_one(filter)
            .await
            .map_err(|e| AuthStoreError::StoreError(format!("MongoDB delete error: {e}")))?;
        Ok(())
    }

    fn get_key(&self) -> String {
        self.secret_key.clone()
    }

    fn get_duration(&self) -> TimeDelta {
        self.cookie_duration
    }
}
