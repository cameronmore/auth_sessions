//! ## Axum Authentication
//! Implementation of the AuthStore for Axum + Tower web applications. This module provides handlers for:
//! - Registering users
//! - Logging in users
//! - Logging out users
//! - Authenticating users for protecting routes and injecting the user context

use axum::{
    self, Extension, Json,
    extract::FromRequestParts,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use http::request::Parts;
use std::sync::Arc;
use tower_cookies::{Cookie, Cookies};
use ulid::Ulid;

use crate::{
    auth_store::{AuthStore, AuthStoreError},
    password_validator::Password,
    session::{self, Session},
    session_id::{self, verify_signed_session_id},
    user::{self, User},
};

/// This is a struct that is injected into the context of a request.
pub struct AuthUser {
    pub user: User,
    pub session: Session,
}

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(serde::Deserialize)]
pub struct RegisterRequest {
    username: String,
    password: String,
}

/// Expects a request in JSON of the shape:
///
/// { "username" : "VALUE", "password" : "VALUE" }
///
/// This handler also expects a password validator, which is optional, so
/// be sure tho add that extension in your main Axum route definition like:
///
///
pub async fn register_user(
    Extension(store): Extension<Arc<dyn AuthStore>>,
    Extension(validator): Extension<Option<Arc<Password>>>,
    cookies: Cookies,
    Json(register_request): Json<RegisterRequest>,
) -> Result<Response, (StatusCode, String)> {
    if let Some(validator) = validator {
        let password_is_valid = validator.validate_immutable(&register_request.password);
        if !password_is_valid {
            return Err((
                StatusCode::BAD_REQUEST,
                "Unable to create user: Password is not valid".to_string(),
            ));
        }
    };
    let hashed_password = match user::hash_password(&register_request.password) {
        Ok(hpw) => hpw,
        Err(e) => {
            println!("{e:?}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to create user".to_string(),
            ));
        }
    };

    // todo it would also be good to add a user created timestamp field to the user object
    // or, for now, we could add it as a data field in the user.data map

    // define a new user and save the user
    let new_user_id = Ulid::new().to_string();
    let new_user = User::new(&register_request.username, hashed_password, &new_user_id);
    match store.save_user(&new_user).await {
        Ok(_) => {
            let new_session_object = session::Session::new_with_session_id(
                new_user_id,
                session_id::SessionId::new(),
                store.get_duration(),
            );
            let session_cookie = Cookie::build((
                "session_id",
                new_session_object
                    .id
                    .sign(store.get_key().as_bytes())
                    .to_string(),
            ))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(tower_cookies::cookie::SameSite::Lax)
            .build();
            cookies.add(session_cookie);

            match store.save_session(&new_session_object).await {
                Ok(_) => {
                    // here we could return our ok response but for the same of not making the code wider,
                    // just do nothing and return the ok below
                }
                Err(e) => {
                    println!("{e:?}");
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Unable to create user".to_string(),
                    ));
                }
            }

            Ok((
                StatusCode::CREATED,
                "User registered successfully!".to_string(),
            )
                .into_response())
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to create user".to_string(),
        )),
    }
}

/// Expects a JSON request in the shape:
///
///
/// { "username" : "VALUE", "password" : "VALUE" }
pub async fn login_user(
    Extension(store): Extension<Arc<dyn AuthStore>>,
    cookies: Cookies,
    Json(login_data): Json<LoginRequest>,
) -> Result<Response, (StatusCode, String)> {
    // the request comes in as the username and password, so we need to load the user by username,
    // but then use that user's user_id to make the session, since the username could be changed
    let user_by_username = store.load_user_by_username(&login_data.username).await;

    let user = match user_by_username {
        Ok(u) => u,
        Err(AuthStoreError::UserNotFound) => {
            return Err((StatusCode::UNAUTHORIZED, "Invalid credentials.".to_string()));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to load user: {e}"),
            ));
        }
    };

    let is_password_correct = match user.has_equivilent_hashed_password(&login_data.password) {
        Ok(is_eq) => is_eq,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Password verification error: {e}"),
            ));
        }
    };

    if !is_password_correct {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials.".to_string()));
    }

    // Create a new session for the logged-in user
    let session = Session::new(user.user_id, store.get_duration()); // Assuming user_id is always Some here after loading

    let signed_session_id = session.id.sign(store.get_key().as_bytes());

    match store.save_session(&session).await {
        Ok(_) => {
            // Set the session cookie

            let session_cookie = Cookie::build(("session_id", signed_session_id.to_string()))
                .path("/") // Make the cookie available to all paths
                .http_only(true) // Prevent client-side JavaScript access
                .secure(true) // Only send over HTTPS (important for production)
                .same_site(tower_cookies::cookie::SameSite::Lax) // Or Strict for more security
                .build();
            cookies.add(session_cookie);
            Ok((StatusCode::OK, "Login successful!".to_string()).into_response())
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save session: {e}"),
        )),
    }
}

/// Does not expect any request body
pub async fn logout_user(
    Extension(store): Extension<Arc<dyn AuthStore>>,
    cookies: Cookies,
) -> Result<Response, (StatusCode, String)> {
    let session_id_cookie = match cookies.get("session_id") {
        Some(c) => c,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "No cookie found".to_string(),
            ));
        }
    };

    let verified_session_id =
        match verify_signed_session_id(session_id_cookie.value(), store.get_key().as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                println!("{:?}", session_id_cookie.value());
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to load session id from cookie: {e}"),
                ));
            }
        };

    match store.delete_session(&verified_session_id).await {
        Ok(_) => {
            let session_cookie = tower_cookies::Cookie::new("session_id", "");
            cookies.remove(session_cookie);
            Ok((StatusCode::OK, "Logged out successfully!".to_string()).into_response())
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to delete session: {e}"),
        )),
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the AuthStore from the request extensions
        let Extension(store) = Extension::<Arc<dyn AuthStore>>::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AuthStore not found in request extensions".to_string(),
                )
            })?;

        // Extract cookies from the request
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to extract cookies".to_string(),
                )
            })?;

        // Get the session cookie
        let session_cookie = cookies.get("session_id").ok_or((
            StatusCode::UNAUTHORIZED,
            "Authentication required".to_string(),
        ))?;

        // Verify the signed session ID
        let session_id =
            verify_signed_session_id(session_cookie.value(), store.get_key().as_bytes())
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

        // Load session from the store
        let session = store.load_session(&session_id).await.map_err(|e| match e {
            AuthStoreError::SessionExpired => {
                (StatusCode::UNAUTHORIZED, "Session expired".to_string())
            }
            AuthStoreError::SessionNotFound => {
                (StatusCode::UNAUTHORIZED, "Session not found".to_string())
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load session".to_string(),
            ),
        })?;

        // Check if session is expired
        if session.is_expired() {
            return Err((StatusCode::UNAUTHORIZED, "Session expired".to_string()));
        }

        // Load user using the session's user_id
        let user = store
            .load_user(&session.user_id)
            .await
            .map_err(|e| match e {
                AuthStoreError::UserNotFound => {
                    (StatusCode::UNAUTHORIZED, "User not found".to_string())
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to load user".to_string(),
                ),
            })?;

        Ok(AuthUser { user, session })
    }
}
