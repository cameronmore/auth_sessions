//! ## Rocket Auth Sessions
//! This module provides authentication route handlers for Rocket applications given any
//! store that implements the AuthStore trait.

// TODO for this implementation:
// - add better error responding for data validation errors like user already exists and so on.

use crate::{
    auth_store::{AuthStore, AuthStoreError},
    password_validator::Password,
    session::Session,
    session_id::verify_signed_session_id,
    user::User,
};
use rocket::http::Cookie;
use rocket::http::CookieJar;
use rocket::{
    State, get,
    http::Status,
    post,
    request::{self, FromRequest},
};
use serde::Deserialize;
use std::sync::Arc;

/// This is a struct that is injected into the context of a request.
/// It will also serve as the Request Guard.
pub struct AuthUser {
    pub user: User,
    pub session: Session,
}

/// Request type definition for the login route
#[derive(Deserialize, Debug)]
#[serde(crate = "rocket::serde")] // Important for Rocket's serde integration
pub struct LoginRequest {
    username: String,
    password: String,
}

/// Request type definition for registration route
#[derive(Deserialize, Debug)]
#[serde(crate = "rocket::serde")]
pub struct RegisterRequest {
    username: String,
    password: String,
}

/// Rocket Request Guard implementation for `AuthUser`.
/// This makes `AuthUser` injectable into route handlers.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthUser {
    type Error = String;

    async fn from_request(
        req: &'r request::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        let store = req
            .guard::<&State<Arc<dyn AuthStore>>>()
            .await
            .succeeded()
            .expect(
                "AuthStore not found in Rocket managed state. Ensure .manage(AuthStore) is called.",
            );

        let cookies = req.cookies();

        let session_cookie = match cookies.get("session_id") {
            Some(cookie) => cookie,
            None => {
                return rocket::request::Outcome::Error((
                    Status::Unauthorized,
                    "Authentication required.".to_string(),
                ));
            }
        };

        let session_id =
            match verify_signed_session_id(session_cookie.value(), store.get_key().as_bytes()) {
                Ok(s_id) => s_id,
                Err(_) => {
                    cookies.remove(session_cookie.clone());
                    return rocket::request::Outcome::Error((
                        Status::Unauthorized,
                        "Invalid or tampered session ID.".to_string(),
                    ));
                }
            };

        let session = match store.load_session(&session_id).await {
            Ok(s) => s,
            Err(AuthStoreError::SessionExpired) => {
                cookies.remove(session_cookie.clone()); // Clear expired session cookie
                return rocket::request::Outcome::Error((
                    Status::Unauthorized,
                    "Session expired.".to_string(),
                ));
            }
            Err(AuthStoreError::SessionNotFound) => {
                cookies.remove(session_cookie.clone()); // Clear non-existent session cookie
                return rocket::request::Outcome::Error((
                    Status::Unauthorized,
                    "Session not found.".to_string(),
                ));
            }
            Err(e) => {
                return rocket::request::Outcome::Error((
                    Status::InternalServerError,
                    format!("Failed to load session: {e}"),
                ));
            }
        };

        if session.is_expired() {
            cookies.remove(session_cookie.clone());
            return rocket::request::Outcome::Error((
                Status::Unauthorized,
                "Session expired.".to_string(),
            ));
        }

        let user = match store.load_user(&session.user_id).await {
            Ok(u) => u,
            Err(AuthStoreError::UserNotFound) => {
                // This shouldn't happen if session exists for a valid user_id, but good for robustness
                cookies.remove(session_cookie.clone());
                return rocket::request::Outcome::Error((
                    Status::Unauthorized,
                    "Associated user not found.".to_string(),
                ));
            }
            Err(e) => {
                return rocket::request::Outcome::Error((
                    Status::InternalServerError,
                    format!("Failed to load user: {e}"),
                ));
            }
        };

        rocket::request::Outcome::Success(AuthUser { user, session })
    }
}

/// Route for accepting login requests
#[post("/login", data = "<login_data>")]
async fn login_route(
    store: &State<Arc<dyn AuthStore>>,
    cookies: &CookieJar<'_>,
    login_data: rocket::serde::json::Json<LoginRequest>,
) -> Result<String, Status> {
    let provided_username = login_data.username.clone();
    let provided_password = login_data.password.clone();

    let loaded_user = match store.load_user_by_username(&provided_username).await {
        Ok(u) => u,
        Err(e) => {
            println!("Error loading user from DB: {e:?}");
            return Err(Status::InternalServerError);
        }
    };

    let is_eq = match loaded_user.has_equivilent_hashed_password(provided_password) {
        Ok(eq) => eq,
        Err(e) => {
            println!("Error comparing passwords: {e:?}");
            return Err(Status::InternalServerError);
        }
    };

    if !is_eq {
        return Err(Status::BadRequest);
    }

    let session = Session::new(loaded_user.user_id.to_string(), store.get_duration());
    let signed_session_id = session.id.sign(store.get_key().as_bytes()).to_string();

    match store.save_session(&session).await {
        Ok(_) => {
            cookies.add(
                Cookie::build(("session_id", signed_session_id))
                    .path("/")
                    .http_only(true)
                    .secure(true) // Set to true if using HTTPS in production
                    .same_site(rocket::http::SameSite::Lax),
            );
            Ok(format!("Logged in as user: {}", loaded_user.username))
        }
        Err(e) => {
            eprintln!("Failed to save session for test login: {:?}", e);
            Err(Status::InternalServerError)
        }
    }
}

/// Route for acccepting registration requests
#[post("/register", rank = 1, data = "<register_request>")]
async fn register_route(
    store: &State<Arc<dyn AuthStore>>,
    cookies: &CookieJar<'_>,
    register_request: rocket::serde::json::Json<RegisterRequest>,
    validator: &State<Arc<Option<Password>>>,
) -> Result<String, Status> {
    let username = register_request.username.clone();
    let password = register_request.password.clone();
    let v = validator.as_ref();
    if let Some(v) = v {
        let is_valid_password = v.validate_immutable(&password);

        if !is_valid_password {
            return Err(Status::BadRequest);
        }
    }

    let new_user_id = ulid::Ulid::new();

    let new_user = match User::new_and_hash_password(username, new_user_id, password) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Failed make new user: {:?}", e);
            return Err(Status::InternalServerError);
        }
    };
    let session = Session::new(new_user.user_id.to_string().clone(), store.get_duration());
    let signed_session_id = session.id.sign(store.get_key().as_bytes()).to_string();

    match store.save_session(&session).await {
        Ok(_) => {
            cookies.add(
                Cookie::build(("session_id", signed_session_id))
                    .path("/")
                    .http_only(true)
                    .secure(true) // Set to true if using HTTPS in production
                    .same_site(rocket::http::SameSite::Lax),
            );
        }
        Err(e) => {
            eprintln!("Failed to save session for test login: {:?}", e);
            return Err(Status::InternalServerError);
        }
    }

    match store.save_user(&new_user).await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error saving user: {e:?}");
            return Err(Status::InternalServerError);
        }
    }
    return Ok(format!("Registered as user: {}", new_user.username));
}

/// Route for logging out
#[get("/logout", rank = 1)]
async fn logout_route(store: &State<Arc<dyn AuthStore>>, user: AuthUser) -> Result<String, Status> {
    match store.delete_session(&user.session.id).await {
        Ok(_) => {
            println!("logged out");
            return Ok(String::from("Logged out"));
        }
        Err(e) => {
            println!("Error logging out user: {e:?}");
            return Err(Status::InternalServerError);
        }
    }
}

// --- Public function to expose routes ---
// This function collects all the routes in this module
// and returns them as a Vec<rocket::Route> to be mounted.
/// This function provides three routes needed for authentication:
/// - `/register`
/// - `/login`
/// - `/logout`
pub fn auth_routes() -> Vec<rocket::Route> {
    rocket::routes![login_route, register_route, logout_route]
}
