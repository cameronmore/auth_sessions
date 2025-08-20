# Auth Sessions

> 🚧 NOTE, this library is pre-1.0.0, and should not be considered stable. See TODOs for a list of features needed before a stable(-ish) release can be considered

This library is designed to provide a simple and extensible session based authentication solution for web applications.

Currently, it's only designed to work with axum and rocket and handles registration (including password requirement validation), login, logout, and middleware authentication, all batteries included.

## Documentation

The overall approach to using this library is to choose an auth store (or make your own) that implements the AuthStore trait and then use it in your framework of choice (currently, only Axum and Rocket are supported).

This library includes three implementations of the AuthStore trait for:
- SQLite
- Postgres
- MongoDB

Below are two hello-world examples of how to use this library with Axum and Rocket:

Axum:
```rust
use auth_sessions::auth_store::{AuthStore, SqliteAuthStore};
use auth_sessions::axum_auth_sessions::{self, AuthUser};
use auth_sessions::password_validator::Password;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use dotenv_lib as dot;
use axum::http::StatusCode;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

async fn protected_route(auth_user: AuthUser) -> impl IntoResponse {
    Json(serde_json::json!({
        "message": format!("Hello, {}!", auth_user.user.username),
        "user_id": auth_user.user.user_id,
        "session_id": auth_user.session.id.to_string()
    }))
}

// Example user profile route
async fn get_profile(auth_user: AuthUser) -> impl IntoResponse {
    Json(serde_json::json!({
        "username": auth_user.user.username,
        "user_id": auth_user.user.user_id,
        "session_created": auth_user.session.created_at,
        "session_expires": auth_user.session.expires_at
    }))
}

// Example admin route that could check any set roles in the user type
async fn admin_route(auth_user: AuthUser) -> Result<impl IntoResponse, (StatusCode, String)> {
    //auth_user.user.get("role")...
    Ok(Json(serde_json::json!({
        "message": "Admin area",
        "user": auth_user.user.username
    })))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // load the env variables
    let env_contents = fs::read_to_string(".env").expect("unable to read file");
    let new_env_map: HashMap<String, String> =
        dot::process_dot_env(env_contents).expect("unable to parse env file");
    let sk = new_env_map.get("AUTH_KEY").expect("No auth key found");

    // SQLite example, be sure that auth.db exists before trying to access it
    let new_app_auth_store = SqliteAuthStore::new("sqlite://auth.db", sk.clone(), chrono::TimeDelta::days(7)).await?;

    // define the shared store
    let shared_auth_store: Arc<dyn AuthStore> = Arc::new(new_app_auth_store);

    // create a new validator and define its parameters
    let mut validator = Password::new();
    validator
        .min(5)
        .max(30)
        .allow_whitespace(false)
        .min_special_chars(2);

    // here, we wrap the validator in an Arc for the axum Extension
    let shared_validator = Some(Arc::new(validator));

    // here, we can define an empty validator if we don't want one, but it is recommmended
    //let null_password_validator: Option<Arc<Password>> = None;

    let app = Router::new()
        // Auth routes (no authentication required)
        .route("/register", post(axum_auth_sessions::register_user))
        .route("/login", post(axum_auth_sessions::login_user))
        .route("/logout", get(axum_auth_sessions::logout_user))
        // Protected routes (authentication required)
        .route("/protected", get(protected_route))
        .route("/profile", get(get_profile))
        .route("/admin", get(admin_route))
        .layer(tower_cookies::CookieManagerLayer::new())
        .layer(Extension(shared_auth_store.clone()))
        .layer(Extension(shared_validator));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
```

And Rocket:
```rust
#[macro_use] extern crate rocket;

use std::{collections::HashMap, sync::Arc};
use auth_sessions::{auth_store::{AuthStore, SqliteAuthStore}, password_validator::Password, rocket_auth_sessions::{self, AuthUser}};
use dotenv_lib as dot;

/// Only returns a string if the user is authenticated
#[get("/profile", rank=1)]
async fn profile(user: AuthUser) -> String {
    format!("Welcome {}!", user.user.username)
}

/// Example access to the session object when user is authenticated
#[get("/session", rank=1)]
async fn session_route(user: AuthUser) -> String {
    format!("{}, {}, {}",user.session.id,user.session.expires_at, user.session.user_id)
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {

    // This code is just boilerplate to get the secret auth key from an .env file
    let env_contents = std::fs::read_to_string(".env").expect("unable to read file");
    let new_env_map: HashMap<String, String> =
        dot::process_dot_env(env_contents).expect("unable to parse env file");
    let sk = new_env_map.get("AUTH_KEY").expect("No auth key found");

    // Define a new auth store and make it sharable by wrapping it in
    // an Arc. Be sure that the SQLite file exists before running the app
    let new_app_auth_store = SqliteAuthStore::new("sqlite://auth.db", sk.clone(),chrono::TimeDelta::days(1)).await.expect("Unable to create auth store");
    let shared_auth_store: Arc<dyn AuthStore> = Arc::new(new_app_auth_store);
    
    let mut validator = Password::new();
    validator
        .min(5)
        .max(30)
        .allow_whitespace(false)
        .min_special_chars(2);

    // here, we wrap the validator in an Arc for the axum Extension
    let shared_validator: Arc<Option<Password>> = Arc::new(Some(validator));

    let _rocket = rocket::build()
        .mount("/", routes![profile, session_route])
        // Mount the auth route and pass it the auth_routes() function
        .mount("/auth", rocket_auth_sessions::auth_routes())
        // Pass the auth store to the app
        .manage(shared_auth_store as Arc<dyn AuthStore>)
        .manage(shared_validator as Arc<Option<Password>>)
        .launch()
        .await?;

    Ok(())
}
```

## TODOs

- Remove certain debugging statements and returns
- Improve error messages that are returned to clients on various kinds of expected failures (like ErrUsernameAlreadyInUse, ErrPasswordDoesNotMeetRequirements)

### License

This project is licensed under the Apache-2.0 license.