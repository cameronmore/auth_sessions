//! ## Session Id
//! This module contains the definition for SessionId which is used in the Session type. It includes
//! everything relating to generating signed session ids that can be used in cookies and verifying
//! signed session ids that are retrieved from incoming requests.

use base64::Engine as _;
use ring::{error::Unspecified, hmac};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};
use uuid::Uuid;

/// SessionId is essentially a wrapper for a UUIDv4 used for giving users unique session ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

/// Error type for working with SessionId
#[derive(Debug, PartialEq, Eq)]
pub enum SessionIdError {
    // todo, consider renameing this to IncorrectLength
    InvalidFormat,
    InvalidSignature,
    UuidError(uuid::Error),
    Base64Error(base64::DecodeError),
    RingCryptoError(String),
}

impl Display for SessionIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionIdError::InvalidFormat => write!(f, "Invalid session ID format"),
            SessionIdError::InvalidSignature => write!(f, "Invalid session ID signature"),
            SessionIdError::UuidError(e) => write!(f, "UUID parsing error: {e}"),
            SessionIdError::Base64Error(e) => write!(f, "Base64 decoding error: {e}"),
            SessionIdError::RingCryptoError(e) => write!(f, "Cryptographic error: {e}"),
        }
    }
}

impl std::error::Error for SessionIdError {}

impl From<uuid::Error> for SessionIdError {
    fn from(value: uuid::Error) -> Self {
        SessionIdError::UuidError(value)
    }
}

impl From<base64::DecodeError> for SessionIdError {
    fn from(value: base64::DecodeError) -> Self {
        SessionIdError::Base64Error(value)
    }
}

impl From<Unspecified> for SessionIdError {
    fn from(value: Unspecified) -> Self {
        SessionIdError::RingCryptoError(format!("ring crypto error: {value:?}"))
    }
}

impl SessionId {
    /// Returns a new SessionId
    pub fn new() -> Self {
        SessionId(Uuid::new_v4())
    }

    /// Returns a string that is a session id followed by a signature that was encrypted with
    /// a secret key, separated by a ".", in the form:
    ///
    /// SessionId.Signature
    pub fn sign(&self, secret_key: &[u8]) -> String {
        let id_str = self.to_string();
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key);
        let signature = hmac::sign(&key, id_str.as_bytes());
        let encoded_signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
        format!("{id_str}.{encoded_signature}")
    }
}

impl Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for SessionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SessionId(uuid::Uuid::parse_str(s)?))
    }
}

impl From<uuid::Uuid> for SessionId {
    fn from(value: uuid::Uuid) -> Self {
        SessionId(value)
    }
}

impl TryFrom<String> for SessionId {
    type Error = uuid::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let new_uuid_result = uuid::Uuid::try_from(value);
        match new_uuid_result {
            Ok(u) => Ok(Self::from(u)),
            Err(e) => Err(e),
        }
    }
}

/// Takes a signed session id and a key and verifies the signature.
pub fn verify_signed_session_id(
    signed_id_str: &str,
    secret_key: &[u8],
) -> Result<SessionId, SessionIdError> {
    let parts: Vec<&str> = signed_id_str.split('.').collect();
    if parts.len() != 2 {
        return Err(SessionIdError::InvalidFormat);
    }

    let id_str = parts[0];
    let encoded_signature = parts[1];

    let decoded_signature_bytes =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded_signature)?;

    let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key);

    hmac::verify(&key, id_str.as_bytes(), &decoded_signature_bytes)
        .map_err(|_| SessionIdError::InvalidSignature)?; // Convert ring::error::Unspecified to InvalidSignature on failure

    let uuid = Uuid::parse_str(id_str)?;
    Ok(SessionId(uuid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_id() {
        let _id = SessionId::new();
        assert!(true)
    }

    #[test]
    fn new_session_id_from_uuid() {
        let new_uuid = uuid::Uuid::new_v4();
        let new_session_id = SessionId::from(new_uuid);
        assert_eq!(new_session_id.to_string(), new_uuid.to_string());
    }

    #[test]
    fn new_session_id_from_string() {
        let new_uuid_string = uuid::Uuid::new_v4().to_string();
        let new_session_id = SessionId::try_from(new_uuid_string.clone());
        assert_eq!(new_session_id.unwrap().to_string(), new_uuid_string);
    }

    #[test]
    fn invalid_from_string() {
        let invalid_uuid_string = "not-valid".to_string();
        let new_invalid_session_id_result = SessionId::try_from(invalid_uuid_string.clone());
        match new_invalid_session_id_result {
            Err(_) => {
                assert!(true)
            }
            _ => {
                panic!("Expected error, got no error")
            }
        }
    }

    #[test]
    fn test_sign_and_verify_id() {
        let secret = "This_is_a_good_test_secret_key";
        let new_id = SessionId::new();
        let new_signed_id = new_id.sign(&secret.as_bytes());
        match verify_signed_session_id(&new_signed_id, &secret.as_bytes()) {
            Ok(_) => {
                assert!(true);
            }
            Err(e) => {
                println!("{e:?}");
                panic!("Did not expect error verifying signed session id")
            }
        };
    }

    #[test]
    fn test_sign_and_verify_incorrect_id() {
        let secret = "This_is_a_good_test_secret_key";
        match verify_signed_session_id(&String::from("not_valid_session_id"), &secret.as_bytes()) {
            Ok(o) => {
                println!("{o:?}");
                panic!("Expected error veridying invalid session id")
            }
            Err(e) => match e {
                SessionIdError::InvalidFormat => {
                    assert!(true)
                }
                _ => {
                    panic!("Got the wrong session id error, expected invalid format")
                }
            },
        };
    }
}
