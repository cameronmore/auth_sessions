//! ## Password Validator
//! This is a module for validating passwords against some validator instance.
//! The API for defining a new validator is designed to be similar to the
//! Zod validador

use std::fmt::Display;

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordError {
    TooShort,
    TooLong,
    NotEnoughSpecialCharacters,
    TooManySpecialCharacters,
    NotEnoughCapitals,
    TooManyCapitals,
    NotEnoughLowercase,
    TooManyLowercase,
    WhitespaceNotAllowed,
}

impl Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::TooShort => write!(f, "Password is too short"),
            PasswordError::TooLong => write!(f, "Password is too long"),
            PasswordError::NotEnoughSpecialCharacters => {
                write!(f, "Password does not have enough special characters")
            }
            PasswordError::TooManySpecialCharacters => {
                write!(f, "Password has too many special characters")
            }
            PasswordError::NotEnoughCapitals => {
                write!(f, "Password does not have enough capital letters")
            }
            PasswordError::TooManyCapitals => write!(f, "Password has too many capital letters"),

            PasswordError::NotEnoughLowercase => {
                write!(f, "Password does not have enough lowercase letters")
            }
            PasswordError::TooManyLowercase => write!(f, "Password has too many lowercase letters"),
            PasswordError::WhitespaceNotAllowed => write!(f, "Whitespace is not allowed"),
        }
    }
}

#[derive(Debug)]
pub struct Password {
    value: Option<String>,
    is_valid: bool,
    min_length: Option<usize>,
    max_length: Option<usize>,
    min_uppercase: Option<usize>,
    max_uppercase: Option<usize>,
    min_lowercase: Option<usize>,
    max_lowercase: Option<usize>,
    min_special_chars: Option<usize>,
    max_special_chars: Option<usize>,
    whitespace_allowed: Option<bool>,
    errors: Vec<PasswordError>,
}

impl Password {
    /// Returns a new password validator that is reusable aceoss values
    pub fn new() -> Self {
        Self {
            value: None,
            is_valid: false,
            min_length: None,
            max_length: None,
            min_uppercase: None,
            max_uppercase: None,
            min_lowercase: None,
            max_lowercase: None,
            min_special_chars: None,
            max_special_chars: None,
            whitespace_allowed: None,
            errors: Vec::new(),
        }
    }
    /// Returns a new password from a given value ready to validate
    pub fn new_from_value(value: impl Into<String>) -> Self {
        Self {
            value: Some(value.into()),
            is_valid: false,
            min_length: None,
            max_length: None,
            min_uppercase: None,
            max_uppercase: None,
            min_lowercase: None,
            max_lowercase: None,
            min_special_chars: None,
            max_special_chars: None,
            whitespace_allowed: None,
            errors: Vec::new(),
        }
    }
    /// Sets the value of the string to validate
    pub fn set_value(&mut self, value: impl Into<String>) {
        self.value = Some(value.into());
    }
    /// Sets the minimum length of a password
    pub fn min(&mut self, min: usize) -> &mut Self {
        self.min_length = Some(min);
        self
    }
    /// Sets the maximum length of a password
    pub fn max(&mut self, max: usize) -> &mut Self {
        self.max_length = Some(max);
        self
    }
    /// Sets the minimum number of capitals in a password
    pub fn min_uppercase(&mut self, num: usize) -> &mut Self {
        self.min_uppercase = Some(num);
        self
    }
    /// Sets the maximum number of capitals in a password
    pub fn max_uppercase(&mut self, num: usize) -> &mut Self {
        self.max_uppercase = Some(num);
        self
    }
    /// Sets the minimum number of lowercase in a password
    pub fn min_lowercase(&mut self, num: usize) -> &mut Self {
        self.min_lowercase = Some(num);
        self
    }
    /// Sets the maximum number of lowercase in a password
    pub fn max_lowercase(&mut self, num: usize) -> &mut Self {
        self.max_lowercase = Some(num);
        self
    }
    /// Sets the min number of special characters in a password
    pub fn min_special_chars(&mut self, num: usize) -> &mut Self {
        self.min_special_chars = Some(num);
        self
    }
    /// Sets the max number of special characters in a password
    pub fn max_special_chars(&mut self, num: usize) -> &mut Self {
        self.max_special_chars = Some(num);
        self
    }
    pub fn allow_whitespace(&mut self, opt: bool) -> &mut Self {
        self.whitespace_allowed = Some(opt);
        self
    }
    /// Validates the password
    pub fn validate(&mut self) -> bool {
        self.is_valid = true;
        self.errors.clear();
        let value = match &self.value {
            Some(v) => v,
            None => return false,
        };

        if let Some(m) = self.min_length {
            if value.chars().count() < m {
                self.is_valid = false;
                self.errors.push(PasswordError::TooShort);
            }
        }
        if let Some(m) = self.max_length {
            if value.chars().count() > m {
                self.is_valid = false;
                self.errors.push(PasswordError::TooLong);
            }
        }

        let mut capital_count: usize = 0;
        let mut lowercase_count: usize = 0;
        let mut special_char_count: usize = 0;
        let mut whitespace_count: usize = 0;

        for c in value.chars() {
            if c.is_uppercase() {
                capital_count += 1;
            } else if c.is_lowercase() {
                lowercase_count += 1;
            } else if is_ascii_special_char(c) {
                special_char_count += 1;
            } else if c.is_whitespace() {
                whitespace_count += 1;
            }
        }

        if let Some(m) = self.min_uppercase {
            if capital_count < m {
                self.is_valid = false;
                self.errors.push(PasswordError::NotEnoughCapitals)
            }
        }

        if let Some(m) = self.max_uppercase {
            if capital_count > m {
                self.is_valid = false;
                self.errors.push(PasswordError::TooManyCapitals)
            }
        }

        if let Some(m) = self.min_lowercase {
            if lowercase_count < m {
                self.is_valid = false;
                self.errors.push(PasswordError::NotEnoughLowercase)
            }
        }

        if let Some(m) = self.max_lowercase {
            if lowercase_count > m {
                self.is_valid = false;
                self.errors.push(PasswordError::TooManyLowercase)
            }
        }

        if let Some(m) = self.min_special_chars {
            if special_char_count < m {
                self.is_valid = false;
                self.errors.push(PasswordError::NotEnoughSpecialCharacters)
            }
        }

        if let Some(m) = self.max_special_chars {
            if special_char_count > m {
                self.is_valid = false;
                self.errors.push(PasswordError::TooManySpecialCharacters)
            }
        }

        if let Some(opt) = self.whitespace_allowed {
            if opt && whitespace_count != 0 {
                self.is_valid = false;
                self.errors.push(PasswordError::WhitespaceNotAllowed);
            }
        }

        self.is_valid
    }

    /// A more efficent validate method that does not mutate the validator object and can be used in
    /// middlewares, layers, and extensions.
    pub fn validate_immutable(&self, value: &String) -> bool {
        let mut is_valid = true;

        if let Some(m) = self.min_length {
            if value.chars().count() < m {
                is_valid = false;
                return is_valid;
            }
        }
        if let Some(m) = self.max_length {
            if value.chars().count() > m {
                is_valid = false;
                return is_valid;
            }
        }

        let mut capital_count: usize = 0;
        let mut lowercase_count: usize = 0;
        let mut special_char_count: usize = 0;
        let mut whitespace_count: usize = 0;

        for c in value.chars() {
            if c.is_uppercase() {
                capital_count += 1;
            } else if c.is_lowercase() {
                lowercase_count += 1;
            } else if is_ascii_special_char(c) {
                special_char_count += 1;
            } else if c.is_whitespace() {
                whitespace_count += 1;
            }
        }

        if let Some(m) = self.min_uppercase {
            if capital_count < m {
                is_valid = false;
                return is_valid;
            }
        }

        if let Some(m) = self.max_uppercase {
            if capital_count > m {
                is_valid = false;
                return is_valid;
            }
        }

        if let Some(m) = self.min_lowercase {
            if lowercase_count < m {
                is_valid = false;
                return is_valid;
            }
        }

        if let Some(m) = self.max_lowercase {
            if lowercase_count > m {
                is_valid = false;
                return is_valid;
            }
        }

        if let Some(m) = self.min_special_chars {
            if special_char_count < m {
                is_valid = false;
                return is_valid;
            }
        }

        if let Some(m) = self.max_special_chars {
            if special_char_count > m {
                is_valid = false;
                return is_valid;
            }
        }

        if let Some(opt) = self.whitespace_allowed {
            if opt && whitespace_count != 0 {
                is_valid = false;
                return is_valid;
            }
        }

        is_valid
    }
}

impl Default for Password {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to check for special characters
fn is_ascii_special_char(c: char) -> bool {
    let special_chars = "!@#$%^&*()_+-=[]{}\\|;:'\",<.>/?`~";
    special_chars.contains(c)
}

impl<T: Into<String>> From<T> for Password {
    fn from(value: T) -> Self {
        Password::new_from_value(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_basic() {
        let mut new_validator = Password::new_from_value("toolong");
        new_validator.max(5).min(1);
        new_validator.validate();
        assert_eq!(new_validator.is_valid, false);
        assert_eq!(new_validator.errors.len(), 1)
    }

    #[test]
    fn test_new_from() {
        let mut new_password = Password::from("password");
        assert_eq!(new_password.validate(), true);
    }

    #[test]
    fn test_full_validator() {
        let mut password = Password::from("word!");
        password.min(10).min_uppercase(2).min_special_chars(2);
        password.validate();
        assert_eq!(password.errors.len(), 3);
    }

    #[test]
    fn test_empty_validator() {
        let mut validator = Password::new();
        validator.min(3);
        assert_eq!(validator.value, None);
        assert_eq!(validator.max_length, None);
        assert_eq!(validator.value, None);
        assert_eq!(validator.validate(), false);
        validator.value = Some("password".into());
        validator.validate();
        assert_eq!(validator.is_valid, true);
    }

    #[test]
    fn test_special_chars() {
        let mut v = Password::new_from_value("passw_rd@");
        v.min_special_chars(2).max_special_chars(7);
        //v.value = Some("passw_rd@");
        v.validate();
        assert_eq!(v.is_valid, true);
        v.value = Some("passw_rd@`#\\'\"*".to_string());
        v.validate();
        assert_eq!(v.is_valid, false);
    }
}
