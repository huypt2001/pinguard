//! Centralized error handling for PinGuard
//!
//! This module provides standardized error types and error handling utilities
//! to ensure consistent error management across the entire application.

use std::fmt;
use thiserror::Error;

/// Main error type for PinGuard operations
#[derive(Debug, Clone, Error)]
#[allow(dead_code)]
pub enum PinGuardError {
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Scanner '{scanner}' error: {message}")]
    Scanner {
        scanner: String,
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Fixer '{fixer}' error: {message}")]
    Fixer {
        fixer: String,
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Database error: {message}")]
    Database {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Network error: {message}")]
    Network {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("I/O error: {message}")]
    Io {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Permission denied: {message}")]
    Permission {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("CVE API error: {message}")]
    CveApi {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Validation error: {message}")]
    Validation {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Parse error: {message}")]
    Parse {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Timeout error: {message}")]
    Timeout {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Authentication error: {message}")]
    Authentication {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Authorization error: {message}")]
    Authorization {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Not found: {message}")]
    NotFound {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Already exists: {message}")]
    AlreadyExists {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Dependency error: {message}")]
    Dependency {
        message: String,
        source: Option<Box<PinGuardError>>,
    },

    #[error("Unknown error: {message}")]
    Unknown {
        message: String,
        source: Option<Box<PinGuardError>>,
    },
}

/// Result type for PinGuard operations
pub type PinGuardResult<T> = Result<T, PinGuardError>;

#[allow(dead_code)]
impl PinGuardError {
    /// Create a new configuration error
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Config {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new configuration error with source
    pub fn config_with_source<S: Into<String>>(message: S, source: PinGuardError) -> Self {
        Self::Config {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a new scanner error
    pub fn scanner<S1: Into<String>, S2: Into<String>>(scanner: S1, message: S2) -> Self {
        Self::Scanner {
            scanner: scanner.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Create a new scanner error with source
    pub fn scanner_with_source<S1: Into<String>, S2: Into<String>>(
        scanner: S1,
        message: S2,
        source: PinGuardError,
    ) -> Self {
        Self::Scanner {
            scanner: scanner.into(),
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a new fixer error
    pub fn fixer<S1: Into<String>, S2: Into<String>>(fixer: S1, message: S2) -> Self {
        Self::Fixer {
            fixer: fixer.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Create a new fixer error with source
    pub fn fixer_with_source<S1: Into<String>, S2: Into<String>>(
        fixer: S1,
        message: S2,
        source: PinGuardError,
    ) -> Self {
        Self::Fixer {
            fixer: fixer.into(),
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a new database error
    pub fn database<S: Into<String>>(message: S) -> Self {
        Self::Database {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new I/O error
    pub fn io<S: Into<String>>(message: S) -> Self {
        Self::Io {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new network error
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new permission error
    pub fn permission<S: Into<String>>(message: S) -> Self {
        Self::Permission {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new parse error
    pub fn parse<S: Into<String>>(message: S) -> Self {
        Self::Parse {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new timeout error
    pub fn timeout<S: Into<String>>(message: S) -> Self {
        Self::Timeout {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new not found error
    pub fn not_found<S: Into<String>>(message: S) -> Self {
        Self::NotFound {
            message: message.into(),
            source: None,
        }
    }

    /// Check if this is a retryable error
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            PinGuardError::Network { .. }
                | PinGuardError::Timeout { .. }
                | PinGuardError::CveApi { .. }
        )
    }

    /// Get the error category
    pub fn category(&self) -> ErrorCategory {
        match self {
            PinGuardError::Config { .. } => ErrorCategory::Configuration,
            PinGuardError::Scanner { .. } => ErrorCategory::Scanner,
            PinGuardError::Fixer { .. } => ErrorCategory::Fixer,
            PinGuardError::Database { .. } => ErrorCategory::Database,
            PinGuardError::Network { .. } => ErrorCategory::Network,
            PinGuardError::Io { .. } => ErrorCategory::IO,
            PinGuardError::Permission { .. } => ErrorCategory::Permission,
            PinGuardError::CveApi { .. } => ErrorCategory::External,
            PinGuardError::Validation { .. } => ErrorCategory::Validation,
            PinGuardError::Parse { .. } => ErrorCategory::Parse,
            PinGuardError::Timeout { .. } => ErrorCategory::Timeout,
            PinGuardError::Authentication { .. } => ErrorCategory::Authentication,
            PinGuardError::Authorization { .. } => ErrorCategory::Authorization,
            PinGuardError::NotFound { .. } => ErrorCategory::NotFound,
            PinGuardError::AlreadyExists { .. } => ErrorCategory::AlreadyExists,
            PinGuardError::Dependency { .. } => ErrorCategory::Dependency,
            PinGuardError::Unknown { .. } => ErrorCategory::Unknown,
        }
    }

    /// Get error severity
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            PinGuardError::Config { .. } => ErrorSeverity::High,
            PinGuardError::Database { .. } => ErrorSeverity::High,
            PinGuardError::Permission { .. } => ErrorSeverity::High,
            PinGuardError::Authentication { .. } => ErrorSeverity::High,
            PinGuardError::Authorization { .. } => ErrorSeverity::High,
            PinGuardError::Scanner { .. } => ErrorSeverity::Medium,
            PinGuardError::Fixer { .. } => ErrorSeverity::Medium,
            PinGuardError::Validation { .. } => ErrorSeverity::Medium,
            PinGuardError::Parse { .. } => ErrorSeverity::Medium,
            PinGuardError::Network { .. } => ErrorSeverity::Low,
            PinGuardError::Timeout { .. } => ErrorSeverity::Low,
            PinGuardError::CveApi { .. } => ErrorSeverity::Low,
            PinGuardError::NotFound { .. } => ErrorSeverity::Low,
            PinGuardError::AlreadyExists { .. } => ErrorSeverity::Low,
            PinGuardError::Io { .. } => ErrorSeverity::Medium,
            PinGuardError::Dependency { .. } => ErrorSeverity::Medium,
            PinGuardError::Unknown { .. } => ErrorSeverity::Medium,
        }
    }
}

/// Error categories for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ErrorCategory {
    Configuration,
    Scanner,
    Fixer,
    Database,
    Network,
    IO,
    Permission,
    External,
    Validation,
    Parse,
    Timeout,
    Authentication,
    Authorization,
    NotFound,
    AlreadyExists,
    Dependency,
    Unknown,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::Configuration => write!(f, "Configuration"),
            ErrorCategory::Scanner => write!(f, "Scanner"),
            ErrorCategory::Fixer => write!(f, "Fixer"),
            ErrorCategory::Database => write!(f, "Database"),
            ErrorCategory::Network => write!(f, "Network"),
            ErrorCategory::IO => write!(f, "I/O"),
            ErrorCategory::Permission => write!(f, "Permission"),
            ErrorCategory::External => write!(f, "External"),
            ErrorCategory::Validation => write!(f, "Validation"),
            ErrorCategory::Parse => write!(f, "Parse"),
            ErrorCategory::Timeout => write!(f, "Timeout"),
            ErrorCategory::Authentication => write!(f, "Authentication"),
            ErrorCategory::Authorization => write!(f, "Authorization"),
            ErrorCategory::NotFound => write!(f, "Not Found"),
            ErrorCategory::AlreadyExists => write!(f, "Already Exists"),
            ErrorCategory::Dependency => write!(f, "Dependency"),
            ErrorCategory::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Low => write!(f, "Low"),
            ErrorSeverity::Medium => write!(f, "Medium"),
            ErrorSeverity::High => write!(f, "High"),
            ErrorSeverity::Critical => write!(f, "Critical"),
        }
    }
}

// Conversion implementations for common error types
impl From<std::io::Error> for PinGuardError {
    fn from(err: std::io::Error) -> Self {
        PinGuardError::io(format!("I/O operation failed: {}", err))
    }
}

impl From<serde_yaml::Error> for PinGuardError {
    fn from(err: serde_yaml::Error) -> Self {
        PinGuardError::parse(format!("YAML parsing failed: {}", err))
    }
}

impl From<serde_json::Error> for PinGuardError {
    fn from(err: serde_json::Error) -> Self {
        PinGuardError::parse(format!("JSON parsing failed: {}", err))
    }
}

impl From<reqwest::Error> for PinGuardError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            PinGuardError::timeout(format!("HTTP request timed out: {}", err))
        } else if err.is_connect() {
            PinGuardError::network(format!("Network connection failed: {}", err))
        } else {
            PinGuardError::network(format!("HTTP request failed: {}", err))
        }
    }
}

impl From<rusqlite::Error> for PinGuardError {
    fn from(err: rusqlite::Error) -> Self {
        PinGuardError::database(format!("Database operation failed: {}", err))
    }
}

impl From<tokio::time::error::Elapsed> for PinGuardError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        PinGuardError::timeout(format!("Operation timed out: {}", err))
    }
}

/// Error context trait for adding context to errors
#[allow(dead_code)]
pub trait ErrorContext<T> {
    fn with_context<F>(self, f: F) -> PinGuardResult<T>
    where
        F: FnOnce() -> String;

    fn with_scanner_context<F>(self, scanner: &str, f: F) -> PinGuardResult<T>
    where
        F: FnOnce() -> String;

    fn with_fixer_context<F>(self, fixer: &str, f: F) -> PinGuardResult<T>
    where
        F: FnOnce() -> String;
}

impl<T, E> ErrorContext<T> for Result<T, E>
where
    E: Into<PinGuardError>,
{
    fn with_context<F>(self, f: F) -> PinGuardResult<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| {
            let original_error = e.into();
            match original_error {
                PinGuardError::Unknown { .. } => PinGuardError::Unknown {
                    message: f(),
                    source: Some(Box::new(original_error)),
                },
                _ => original_error,
            }
        })
    }

    fn with_scanner_context<F>(self, scanner: &str, f: F) -> PinGuardResult<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| PinGuardError::scanner_with_source(scanner, f(), e.into()))
    }

    fn with_fixer_context<F>(self, fixer: &str, f: F) -> PinGuardResult<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| PinGuardError::fixer_with_source(fixer, f(), e.into()))
    }
}

/// Utility functions for error handling
pub mod utils {
    use super::*;
    use tracing::{error, warn};

    /// Log an error with appropriate level based on severity
    #[allow(dead_code)]
    pub fn log_error(err: &PinGuardError) {
        match err.severity() {
            ErrorSeverity::Critical | ErrorSeverity::High => {
                error!(
                    category = %err.category(),
                    severity = %err.severity(),
                    error = %err,
                    "Critical error occurred"
                );
            }
            ErrorSeverity::Medium => {
                warn!(
                    category = %err.category(),
                    severity = %err.severity(),
                    error = %err,
                    "Error occurred"
                );
            }
            ErrorSeverity::Low => {
                warn!(
                    category = %err.category(),
                    severity = %err.severity(),
                    error = %err,
                    "Minor error occurred"
                );
            }
        }
    }

    /// Check if an error should cause the application to exit
    #[allow(dead_code)]
    pub fn is_fatal_error(err: &PinGuardError) -> bool {
        matches!(
            err,
            PinGuardError::Config { .. } | PinGuardError::Database { .. }
        ) && err.severity() == ErrorSeverity::Critical
    }

    /// Retry logic for retryable errors
    #[allow(dead_code)]
    pub async fn retry_on_error<T, F, Fut>(
        mut operation: F,
        max_retries: usize,
        base_delay: std::time::Duration,
    ) -> PinGuardResult<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = PinGuardResult<T>>,
    {
        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(err) if err.is_retryable() && attempts < max_retries => {
                    warn!(
                        attempt = attempts + 1,
                        max_retries = max_retries,
                        error = %err,
                        "Retrying operation after error"
                    );
                    
                    let delay = base_delay * 2_u32.pow(attempts as u32);
                    tokio::time::sleep(delay).await;
                    last_error = Some(err);
                    attempts += 1;
                }
                Err(err) => return Err(err),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            PinGuardError::Unknown {
                message: "Retry logic failed unexpectedly".to_string(),
                source: None,
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = PinGuardError::scanner("test_scanner", "test message");
        assert!(matches!(err, PinGuardError::Scanner { .. }));
        assert_eq!(err.category(), ErrorCategory::Scanner);
    }

    #[test]
    fn test_error_severity() {
        let config_err = PinGuardError::config("test");
        assert_eq!(config_err.severity(), ErrorSeverity::High);

        let network_err = PinGuardError::network("test");
        assert_eq!(network_err.severity(), ErrorSeverity::Low);
    }

    #[test]
    fn test_retryable_error() {
        let network_err = PinGuardError::network("test");
        assert!(network_err.is_retryable());

        let config_err = PinGuardError::config("test");
        assert!(!config_err.is_retryable());
    }

    #[tokio::test]
    async fn test_retry_logic() {
        let mut call_count = 0;
        let result = utils::retry_on_error(
            || {
                call_count += 1;
                async move {
                    if call_count < 3 {
                        Err(PinGuardError::network("temporary failure"))
                    } else {
                        Ok("success")
                    }
                }
            },
            3,
            std::time::Duration::from_millis(1),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(call_count, 3);
    }
}