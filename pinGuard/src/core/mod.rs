pub mod config;
pub mod enhanced_config;
pub mod errors;
pub mod service_locator;
pub mod traits;
pub mod utils;

// Re-export commonly used types
pub use errors::{ErrorContext, PinGuardError, PinGuardResult};
pub use traits::{
    Category, Finding, Fixer, FixResult, FixStatus,
    ScanResult, ScanStatus, Scanner, Severity, ConfigProvider,
};
