//! PinGuard - Linux-first Vulnerability Scanner & Remediator
//!
//! This library provides security scanning and remediation capabilities for Linux systems.

pub mod core;
pub mod cve;
pub mod database;
pub mod fixers;
pub mod report;
pub mod scanners;
pub mod scheduler;

// Test utilities (only available during testing)
#[cfg(test)]
pub mod testing;

// Re-export commonly used types from core
pub use core::{
    Category, Finding, Fixer, FixResult,
    FixStatus, PinGuardError, PinGuardResult, ScanResult, ScanStatus, Scanner, Severity,
};

// Legacy re-exports for backward compatibility
pub use scanners::{ScanError, ScanResult as LegacyScanResult, Scanner as LegacyScanner};
