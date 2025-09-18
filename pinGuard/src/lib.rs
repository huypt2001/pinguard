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

pub use scanners::{ScanError, ScanResult, Scanner};
