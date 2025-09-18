pub mod kernel_check;
pub mod manager;
pub mod network_audit;
pub mod package_audit;
pub mod permission_audit;
pub mod service_audit;
pub mod user_audit;
// Other modules will be added progressively
// pub mod service_audit;
// pub mod user_audit;
// pub mod network_audit;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main scanner trait - all scanners implement this
pub trait Scanner {
    fn name(&self) -> &'static str;
    fn scan(&self) -> Result<ScanResult, ScanError>;
    fn is_enabled(&self, config: &crate::core::config::Config) -> bool;
}

/// Main scan result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanner_name: String,
    pub scan_time: String,
    pub status: ScanStatus,
    pub findings: Vec<Finding>,
    pub metadata: ScanMetadata,
    pub raw_data: Option<HashMap<String, String>>,
}

/// Scan status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum ScanStatus {
    Success,
    Warning,
    Error(String),
    Skipped(String),
}

/// Individual finding (vulnerability, misconfiguration, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: Category,
    pub affected_item: String,
    pub current_value: Option<String>,
    pub recommended_value: Option<String>,
    pub references: Vec<String>,
    pub cve_ids: Vec<String>,
    pub fix_available: bool,
}

/// Finding severity level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Finding category
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum Category {
    Package,
    Kernel,
    Permission,
    Service,
    User,
    Network,
    Configuration,
    Security,
}

/// Scan metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub duration_ms: u64,
    pub items_scanned: u32,
    pub issues_found: u32,
    pub scan_timestamp: String,
    pub scanner_version: String,
}

/// Scanner errors
#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
#[allow(dead_code)]
pub enum ScanError {
    #[error("Command execution failed: {0}")]
    CommandError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Permission denied: {0}")]
    PermissionError(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("External service error: {0}")]
    ExternalServiceError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

#[allow(dead_code)]
impl ScanResult {
    pub fn new(scanner_name: String) -> Self {
        Self {
            scanner_name,
            scan_time: chrono::Utc::now().to_rfc3339(),
            status: ScanStatus::Success,
            findings: Vec::new(),
            metadata: ScanMetadata {
                duration_ms: 0,
                items_scanned: 0,
                issues_found: 0,
                scan_timestamp: chrono::Utc::now().to_rfc3339(),
                scanner_version: "0.1.0".to_string(),
            },
            raw_data: Some(HashMap::new()),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
        self.metadata.issues_found = self.findings.len() as u32;
    }

    pub fn set_duration(&mut self, duration_ms: u64) {
        self.metadata.duration_ms = duration_ms;
    }

    pub fn set_items_scanned(&mut self, count: u32) {
        self.metadata.items_scanned = count;
    }

    pub fn get_critical_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect()
    }

    pub fn get_high_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect()
    }
}
