//! Core traits and interfaces for the PinGuard system
//!
//! This module defines the fundamental abstractions that all components
//! of the PinGuard system implement, ensuring consistency and modularity.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;

// Import PinGuardError and PinGuardResult from errors module
use super::errors::PinGuardResult;

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Categories for findings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Vulnerability,
    Configuration,
    Permission,
    Network,
    Service,
    Package,
    Kernel,
    User,
    Container,
    WebSecurity,
    Custom(String),
}

impl Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::Vulnerability => write!(f, "VULNERABILITY"),
            Category::Configuration => write!(f, "CONFIGURATION"),
            Category::Permission => write!(f, "PERMISSION"),
            Category::Network => write!(f, "NETWORK"),
            Category::Service => write!(f, "SERVICE"),
            Category::Package => write!(f, "PACKAGE"),
            Category::Kernel => write!(f, "KERNEL"),
            Category::User => write!(f, "USER"),
            Category::Container => write!(f, "CONTAINER"),
            Category::WebSecurity => write!(f, "WEB_SECURITY"),
            Category::Custom(name) => write!(f, "{}", name.to_uppercase()),
        }
    }
}

/// A security finding discovered by a scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: Category,
    pub affected_item: String,
    pub recommendation: Option<String>,
    pub cve_id: Option<String>,
    pub cvss_score: Option<f64>,
    pub references: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
    pub fixable: bool,
}

#[allow(dead_code)]
impl Finding {
    pub fn new(
        id: String,
        title: String,
        description: String,
        severity: Severity,
        category: Category,
        affected_item: String,
    ) -> Self {
        Self {
            id,
            title,
            description,
            severity,
            category,
            affected_item,
            recommendation: None,
            cve_id: None,
            cvss_score: None,
            references: Vec::new(),
            metadata: HashMap::new(),
            discovered_at: chrono::Utc::now(),
            fixable: false,
        }
    }

    pub fn with_recommendation(mut self, recommendation: String) -> Self {
        self.recommendation = Some(recommendation);
        self
    }

    pub fn with_cve(mut self, cve_id: String, cvss_score: Option<f64>) -> Self {
        self.cve_id = Some(cve_id);
        self.cvss_score = cvss_score;
        self
    }

    pub fn with_references(mut self, references: Vec<String>) -> Self {
        self.references = references;
        self
    }

    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    pub fn make_fixable(mut self) -> Self {
        self.fixable = true;
        self
    }
}

/// Status of a scan operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanStatus {
    Success,
    Warning,
    Error(String),
    Skipped(String),
}

/// Metadata about a scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub duration: std::time::Duration,
    pub items_scanned: usize,
    pub scanner_version: String,
    pub configuration: HashMap<String, String>,
}

/// Result of a scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanner_name: String,
    pub scan_time: chrono::DateTime<chrono::Utc>,
    pub status: ScanStatus,
    pub findings: Vec<Finding>,
    pub metadata: ScanMetadata,
    pub raw_data: Option<HashMap<String, String>>,
}

/// Main scanner trait that all scanners must implement
#[async_trait]
#[allow(dead_code)]
pub trait Scanner: Send + Sync {
    /// Unique name of the scanner
    fn name(&self) -> &'static str;
    
    /// Human-readable description of what this scanner does
    fn description(&self) -> &'static str;
    
    /// Categories that this scanner covers
    fn categories(&self) -> Vec<Category>;
    
    /// Check if the scanner is enabled in the given configuration
    fn is_enabled(&self, config: &crate::core::enhanced_config::Config) -> bool;
    
    /// Perform the scan operation
    async fn scan(&self, config: &crate::core::enhanced_config::Config) -> PinGuardResult<ScanResult>;
    
    /// Validate that the scanner can run (check dependencies, permissions, etc.)
    async fn validate(&self) -> PinGuardResult<()> {
        Ok(())
    }
    
    /// Get scanner-specific configuration schema
    fn config_schema(&self) -> Option<serde_json::Value> {
        None
    }
}

/// Status of a fix operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FixStatus {
    Success,
    Partial,
    Failed(String),
    Skipped(String),
}

/// Plan for a fix operation (dry run)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixPlan {
    pub fixer_name: String,
    pub finding_id: String,
    pub actions: Vec<FixAction>,
    pub estimated_duration: std::time::Duration,
    pub requires_reboot: bool,
    pub backup_required: bool,
    pub risks: Vec<String>,
}

/// Individual action in a fix plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixAction {
    pub description: String,
    pub command: Option<String>,
    pub files_modified: Vec<String>,
    pub reversible: bool,
}

/// Result of a fix operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixResult {
    pub finding_id: String,
    pub fixer_name: String,
    pub status: FixStatus,
    pub message: String,
    pub actions_taken: Vec<FixAction>,
    pub duration: std::time::Duration,
    pub backup_created: Option<String>,
    pub requires_reboot: bool,
}

/// Main fixer trait that all fixers must implement
#[async_trait]
#[allow(dead_code)]
pub trait Fixer: Send + Sync {
    /// Unique name of the fixer
    fn name(&self) -> &'static str;
    
    /// Human-readable description of what this fixer does
    fn description(&self) -> &'static str;
    
    /// Categories that this fixer can handle
    fn categories(&self) -> Vec<Category>;
    
    /// Check if this fixer can handle the given finding
    fn can_fix(&self, finding: &Finding) -> bool;
    
    /// Check if the fixer is enabled in the given configuration
    fn is_enabled(&self, config: &crate::core::enhanced_config::Config) -> bool;
    
    /// Create a fix plan (dry run) for the given finding
    async fn plan_fix(&self, finding: &Finding, config: &crate::core::enhanced_config::Config) -> PinGuardResult<FixPlan>;
    
    /// Execute the fix for the given finding
    async fn fix(&self, finding: &Finding, config: &crate::core::enhanced_config::Config) -> PinGuardResult<FixResult>;
    
    /// Validate that the fixer can run (check dependencies, permissions, etc.)
    async fn validate(&self) -> PinGuardResult<()> {
        Ok(())
    }
}

/// Configuration provider trait
#[allow(dead_code)]
pub trait ConfigProvider: Send + Sync {
    /// Get configuration value by key
    fn get_string(&self, key: &str) -> Option<String>;
    
    /// Get configuration value by key with default
    fn get_string_or(&self, key: &str, default: &str) -> String {
        self.get_string(key).unwrap_or_else(|| default.to_string())
    }
    
    /// Get boolean configuration value
    fn get_bool(&self, key: &str) -> Option<bool>;
    
    /// Get boolean configuration value with default
    fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }
    
    /// Get integer configuration value
    fn get_int(&self, key: &str) -> Option<i64>;
    
    /// Get integer configuration value with default
    fn get_int_or(&self, key: &str, default: i64) -> i64 {
        self.get_int(key).unwrap_or(default)
    }
    
    /// Get array of strings
    fn get_string_array(&self, key: &str) -> Option<Vec<String>>;
}

/// Service locator trait for dependency injection
#[allow(dead_code)]
pub trait ServiceLocator: Send + Sync {
    /// Get a scanner by name
    fn get_scanner(&self, name: &str) -> Option<Box<dyn Scanner>>;
    
    /// Get all available scanners
    fn get_scanners(&self) -> Vec<Box<dyn Scanner>>;
    
    /// Get a fixer by name
    fn get_fixer(&self, name: &str) -> Option<Box<dyn Fixer>>;
    
    /// Get all available fixers
    fn get_fixers(&self) -> Vec<Box<dyn Fixer>>;
    
    /// Get configuration provider
    fn config(&self) -> &dyn ConfigProvider;
}

/// Event types for the event system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    ScanStarted { scanner: String },
    ScanCompleted { scanner: String, result: ScanResult },
    FixStarted { fixer: String, finding_id: String },
    FixCompleted { fixer: String, result: FixResult },
    ConfigReloaded,
    DatabaseUpdated,
    CveDataUpdated,
    Error { component: String, error: String },
}

/// Event handler trait
#[async_trait]
#[allow(dead_code)]
pub trait EventHandler: Send + Sync {
    async fn handle(&self, event: Event) -> PinGuardResult<()>;
}

/// Event bus trait
#[async_trait]
#[allow(dead_code)]
pub trait EventBus: Send + Sync {
    /// Publish an event
    async fn publish(&self, event: Event) -> PinGuardResult<()>;
    
    /// Subscribe to events
    fn subscribe(&mut self, handler: Box<dyn EventHandler>);
}