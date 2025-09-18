//! Test utilities and framework for PinGuard
//!
//! This module provides testing utilities, mock implementations,
//! and test fixtures for comprehensive testing.

use crate::core::{
    enhanced_config::Config, Category, Finding, Fixer,
    FixResult, FixStatus, PinGuardResult, ScanResult, ScanStatus, Scanner,
    Severity,
    service_locator::ServiceRegistry,
    traits::{Event, EventHandler, FixPlan, ScanMetadata},
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Mock scanner for testing
pub struct MockScanner {
    name: String,
    findings: Vec<Finding>,
    should_fail: bool,
}

impl MockScanner {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            findings: Vec::new(),
            should_fail: false,
        }
    }

    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }

    pub fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }
}

#[async_trait]
impl Scanner for MockScanner {
    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn description(&self) -> &'static str {
        "Mock scanner for testing"
    }

    fn categories(&self) -> Vec<Category> {
        vec![Category::Custom("test".to_string())]
    }

    fn is_enabled(&self, _config: &Config) -> bool {
        true
    }

    async fn scan(&self, _config: &Config) -> PinGuardResult<ScanResult> {
        if self.should_fail {
            return Err(crate::core::PinGuardError::scanner(
                &self.name,
                "Mock scanner failure",
            ));
        }

        Ok(ScanResult {
            scanner_name: self.name.clone(),
            scan_time: chrono::Utc::now(),
            status: ScanStatus::Success,
            findings: self.findings.clone(),
            metadata: ScanMetadata {
                duration: Duration::from_millis(100),
                items_scanned: self.findings.len(),
                scanner_version: "1.0.0-test".to_string(),
                configuration: HashMap::new(),
            },
            raw_data: None,
        })
    }
}

/// Mock fixer for testing
pub struct MockFixer {
    name: String,
    can_fix_predicate: Box<dyn Fn(&Finding) -> bool + Send + Sync>,
    should_fail: bool,
}

impl MockFixer {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            can_fix_predicate: Box::new(|_| true),
            should_fail: false,
        }
    }

    pub fn with_predicate<F>(mut self, predicate: F) -> Self
    where
        F: Fn(&Finding) -> bool + Send + Sync + 'static,
    {
        self.can_fix_predicate = Box::new(predicate);
        self
    }

    pub fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }
}

#[async_trait]
impl Fixer for MockFixer {
    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn description(&self) -> &'static str {
        "Mock fixer for testing"
    }

    fn categories(&self) -> Vec<Category> {
        vec![Category::Custom("test".to_string())]
    }

    fn can_fix(&self, finding: &Finding) -> bool {
        (self.can_fix_predicate)(finding)
    }

    fn is_enabled(&self, _config: &Config) -> bool {
        true
    }

    async fn plan_fix(&self, finding: &Finding, _config: &Config) -> PinGuardResult<FixPlan> {
        if self.should_fail {
            return Err(crate::core::PinGuardError::fixer(
                &self.name,
                "Mock fixer plan failure",
            ));
        }

        Ok(FixPlan {
            fixer_name: self.name.clone(),
            finding_id: finding.id.clone(),
            actions: vec![],
            estimated_duration: Duration::from_secs(1),
            requires_reboot: false,
            backup_required: false,
            risks: vec![],
        })
    }

    async fn fix(&self, finding: &Finding, _config: &Config) -> PinGuardResult<FixResult> {
        if self.should_fail {
            return Err(crate::core::PinGuardError::fixer(
                &self.name,
                "Mock fixer execution failure",
            ));
        }

        Ok(FixResult {
            finding_id: finding.id.clone(),
            fixer_name: self.name.clone(),
            status: FixStatus::Success,
            message: "Mock fix completed".to_string(),
            actions_taken: vec![],
            duration: Duration::from_millis(50),
            backup_created: None,
            requires_reboot: false,
        })
    }
}

/// Mock event handler for testing
pub struct MockEventHandler {
    events: Arc<RwLock<Vec<Event>>>,
}

impl MockEventHandler {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn get_events(&self) -> Vec<Event> {
        self.events.read().await.clone()
    }

    pub async fn clear_events(&self) {
        self.events.write().await.clear();
    }
}

#[async_trait]
impl EventHandler for MockEventHandler {
    async fn handle(&self, event: Event) -> PinGuardResult<()> {
        self.events.write().await.push(event);
        Ok(())
    }
}

impl Default for MockEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Test utilities
pub struct TestUtils;

impl TestUtils {
    /// Create a test configuration
    pub fn create_test_config() -> Config {
        let mut config = Config::default();
        config.app.debug_mode = true;
        config.database.path = ":memory:".to_string();
        config
    }

    /// Create a sample finding for testing
    pub fn create_test_finding(id: &str, severity: Severity, category: Category) -> Finding {
        Finding::new(
            id.to_string(),
            format!("Test finding: {}", id),
            format!("This is a test finding with ID {}", id),
            severity,
            category,
            "test-item".to_string(),
        )
        .with_recommendation("Fix this test finding".to_string())
        .make_fixable()
    }

    /// Create multiple test findings
    pub fn create_test_findings(count: usize) -> Vec<Finding> {
        (0..count)
            .map(|i| {
                Self::create_test_finding(
                    &format!("test-{}", i),
                    if i % 2 == 0 {
                        Severity::High
                    } else {
                        Severity::Low
                    },
                    Category::Custom("test".to_string()),
                )
            })
            .collect()
    }

    /// Create a test service registry
    pub async fn create_test_service_registry() -> PinGuardResult<ServiceRegistry> {
        let config = Self::create_test_config();
        let registry = ServiceRegistry::new(config);

        // Add some test scanners and fixers
        let container = registry.container();
        
        container
            .register_scanner(Box::new(MockScanner::new("test_scanner")))
            .await?;
        
        container
            .register_fixer(Box::new(MockFixer::new("test_fixer")))
            .await?;

        Ok(registry)
    }

    /// Setup test environment
    pub async fn setup_test_env() -> PinGuardResult<ServiceRegistry> {
        // Set test environment variables
        std::env::set_var("PINGUARD_LOG_LEVEL", "debug");
        std::env::set_var("PINGUARD_DB_PATH", ":memory:");

        Self::create_test_service_registry().await
    }

    /// Cleanup test environment
    pub fn cleanup_test_env() {
        std::env::remove_var("PINGUARD_LOG_LEVEL");
        std::env::remove_var("PINGUARD_DB_PATH");
    }

    /// Assert that two findings are equal (ignoring timestamps)
    pub fn assert_findings_equal(actual: &Finding, expected: &Finding) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.title, expected.title);
        assert_eq!(actual.description, expected.description);
        assert_eq!(actual.severity, expected.severity);
        assert_eq!(actual.category, expected.category);
        assert_eq!(actual.affected_item, expected.affected_item);
        assert_eq!(actual.fixable, expected.fixable);
    }

    /// Assert that scan result is valid
    pub fn assert_scan_result_valid(result: &ScanResult) {
        assert!(!result.scanner_name.is_empty());
        assert!(!result.metadata.scanner_version.is_empty());
        assert!(result.metadata.duration.as_millis() > 0);

        // Validate findings
        for finding in &result.findings {
            assert!(!finding.id.is_empty());
            assert!(!finding.title.is_empty());
            assert!(!finding.affected_item.is_empty());
        }
    }

    /// Assert that fix result is valid
    pub fn assert_fix_result_valid(result: &FixResult) {
        assert!(!result.finding_id.is_empty());
        assert!(!result.fixer_name.is_empty());
        assert!(!result.message.is_empty());
        assert!(result.duration.as_millis() > 0);
    }
}

/// Test macros for common assertions
#[macro_export]
macro_rules! assert_scanner_result {
    ($result:expr, $expected_findings:expr) => {
        assert!($result.is_ok());
        let scan_result = $result.unwrap();
        $crate::testing::TestUtils::assert_scan_result_valid(&scan_result);
        assert_eq!(scan_result.findings.len(), $expected_findings);
    };
}

#[macro_export]
macro_rules! assert_fixer_success {
    ($result:expr) => {
        assert!($result.is_ok());
        let fix_result = $result.unwrap();
        $crate::testing::TestUtils::assert_fix_result_valid(&fix_result);
        assert_eq!(fix_result.status, $crate::core::FixStatus::Success);
    };
}

#[macro_export]
macro_rules! assert_error_type {
    ($result:expr, $error_type:pat) => {
        assert!($result.is_err());
        match $result.unwrap_err() {
            $error_type => (),
            other => panic!("Expected error type, got: {:?}", other),
        }
    };
}

/// Integration test helpers
pub struct IntegrationTestHelper {
    pub registry: ServiceRegistry,
    pub event_handler: Arc<MockEventHandler>,
}

impl IntegrationTestHelper {
    pub async fn new() -> PinGuardResult<Self> {
        let registry = TestUtils::setup_test_env().await?;
        let event_handler = Arc::new(MockEventHandler::new());

        Ok(Self {
            registry,
            event_handler,
        })
    }

    pub async fn run_full_scan_cycle(&self) -> PinGuardResult<Vec<ScanResult>> {
        // This would implement a full scan cycle for integration tests
        // For now, return empty results
        Ok(Vec::new())
    }

    pub async fn run_full_fix_cycle(&self, _findings: Vec<Finding>) -> PinGuardResult<Vec<FixResult>> {
        // This would implement a full fix cycle for integration tests
        // For now, return empty results
        Ok(Vec::new())
    }
}

impl Drop for IntegrationTestHelper {
    fn drop(&mut self) {
        TestUtils::cleanup_test_env();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_scanner() {
        let findings = TestUtils::create_test_findings(2);
        let scanner = MockScanner::new("test").with_findings(findings.clone());
        let config = TestUtils::create_test_config();

        let result = scanner.scan(&config).await;
        assert_scanner_result!(result, 2);
    }

    #[tokio::test]
    async fn test_mock_fixer() {
        let finding = TestUtils::create_test_finding("test", Severity::High, Category::Package);
        let fixer = MockFixer::new("test");
        let config = TestUtils::create_test_config();

        assert!(fixer.can_fix(&finding));

        let plan_result = fixer.plan_fix(&finding, &config).await;
        assert!(plan_result.is_ok());

        let fix_result = fixer.fix(&finding, &config).await;
        assert_fixer_success!(fix_result);
    }

    #[tokio::test]
    async fn test_event_handler() {
        let handler = MockEventHandler::new();
        let event = Event::ConfigReloaded;

        let result = handler.handle(event.clone()).await;
        assert!(result.is_ok());

        let events = handler.get_events().await;
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_integration_helper() {
        let helper = IntegrationTestHelper::new().await;
        assert!(helper.is_ok());
    }
}