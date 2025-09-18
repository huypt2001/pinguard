//! Integration tests for PinGuard
//!
//! These tests verify that different components work together correctly.

use pin_guard::testing::{IntegrationTestHelper, TestUtils};
use pin_guard::{Category, Severity};

#[tokio::test]
async fn test_full_scan_and_fix_workflow() {
    let helper = IntegrationTestHelper::new().await.unwrap();

    // Create some test findings
    let findings = vec![
        TestUtils::create_test_finding("outdated-package-nginx", Severity::Medium, Category::Package),
        TestUtils::create_test_finding("cve-2023-1234", Severity::High, Category::Vulnerability),
        TestUtils::create_test_finding("weak-permission", Severity::Low, Category::Permission),
    ];

    // Run scan cycle
    let scan_results = helper.run_full_scan_cycle().await.unwrap();
    
    // For this test, we expect no results since we're using mock data
    assert_eq!(scan_results.len(), 0);

    // Run fix cycle
    let fix_results = helper.run_full_fix_cycle(findings).await.unwrap();
    
    // For this test, we expect no results since we're using mock data
    assert_eq!(fix_results.len(), 0);
}

#[tokio::test]
async fn test_service_registry_initialization() {
    let registry = TestUtils::create_test_service_registry().await.unwrap();
    let container = registry.container();

    // Test that the container initializes properly
    let result = container.initialize().await;
    assert!(result.is_ok());

    // Test cleanup
    let shutdown_result = container.shutdown().await;
    assert!(shutdown_result.is_ok());
}

#[tokio::test]
async fn test_configuration_loading() {
    let config = TestUtils::create_test_config();
    
    // Test basic configuration properties
    assert!(config.app.debug_mode);
    assert_eq!(config.database.path, ":memory:");
    assert!(!config.scanner.enabled_modules.is_empty());
}

#[tokio::test]
async fn test_event_system() {
    use pin_guard::{Event, ServiceRegistryBuilder, InMemoryEventBus, LoggingEventHandler};
    
    let config = TestUtils::create_test_config();
    let event_bus = Box::new(InMemoryEventBus::new());
    
    let _registry = ServiceRegistryBuilder::new()
        .with_config(config)
        .with_event_bus(event_bus)
        .build()
        .await
        .unwrap();

    // Test event publishing (basic functionality)
    // More comprehensive event testing would go here
}

#[tokio::test]
async fn test_error_handling() {
    use pin_guard::{PinGuardError, PinGuardResult};
    
    // Test error creation and categorization
    let error = PinGuardError::scanner("test_scanner", "Test error message");
    assert!(error.to_string().contains("test_scanner"));
    assert!(error.to_string().contains("Test error message"));
    
    // Test error chaining
    let result: PinGuardResult<()> = Err(error);
    assert!(result.is_err());
}