//! Service locator and dependency injection system for PinGuard
//!
//! This module provides a centralized dependency injection container
//! that manages the lifecycle and dependencies of all services.

use crate::core::{
    enhanced_config::Config, errors::PinGuardResult, traits::*, ConfigProvider, PinGuardError,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Main service container that manages all dependencies
#[allow(dead_code)]
pub struct ServiceContainer {
    scanners: Arc<RwLock<HashMap<String, Box<dyn Scanner>>>>,
    fixers: Arc<RwLock<HashMap<String, Box<dyn Fixer>>>>,
    config: Arc<dyn ConfigProvider + Send + Sync>,
    event_bus: Arc<RwLock<Option<Box<dyn EventBus>>>>,
}

#[allow(dead_code)]
impl ServiceContainer {
    /// Create a new service container with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            scanners: Arc::new(RwLock::new(HashMap::new())),
            fixers: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(config),
            event_bus: Arc::new(RwLock::new(None)),
        }
    }

    /// Register a scanner in the container
    pub async fn register_scanner(&self, scanner: Box<dyn Scanner>) -> PinGuardResult<()> {
        let name = scanner.name().to_string();
        let mut scanners = self.scanners.write().await;
        
        if scanners.contains_key(&name) {
            return Err(PinGuardError::AlreadyExists {
                message: format!("Scanner '{}' is already registered", name),
                source: None,
            });
        }
        
        scanners.insert(name.clone(), scanner);
        tracing::info!("Registered scanner: {}", name);
        Ok(())
    }

    /// Register a fixer in the container
    pub async fn register_fixer(&self, fixer: Box<dyn Fixer>) -> PinGuardResult<()> {
        let name = fixer.name().to_string();
        let mut fixers = self.fixers.write().await;
        
        if fixers.contains_key(&name) {
            return Err(PinGuardError::AlreadyExists {
                message: format!("Fixer '{}' is already registered", name),
                source: None,
            });
        }
        
        fixers.insert(name.clone(), fixer);
        tracing::info!("Registered fixer: {}", name);
        Ok(())
    }

    /// Set the event bus
    pub async fn set_event_bus(&self, event_bus: Box<dyn EventBus>) {
        let mut bus = self.event_bus.write().await;
        *bus = Some(event_bus);
        tracing::info!("Event bus registered");
    }

    /// Get a scanner by name
    pub async fn get_scanner(&self, _name: &str) -> Option<Box<dyn Scanner>> {
        let _scanners = self.scanners.read().await;
        // We can't clone the scanner directly, so we'll need a different approach
        // For now, return None - in a real implementation, we'd use Arc<dyn Scanner>
        None
    }

    /// Get all enabled scanners
    pub async fn get_enabled_scanners(&self) -> Vec<String> {
        let scanners = self.scanners.read().await;
        let config = self.config.as_ref();
        
        scanners
            .keys()
            .filter(|name| {
                if let Some(enabled_modules) = config.get_string_array("scanner.enabled_modules") {
                    enabled_modules.contains(name)
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    /// Get a fixer by name
    pub async fn get_fixer(&self, _name: &str) -> Option<Box<dyn Fixer>> {
        let _fixers = self.fixers.read().await;
        // Similar issue as with scanners
        None
    }

    /// Get all enabled fixers
    pub async fn get_enabled_fixers(&self) -> Vec<String> {
        let fixers = self.fixers.read().await;
        let config = self.config.as_ref();
        
        fixers
            .keys()
            .filter(|name| {
                if let Some(enabled_modules) = config.get_string_array("fixer.enabled_modules") {
                    enabled_modules.contains(name)
                } else {
                    false // Fixers are opt-in by default
                }
            })
            .cloned()
            .collect()
    }

    /// Get the configuration
    pub fn config(&self) -> Arc<dyn ConfigProvider + Send + Sync> {
        self.config.clone()
    }

    /// Publish an event
    pub async fn publish_event(&self, event: Event) -> PinGuardResult<()> {
        let event_bus = self.event_bus.read().await;
        if let Some(bus) = event_bus.as_ref() {
            bus.publish(event).await
        } else {
            // If no event bus is registered, just log the event
            tracing::debug!("Event published (no bus registered): {:?}", event);
            Ok(())
        }
    }

    /// Initialize all services and validate dependencies
    pub async fn initialize(&self) -> PinGuardResult<()> {
        tracing::info!("Initializing service container...");

        // Validate all scanners
        let scanners = self.scanners.read().await;
        for (name, scanner) in scanners.iter() {
            if let Err(e) = scanner.validate().await {
                tracing::warn!("Scanner '{}' validation failed: {}", name, e);
            } else {
                tracing::debug!("Scanner '{}' validated successfully", name);
            }
        }

        // Validate all fixers
        let fixers = self.fixers.read().await;
        for (name, fixer) in fixers.iter() {
            if let Err(e) = fixer.validate().await {
                tracing::warn!("Fixer '{}' validation failed: {}", name, e);
            } else {
                tracing::debug!("Fixer '{}' validated successfully", name);
            }
        }

        tracing::info!("Service container initialized successfully");
        Ok(())
    }

    /// Shutdown the service container
    pub async fn shutdown(&self) -> PinGuardResult<()> {
        tracing::info!("Shutting down service container...");
        
        // Clear all services
        {
            let mut scanners = self.scanners.write().await;
            scanners.clear();
        }
        
        {
            let mut fixers = self.fixers.write().await;
            fixers.clear();
        }
        
        {
            let mut event_bus = self.event_bus.write().await;
            *event_bus = None;
        }
        
        tracing::info!("Service container shut down");
        Ok(())
    }
}

/// Service registry that provides a global access point to services
#[allow(dead_code)]
pub struct ServiceRegistry {
    container: Arc<ServiceContainer>,
}

#[allow(dead_code)]
impl ServiceRegistry {
    /// Create a new service registry
    pub fn new(config: Config) -> Self {
        Self {
            container: Arc::new(ServiceContainer::new(config)),
        }
    }

    /// Get the service container
    pub fn container(&self) -> Arc<ServiceContainer> {
        self.container.clone()
    }

    /// Initialize the registry with default services
    pub async fn initialize_default_services(&self) -> PinGuardResult<()> {
        // Register default scanners
        self.register_default_scanners().await?;
        
        // Register default fixers
        self.register_default_fixers().await?;
        
        // Initialize the container
        self.container.initialize().await?;
        
        Ok(())
    }

    async fn register_default_scanners(&self) -> PinGuardResult<()> {
        // This would register all the default scanner implementations
        // For now, we'll add placeholders
        
        tracing::info!("Registering default scanners...");
        
        // TODO: Add actual scanner implementations
        // self.container.register_scanner(Box::new(PackageAuditScanner::new())).await?;
        // self.container.register_scanner(Box::new(KernelCheckScanner::new())).await?;
        // etc.
        
        Ok(())
    }

    async fn register_default_fixers(&self) -> PinGuardResult<()> {
        tracing::info!("Registering default fixers...");
        
        // TODO: Add actual fixer implementations
        // self.container.register_fixer(Box::new(PackageUpdater::new())).await?;
        // self.container.register_fixer(Box::new(KernelUpdater::new())).await?;
        // etc.
        
        Ok(())
    }
}

/// Builder pattern for constructing service registry
#[allow(dead_code)]
pub struct ServiceRegistryBuilder {
    config: Option<Config>,
    custom_scanners: Vec<Box<dyn Scanner>>,
    custom_fixers: Vec<Box<dyn Fixer>>,
    event_bus: Option<Box<dyn EventBus>>,
}

#[allow(dead_code)]
impl ServiceRegistryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: None,
            custom_scanners: Vec::new(),
            custom_fixers: Vec::new(),
            event_bus: None,
        }
    }

    /// Set the configuration
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Add a custom scanner
    pub fn with_scanner(mut self, scanner: Box<dyn Scanner>) -> Self {
        self.custom_scanners.push(scanner);
        self
    }

    /// Add a custom fixer
    pub fn with_fixer(mut self, fixer: Box<dyn Fixer>) -> Self {
        self.custom_fixers.push(fixer);
        self
    }

    /// Set the event bus
    pub fn with_event_bus(mut self, event_bus: Box<dyn EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Build the service registry
    pub async fn build(self) -> PinGuardResult<ServiceRegistry> {
        let config = self.config.unwrap_or_default();
        let registry = ServiceRegistry::new(config);

        // Register custom scanners
        for scanner in self.custom_scanners {
            registry.container.register_scanner(scanner).await?;
        }

        // Register custom fixers
        for fixer in self.custom_fixers {
            registry.container.register_fixer(fixer).await?;
        }

        // Set event bus if provided
        if let Some(event_bus) = self.event_bus {
            registry.container.set_event_bus(event_bus).await;
        }

        // Initialize default services
        registry.initialize_default_services().await?;

        Ok(registry)
    }
}

impl Default for ServiceRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple in-memory event bus implementation
#[allow(dead_code)]
pub struct InMemoryEventBus {
    handlers: Arc<RwLock<Vec<Box<dyn EventHandler>>>>,
}

#[allow(dead_code)]
impl InMemoryEventBus {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait]
impl EventBus for InMemoryEventBus {
    async fn publish(&self, event: Event) -> PinGuardResult<()> {
        let handlers = self.handlers.read().await;
        
        for handler in handlers.iter() {
            if let Err(e) = handler.handle(event.clone()).await {
                tracing::warn!("Event handler failed: {}", e);
            }
        }
        
        Ok(())
    }

    fn subscribe(&mut self, _handler: Box<dyn EventHandler>) {
        // This is problematic with the async nature
        // In a real implementation, we'd need a different approach
        tracing::warn!("Subscribe called on InMemoryEventBus - not implemented correctly");
    }
}

impl Default for InMemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Logging event handler that logs all events
#[allow(dead_code)]
pub struct LoggingEventHandler;

#[async_trait]
impl EventHandler for LoggingEventHandler {
    async fn handle(&self, event: Event) -> PinGuardResult<()> {
        match &event {
            Event::ScanStarted { scanner } => {
                tracing::info!("Scan started: {}", scanner);
            }
            Event::ScanCompleted { scanner, result } => {
                tracing::info!(
                    "Scan completed: {} with {} findings",
                    scanner,
                    result.findings.len()
                );
            }
            Event::FixStarted { fixer, finding_id } => {
                tracing::info!("Fix started: {} for finding {}", fixer, finding_id);
            }
            Event::FixCompleted { fixer, result } => {
                tracing::info!("Fix completed: {} with status {:?}", fixer, result.status);
            }
            Event::ConfigReloaded => {
                tracing::info!("Configuration reloaded");
            }
            Event::DatabaseUpdated => {
                tracing::info!("Database updated");
            }
            Event::CveDataUpdated => {
                tracing::info!("CVE data updated");
            }
            Event::Error { component, error } => {
                tracing::error!("Error in {}: {}", component, error);
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_container_creation() {
        let config = Config::default();
        let container = ServiceContainer::new(config);
        
        // Test that container initializes
        assert!(container.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_service_registry_builder() {
        let registry = ServiceRegistryBuilder::new()
            .with_config(Config::default())
            .build()
            .await;
            
        assert!(registry.is_ok());
    }

    #[tokio::test]
    async fn test_event_bus() {
        let event_bus = InMemoryEventBus::new();
        let event = Event::ConfigReloaded;
        
        assert!(event_bus.publish(event).await.is_ok());
    }
}