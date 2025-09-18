pub mod schedule_manager;
pub mod systemd_integration;
pub mod scheduler_types;

pub use schedule_manager::ScheduleManager;
pub use systemd_integration::SystemdIntegration;
pub use scheduler_types::*;

use crate::database::DatabaseManager;
use crate::scanners::manager::ScannerManager;
use crate::core::config::Config;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn, error, debug};

/// Scheduler error types
#[derive(Error, Debug)]
pub enum SchedulerError {
    #[error("Systemd error: {0}")]
    SystemdError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Scan error: {0}")]
    ScanError(String),
    #[error("Invalid schedule configuration: {0}")]
    InvalidConfig(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Schedule not found: {0}")]
    ScheduleNotFound(String),
    #[error("Schedule already exists: {0}")]
    ScheduleExists(String),
}

pub type SchedulerResult<T> = Result<T, SchedulerError>;

/// Main scheduler manager
pub struct Scheduler {
    db: DatabaseManager,
    pub schedule_manager: ScheduleManager,
    systemd: SystemdIntegration,
    config_path: String,
}

impl Scheduler {
    /// Create new scheduler
    pub fn new(db: DatabaseManager) -> SchedulerResult<Self> {
        let config_path = Self::get_config_path()?;
        let schedule_manager = ScheduleManager::new(&config_path)?;
        let systemd = SystemdIntegration::new()?;

        Ok(Self {
            db,
            schedule_manager,
            systemd,
            config_path,
        })
    }

    /// Start scheduler
    pub fn enable(&mut self, schedule_config: ScheduleConfig) -> SchedulerResult<()> {
        info!("Enabling scheduler: {}", schedule_config.name);

        // Check existing schedule
        if self.schedule_manager.exists(&schedule_config.name)? {
            return Err(SchedulerError::ScheduleExists(schedule_config.name));
        }

        // Save schedule
        self.schedule_manager.save_schedule(&schedule_config)?;

        // Create systemd timer and service files
        self.systemd.create_timer(&schedule_config)?;
        self.systemd.create_service(&schedule_config)?;

        // Enable systemd timer
        self.systemd.enable_timer(&schedule_config.name)?;

        info!("Scheduler successfully enabled: {}", schedule_config.name);
        Ok(())
    }

    /// Stop scheduler
    pub fn disable(&mut self, schedule_name: &str) -> SchedulerResult<()> {
        info!("Disabling scheduler: {}", schedule_name);

        // Check if schedule exists
        if !self.schedule_manager.exists(schedule_name)? {
            return Err(SchedulerError::ScheduleNotFound(schedule_name.to_string()));
        }

        // Stop and disable systemd timer
        self.systemd.disable_timer(schedule_name)?;

        // Remove schedule files
        self.systemd.remove_timer(schedule_name)?;
        self.systemd.remove_service(schedule_name)?;

        // Delete schedule config
        self.schedule_manager.remove_schedule(schedule_name)?;

        info!("Scheduler successfully disabled: {}", schedule_name);
        Ok(())
    }

    /// List active schedules
    pub fn list_schedules(&self) -> SchedulerResult<Vec<ScheduleConfig>> {
        debug!("Listing active schedules");
        self.schedule_manager.list_schedules()
    }

    /// Check schedule status
    pub fn get_schedule_status(&self, schedule_name: &str) -> SchedulerResult<ScheduleStatus> {
        debug!("Checking schedule status: {}", schedule_name);
        
        let config = self.schedule_manager.get_schedule(schedule_name)?;
        let systemd_status = self.systemd.get_timer_status(schedule_name)?;
        let last_run = self.get_last_run_info(schedule_name)?;

        Ok(ScheduleStatus {
            name: schedule_name.to_string(),
            enabled: systemd_status.enabled,
            active: systemd_status.active,
            last_run,
            next_run: systemd_status.next_run,
            config,
        })
    }

    /// Get status of all schedules
    pub fn get_all_statuses(&self) -> SchedulerResult<Vec<ScheduleStatus>> {
        let schedules = self.list_schedules()?;
        let mut statuses = Vec::new();

        for schedule in schedules {
            match self.get_schedule_status(&schedule.name) {
                Ok(status) => statuses.push(status),
                Err(e) => {
                    warn!("Could not get schedule status {}: {}", schedule.name, e);
                }
            }
        }

        Ok(statuses)
    }

    /// Run scheduled scan (called by systemd)
    pub async fn run_scheduled_scan(&self, schedule_name: &str) -> SchedulerResult<()> {
        info!("Starting scheduled scan: {}", schedule_name);

        let config = self.schedule_manager.get_schedule(schedule_name)?;
        
        // Execute scan and save results
        match self.execute_scan(&config).await {
            Ok(scan_result) => {
                info!("Scheduled scan completed: {} - {} finding", 
                    schedule_name, scan_result.total_findings);
            }
            Err(e) => {
                error!("Scheduled scan failed: {} - {}", schedule_name, e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Get config file path
    fn get_config_path() -> SchedulerResult<String> {
        let home = std::env::var("HOME")
            .map_err(|_| SchedulerError::InvalidConfig("HOME environment variable not set".to_string()))?;
        
        let config_dir = format!("{}/.config/pinGuard/schedules", home);
        std::fs::create_dir_all(&config_dir)?;
        
        Ok(config_dir)
    }

    /// Get last run information
    fn get_last_run_info(&self, _schedule_name: &str) -> SchedulerResult<Option<LastRunInfo>> {
        // Get last run information from database
        // This implementation will depend on database module
        Ok(None) // Placeholder
    }

    /// Execute scan
    async fn execute_scan(&self, config: &ScheduleConfig) -> SchedulerResult<ScheduledScanResult> {
        use std::time::Instant;
        use uuid::Uuid;
        use chrono::Utc;
        
        let start_time = Instant::now();
        let scan_id = Uuid::new_v4().to_string();
        
        info!("Starting scheduled scan: {} (ID: {})", config.name, scan_id);

        // Start schedule log
        self.log_scan_start(&config.name, &scan_id).await?;

        // Create default config
        let default_config = Config::default();
        
        // Create scanner manager
        let scanner_manager = ScannerManager::new();
        
        // Perform scan based on scan type
        let scan_results = match &config.scan_type {
            ScanType::Full => {
                info!("Running full scan");
                scanner_manager.run_all_scans(&default_config)
            }
            ScanType::Quick => {
                info!("⚡ Running quick scan");
                match scanner_manager.run_specific_scan("package", &default_config) {
                    Ok(result) => vec![result],
                    Err(e) => {
                        error!("Quick scan failed: {}", e);
                        return Err(SchedulerError::ScanError(format!("Quick scan failed: {}", e)));
                    }
                }
            }
            ScanType::Security => {
                info!("Running security scan");
                let mut results = Vec::new();
                for scanner_type in &["permission", "service", "user"] {
                    match scanner_manager.run_specific_scan(scanner_type, &default_config) {
                        Ok(result) => results.push(result),
                        Err(e) => warn!("Scanner {} failed: {}", scanner_type, e),
                    }
                }
                results
            }
            ScanType::Custom { modules } => {
                info!("Running custom scan: {:?}", modules);
                let mut results = Vec::new();
                for module in modules {
                    match scanner_manager.run_specific_scan(module, &default_config) {
                        Ok(result) => results.push(result),
                        Err(e) => warn!("Scanner {} failed: {}", module, e),
                    }
                }
                results
            }
        };

        let duration = start_time.elapsed();
        let duration_ms = duration.as_millis() as u64;

        let total_findings: u32 = scan_results.iter()
            .map(|result| result.findings.len() as u32)
            .sum();

        let scheduled_result = ScheduledScanResult {
            schedule_name: config.name.clone(),
            total_findings,
            duration_ms,
            success: true,
        };

        // Log successful scan
        self.log_scan_complete(&config.name, &scan_id, &scheduled_result, None).await?;

        info!("Scheduled scan completed: {} findings, {}ms", 
            total_findings, duration_ms);

        Ok(scheduled_result)
    }

    /// Log scan start
    async fn log_scan_start(&self, schedule_name: &str, scan_id: &str) -> SchedulerResult<()> {
        // Add start record to schedule logs table
        let now = chrono::Utc::now();
        
        let result = self.db.execute_prepared(
            "INSERT INTO schedule_logs (schedule_name, scan_id, started_at, success) VALUES (?1, ?2, ?3, FALSE)",
            &[schedule_name, scan_id, &now.format("%Y-%m-%d %H:%M:%S%.3f").to_string()]
        );

        match result {
            Ok(_) => {
                debug!("Scan start logged: {} -> {}", schedule_name, scan_id);
                Ok(())
            }
            Err(e) => {
                warn!("Could not write scan start log: {}", e);
                Ok(()) // Log error should not stop scan
            }
        }
    }

    /// Log scan completion
    async fn log_scan_complete(
        &self, 
        schedule_name: &str, 
        scan_id: &str, 
        result: &ScheduledScanResult,
        error_message: Option<&str>
    ) -> SchedulerResult<()> {
        let now = chrono::Utc::now();
        
        let db_result = self.db.execute_prepared(
            "UPDATE schedule_logs SET completed_at = ?1, success = ?2, total_findings = ?3, scan_duration_ms = ?4, error_message = ?5 WHERE scan_id = ?6",
            &[
                &now.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                &result.success.to_string(),
                &result.total_findings.to_string(),
                &result.duration_ms.to_string(),
                &error_message.map(|s| s.to_string()).unwrap_or_default(),
                scan_id,
            ]
        );

        match db_result {
            Ok(_) => {
                debug!("Scan completion logged: {} -> {}", schedule_name, scan_id);
                Ok(())
            }
            Err(e) => {
                warn!("Could not write scan completion log: {}", e);
                Ok(()) // Log error should not stop scan
            }
        }
    }
}

/// Scheduled scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScanResult {
    pub schedule_name: String,
    pub total_findings: u32,
    pub duration_ms: u64,
    pub success: bool,
}