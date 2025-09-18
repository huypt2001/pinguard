use crate::scanners::Finding;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;

pub mod firewall_configurator;
pub mod kernel_updater;
pub mod manager;
pub mod package_updater;
pub mod permission_fixer;
pub mod service_hardener;
pub mod user_policy_fixer;

/// Fixer trait - every fixer module implements this trait
pub trait Fixer {
    /// Name of the fixer
    fn name(&self) -> &'static str;

    /// Check if this fixer can fix this finding
    fn can_fix(&self, finding: &Finding) -> bool;

    /// Fix the finding - requires user confirmation
    fn fix(
        &self,
        finding: &Finding,
        config: &crate::core::config::Config,
    ) -> Result<FixResult, FixError>;

    /// Dry run - show what would be done but don't execute
    fn dry_run(&self, finding: &Finding) -> Result<FixPlan, FixError>;

    /// Is this fixer enabled?
    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .fixer
            .enabled_modules
            .contains(&self.name().to_string())
    }
}

/// Result of the fix operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixResult {
    pub finding_id: String,
    pub fixer_name: String,
    pub status: FixStatus,
    pub message: String,
    pub commands_executed: Vec<String>,
    pub files_modified: Vec<String>,
    pub backup_created: Option<String>,
    pub reboot_required: bool,
    pub duration: u64, // milliseconds
    pub timestamp: String,
}

/// Fix status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FixStatus {
    Success,
    Failed,
    RequiresUserAction,
    RequiresReboot,
    Skipped,
    Cancelled,
}

/// Fix plan - result of dry run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixPlan {
    pub finding_id: String,
    pub fixer_name: String,
    pub description: String,
    pub commands_to_execute: Vec<String>,
    pub files_to_modify: Vec<String>,
    pub backup_required: bool,
    pub reboot_required: bool,
    pub risk_level: RiskLevel,
    pub estimated_duration: Duration,
}

/// Risk level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,      // Safe changes
    Medium,   // Changes requiring careful approach
    High,     // Changes that might affect system stability
    Critical, // Changes that might crash the system
}

/// Fix errors
#[derive(Debug, Serialize, Deserialize, Clone, Error)]
pub enum FixError {
    #[error("Command error: {0}")]
    CommandError(String),
    #[error("File error: {0}")]
    FileError(String),
    #[error("Config error: {0}")]
    ConfigError(String),
    #[error("Permission error: {0}")]
    PermissionError(String),
    #[error("Unsupported fix: {0}")]
    UnsupportedFix(String),
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Dependency error: {0}")]
    DependencyError(String),
    #[error("Backup error: {0}")]
    BackupError(String),
}

impl FixResult {
    pub fn new(finding_id: String, fixer_name: String) -> Self {
        Self {
            finding_id,
            fixer_name,
            status: FixStatus::Skipped,
            message: String::new(),
            commands_executed: Vec::new(),
            files_modified: Vec::new(),
            backup_created: None,
            reboot_required: false,
            duration: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn success(mut self, message: String) -> Self {
        self.status = FixStatus::Success;
        self.message = message;
        self
    }

    pub fn failed(mut self, message: String) -> Self {
        self.status = FixStatus::Failed;
        self.message = message;
        self
    }

    pub fn requires_reboot(mut self) -> Self {
        self.status = FixStatus::RequiresReboot;
        self.reboot_required = true;
        self
    }

    pub fn add_command(mut self, command: String) -> Self {
        self.commands_executed.push(command);
        self
    }

    pub fn add_file(mut self, file: String) -> Self {
        self.files_modified.push(file);
        self
    }

    pub fn set_backup(mut self, backup_path: String) -> Self {
        self.backup_created = Some(backup_path);
        self
    }

    pub fn set_duration(mut self, start_time: Instant) -> Self {
        self.duration = start_time.elapsed().as_millis() as u64;
        self
    }

    pub fn with_status(mut self, status: FixStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_message(mut self, message: String) -> Self {
        self.message = message;
        self
    }
}

impl FixPlan {
    pub fn new(finding_id: String, fixer_name: String, description: String) -> Self {
        Self {
            finding_id,
            fixer_name,
            description,
            commands_to_execute: Vec::new(),
            files_to_modify: Vec::new(),
            backup_required: false,
            reboot_required: false,
            risk_level: RiskLevel::Low,
            estimated_duration: Duration::from_secs(10),
        }
    }

    pub fn add_command(mut self, command: String) -> Self {
        self.commands_to_execute.push(command);
        self
    }

    pub fn add_file(mut self, file: String) -> Self {
        self.files_to_modify.push(file);
        self
    }

    pub fn requires_backup(mut self) -> Self {
        self.backup_required = true;
        self
    }

    pub fn requires_reboot(mut self) -> Self {
        self.reboot_required = true;
        self
    }

    pub fn set_risk(mut self, risk: RiskLevel) -> Self {
        self.risk_level = risk;
        self
    }

    pub fn set_duration(mut self, duration: Duration) -> Self {
        self.estimated_duration = duration;
        self
    }
}

/// Helper function for user confirmation
pub fn ask_user_confirmation(plan: &FixPlan) -> Result<bool, FixError> {
    use std::io::{self, Write};

    println!("Fix Plan: {}", plan.description);
    println!("Fixer: {}", plan.fixer_name);
    println!("Risk Level: {:?}", plan.risk_level);

    if !plan.commands_to_execute.is_empty() {
        println!("💻 Commands to execute:");
        for cmd in &plan.commands_to_execute {
            println!("   $ {}", cmd);
        }
    }

    if !plan.files_to_modify.is_empty() {
        println!("Files to modify:");
        for file in &plan.files_to_modify {
            println!("   - {}", file);
        }
    }

    if plan.backup_required {
        println!("Backup will be created");
    }

    if plan.reboot_required {
        println!("System reboot will be required");
    }

    println!("Estimated duration: {:?}", plan.estimated_duration);

    print!("\nDo you want to proceed? [y/N]: ");
    io::stdout()
        .flush()
        .map_err(|e| FixError::ConfigError(e.to_string()))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| FixError::ConfigError(e.to_string()))?;

    let response = input.trim().to_lowercase();
    Ok(response == "y" || response == "yes")
}

/// Helper function to create backup
pub fn create_backup(file_path: &str) -> Result<String, FixError> {
    use std::fs;
    use std::path::Path;

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let backup_path = format!("{}.backup_{}", file_path, timestamp);

    if Path::new(file_path).exists() {
        fs::copy(file_path, &backup_path)
            .map_err(|e| FixError::BackupError(format!("Failed to backup {}: {}", file_path, e)))?;

        tracing::info!("Backup created: {}", backup_path);
        Ok(backup_path)
    } else {
        Err(FixError::BackupError(format!(
            "Source file does not exist: {}",
            file_path
        )))
    }
}

/// Helper function to execute command
pub fn execute_command(command: &str, args: &[&str]) -> Result<String, FixError> {
    use std::process::Command;

    tracing::info!("Executing: {} {}", command, args.join(" "));

    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|e| FixError::CommandError(format!("Failed to execute {}: {}", command, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FixError::CommandError(format!(
            "Command failed: {}",
            stderr
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
