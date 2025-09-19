use crate::backup::{BackupResult, BackupError, SystemSnapshot, FileChange, ChangeType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use chrono::{DateTime, Utc};

/// Rollback manager for restoring system states
#[derive(Debug)]
pub struct RollbackManager {
    backup_dir: PathBuf,
    dry_run: bool,
    verify_before_rollback: bool,
    create_safety_snapshot: bool,
}

/// Rollback operation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackOperation {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub source_snapshot_id: String,
    pub target_snapshot_id: String,
    pub operation_type: RollbackType,
    pub status: RollbackStatus,
    pub changes_applied: Vec<FileChange>,
    pub changes_failed: Vec<FailedChange>,
    pub safety_snapshot_id: Option<String>,
    pub rollback_time_seconds: f64,
    pub verification_results: Option<VerificationResults>,
}

/// Types of rollback operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RollbackType {
    Full,           // Complete system rollback
    Partial,        // Rollback specific files/services
    FileOnly,       // Rollback only file changes
    ServiceOnly,    // Rollback only service states
    ConfigOnly,     // Rollback only configuration files
    Emergency,      // Emergency rollback with minimal checks
}

/// Rollback operation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RollbackStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    PartiallyCompleted,
    Aborted,
}

/// Failed change information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedChange {
    pub file_change: FileChange,
    pub error_message: String,
    pub error_code: Option<i32>,
    pub retry_count: u32,
}

/// Verification results after rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResults {
    pub files_verified: u32,
    pub files_failed: u32,
    pub services_verified: u32,
    pub services_failed: u32,
    pub integrity_check_passed: bool,
    pub verification_time_seconds: f64,
    pub failed_verifications: Vec<String>,
}

/// Rollback configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackConfig {
    pub max_rollback_time_seconds: u32,
    pub verify_before_rollback: bool,
    pub create_safety_snapshot: bool,
    pub backup_failed_files: bool,
    pub stop_services_before_rollback: bool,
    pub restart_services_after_rollback: bool,
    pub allowed_failure_percentage: f64,
    pub retry_failed_changes: bool,
    pub max_retries: u32,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            max_rollback_time_seconds: 300, // 5 minutes
            verify_before_rollback: true,
            create_safety_snapshot: true,
            backup_failed_files: true,
            stop_services_before_rollback: true,
            restart_services_after_rollback: true,
            allowed_failure_percentage: 5.0, // 5%
            retry_failed_changes: true,
            max_retries: 3,
        }
    }
}

impl RollbackManager {
    /// Create a new rollback manager
    pub fn new(backup_dir: PathBuf) -> Self {
        Self {
            backup_dir,
            dry_run: false,
            verify_before_rollback: true,
            create_safety_snapshot: true,
        }
    }
    
    /// Set dry run mode
    pub fn set_dry_run(&mut self, dry_run: bool) -> &mut Self {
        self.dry_run = dry_run;
        self
    }
    
    /// Set verification before rollback
    pub fn set_verify_before_rollback(&mut self, verify: bool) -> &mut Self {
        self.verify_before_rollback = verify;
        self
    }
    
    /// Set safety snapshot creation
    pub fn set_create_safety_snapshot(&mut self, create: bool) -> &mut Self {
        self.create_safety_snapshot = create;
        self
    }
    
    /// Perform a full system rollback to a previous snapshot
    pub fn rollback_to_snapshot(
        &self,
        target_snapshot_id: &str,
        config: &RollbackConfig,
    ) -> BackupResult<RollbackOperation> {
        let start_time = std::time::Instant::now();
        let operation_id = format!("rollback_{}", Utc::now().timestamp());
        
        println!("Starting rollback to snapshot: {}", target_snapshot_id);
        
        // Load target snapshot
        let target_snapshot = self.load_snapshot(target_snapshot_id)?;
        
        // Create safety snapshot if requested
        let safety_snapshot_id = if self.create_safety_snapshot && config.create_safety_snapshot {
            Some(self.create_safety_snapshot(&operation_id)?)
        } else {
            None
        };
        
        // Create current snapshot for comparison
        let current_snapshot = SystemSnapshot::create(
            crate::backup::snapshot::SnapshotType::PreChange,
            format!("Pre-rollback snapshot for operation {}", operation_id),
            &target_snapshot.metadata.files_included,
        )?;
        
        // Compare snapshots to find changes needed
        let changes_needed = current_snapshot.compare_with(&target_snapshot);
        
        println!("Found {} changes to apply during rollback", changes_needed.len());
        
        if self.dry_run {
            return self.simulate_rollback(operation_id, target_snapshot_id, changes_needed);
        }
        
        // Verify system state before rollback if requested
        if config.verify_before_rollback && self.verify_before_rollback {
            self.verify_system_state(&current_snapshot)?;
        }
        
        // Stop services if requested
        let stopped_services = if config.stop_services_before_rollback {
            self.stop_critical_services(&target_snapshot)?
        } else {
            Vec::new()
        };
        
        let mut operation = RollbackOperation {
            id: operation_id,
            created_at: Utc::now(),
            source_snapshot_id: current_snapshot.metadata.id.clone(),
            target_snapshot_id: target_snapshot_id.to_string(),
            operation_type: RollbackType::Full,
            status: RollbackStatus::InProgress,
            changes_applied: Vec::new(),
            changes_failed: Vec::new(),
            safety_snapshot_id,
            rollback_time_seconds: 0.0,
            verification_results: None,
        };
        
        // Apply changes
        let (applied_changes, failed_changes) = self.apply_changes(
            &changes_needed,
            &target_snapshot,
            config,
        )?;
        
        operation.changes_applied = applied_changes;
        operation.changes_failed = failed_changes;
        
        // Calculate failure percentage
        let total_changes = operation.changes_applied.len() + operation.changes_failed.len();
        let failure_percentage = if total_changes > 0 {
            (operation.changes_failed.len() as f64 / total_changes as f64) * 100.0
        } else {
            0.0
        };
        
        // Check if rollback is within acceptable failure rate
        if failure_percentage > config.allowed_failure_percentage {
            operation.status = RollbackStatus::Failed;
            println!("Rollback failed: failure rate {:.1}% exceeds threshold {:.1}%", 
                failure_percentage, config.allowed_failure_percentage);
            
            // Attempt to restore from safety snapshot if available
            if let Some(safety_id) = &operation.safety_snapshot_id {
                println!("Attempting to restore from safety snapshot: {}", safety_id);
                return self.emergency_restore(safety_id);
            }
            
            return Err(BackupError::RollbackError(
                format!("Rollback failed with {:.1}% failure rate", failure_percentage)
            ));
        }
        
        // Restart services if requested
        if config.restart_services_after_rollback {
            self.restart_services(&stopped_services, &target_snapshot)?;
        }
        
        // Verify rollback results
        let verification_results = if config.verify_before_rollback {
            Some(self.verify_rollback(&target_snapshot)?)
        } else {
            None
        };
        
        operation.verification_results = verification_results;
        operation.rollback_time_seconds = start_time.elapsed().as_secs_f64();
        
        // Determine final status
        operation.status = if operation.changes_failed.is_empty() {
            RollbackStatus::Completed
        } else {
            RollbackStatus::PartiallyCompleted
        };
        
        // Save rollback operation details
        self.save_rollback_operation(&operation)?;
        
        println!("Rollback completed in {:.2} seconds with status: {:?}", 
            operation.rollback_time_seconds, operation.status);
        
        Ok(operation)
    }
    
    /// Perform a partial rollback of specific files
    pub fn rollback_files(
        &self,
        target_snapshot_id: &str,
        file_paths: &[PathBuf],
        config: &RollbackConfig,
    ) -> BackupResult<RollbackOperation> {
        let start_time = std::time::Instant::now();
        let operation_id = format!("file_rollback_{}", Utc::now().timestamp());
        
        println!("Starting file rollback for {} files", file_paths.len());
        
        // Load target snapshot
        let target_snapshot = self.load_snapshot(target_snapshot_id)?;
        
        // Create safety snapshot if requested
        let safety_snapshot_id = if self.create_safety_snapshot && config.create_safety_snapshot {
            Some(self.create_safety_snapshot(&operation_id)?)
        } else {
            None
        };
        
        let mut operation = RollbackOperation {
            id: operation_id,
            created_at: Utc::now(),
            source_snapshot_id: "current".to_string(),
            target_snapshot_id: target_snapshot_id.to_string(),
            operation_type: RollbackType::FileOnly,
            status: RollbackStatus::InProgress,
            changes_applied: Vec::new(),
            changes_failed: Vec::new(),
            safety_snapshot_id,
            rollback_time_seconds: 0.0,
            verification_results: None,
        };
        
        // Apply file changes
        for file_path in file_paths {
            if let Some(target_file_state) = target_snapshot.file_states.get(file_path) {
                match self.restore_file(file_path, target_file_state, config) {
                    Ok(change) => operation.changes_applied.push(change),
                    Err(e) => {
                        let failed_change = FailedChange {
                            file_change: FileChange {
                                path: file_path.clone(),
                                change_type: ChangeType::Modified,
                                old_content: None,
                                new_content: target_file_state.content_backup.clone(),
                                old_permissions: None,
                                new_permissions: Some(target_file_state.permissions),
                                timestamp: Utc::now(),
                                checksum_before: None,
                                checksum_after: Some(target_file_state.checksum.clone()),
                            },
                            error_message: e.to_string(),
                            error_code: None,
                            retry_count: 0,
                        };
                        operation.changes_failed.push(failed_change);
                    }
                }
            }
        }
        
        operation.rollback_time_seconds = start_time.elapsed().as_secs_f64();
        operation.status = if operation.changes_failed.is_empty() {
            RollbackStatus::Completed
        } else {
            RollbackStatus::PartiallyCompleted
        };
        
        self.save_rollback_operation(&operation)?;
        
        println!("File rollback completed in {:.2} seconds", operation.rollback_time_seconds);
        
        Ok(operation)
    }
    
    /// Emergency restore from safety snapshot
    pub fn emergency_restore(&self, safety_snapshot_id: &str) -> BackupResult<RollbackOperation> {
        println!("Performing emergency restore from snapshot: {}", safety_snapshot_id);
        
        let config = RollbackConfig {
            verify_before_rollback: false,
            create_safety_snapshot: false,
            stop_services_before_rollback: false,
            restart_services_after_rollback: true,
            allowed_failure_percentage: 100.0, // Allow all failures in emergency
            ..RollbackConfig::default()
        };
        
        let mut operation = self.rollback_to_snapshot(safety_snapshot_id, &config)?;
        operation.operation_type = RollbackType::Emergency;
        
        Ok(operation)
    }
    
    /// Simulate rollback without making changes
    fn simulate_rollback(
        &self,
        operation_id: String,
        target_snapshot_id: &str,
        changes: Vec<FileChange>,
    ) -> BackupResult<RollbackOperation> {
        println!("DRY RUN: Simulating rollback operation");
        
        for change in &changes {
            println!("DRY RUN: Would apply {:?} to {}", 
                change.change_type, change.path.display());
        }
        
        let operation = RollbackOperation {
            id: operation_id,
            created_at: Utc::now(),
            source_snapshot_id: "current".to_string(),
            target_snapshot_id: target_snapshot_id.to_string(),
            operation_type: RollbackType::Full,
            status: RollbackStatus::Completed,
            changes_applied: changes,
            changes_failed: Vec::new(),
            safety_snapshot_id: None,
            rollback_time_seconds: 0.0,
            verification_results: None,
        };
        
        println!("DRY RUN: Rollback simulation completed successfully");
        
        Ok(operation)
    }
    
    /// Apply changes from rollback
    fn apply_changes(
        &self,
        changes: &[FileChange],
        target_snapshot: &SystemSnapshot,
        config: &RollbackConfig,
    ) -> BackupResult<(Vec<FileChange>, Vec<FailedChange>)> {
        let mut applied_changes = Vec::new();
        let mut failed_changes = Vec::new();
        
        for change in changes {
            let mut retry_count = 0;
            let mut success = false;
            
            while retry_count <= config.max_retries && !success {
                match self.apply_single_change(change, target_snapshot) {
                    Ok(applied_change) => {
                        applied_changes.push(applied_change);
                        success = true;
                    }
                    Err(e) => {
                        if retry_count < config.max_retries && config.retry_failed_changes {
                            retry_count += 1;
                            println!("Retrying change for {} (attempt {})", 
                                change.path.display(), retry_count + 1);
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        } else {
                            failed_changes.push(FailedChange {
                                file_change: change.clone(),
                                error_message: e.to_string(),
                                error_code: None,
                                retry_count,
                            });
                            break;
                        }
                    }
                }
            }
        }
        
        Ok((applied_changes, failed_changes))
    }
    
    /// Apply a single file change
    fn apply_single_change(
        &self,
        change: &FileChange,
        target_snapshot: &SystemSnapshot,
    ) -> BackupResult<FileChange> {
        match change.change_type {
            ChangeType::Created | ChangeType::Modified => {
                if let Some(target_state) = target_snapshot.file_states.get(&change.path) {
                    self.restore_file(&change.path, target_state, &RollbackConfig::default())?;
                }
            }
            ChangeType::Deleted => {
                // Remove file that shouldn't exist in target state
                if change.path.exists() {
                    fs::remove_file(&change.path)?;
                }
            }
            ChangeType::PermissionChanged => {
                if let Some(new_permissions) = change.new_permissions {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let permissions = std::fs::Permissions::from_mode(new_permissions);
                        fs::set_permissions(&change.path, permissions)?;
                    }
                }
            }
            _ => {
                // Handle other change types as needed
            }
        }
        
        Ok(change.clone())
    }
    
    /// Restore a single file from target state
    fn restore_file(
        &self,
        file_path: &Path,
        target_state: &crate::backup::snapshot::FileState,
        _config: &RollbackConfig,
    ) -> BackupResult<FileChange> {
        // Create parent directories if they don't exist
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Restore file content
        if let Some(content) = &target_state.content_backup {
            fs::write(file_path, content)?;
        } else {
            // For large files without content backup, we can't restore
            return Err(BackupError::RollbackError(
                format!("No content backup available for {}", file_path.display())
            ));
        }
        
        // Restore permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(target_state.permissions);
            fs::set_permissions(file_path, permissions)?;
        }
        
        // Restore ownership (requires root privileges)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if unsafe { libc::geteuid() } == 0 {
                let result = unsafe {
                    libc::chown(
                        std::ffi::CString::new(file_path.to_string_lossy().as_ref())
                            .unwrap()
                            .as_ptr(),
                        target_state.owner_uid,
                        target_state.owner_gid,
                    )
                };
                if result != 0 {
                    println!("Warning: Failed to restore ownership for {}", file_path.display());
                }
            }
        }
        
        Ok(FileChange {
            path: file_path.to_path_buf(),
            change_type: ChangeType::Modified,
            old_content: None,
            new_content: target_state.content_backup.clone(),
            old_permissions: None,
            new_permissions: Some(target_state.permissions),
            timestamp: Utc::now(),
            checksum_before: None,
            checksum_after: Some(target_state.checksum.clone()),
        })
    }
    
    /// Stop critical services before rollback
    fn stop_critical_services(
        &self,
        target_snapshot: &SystemSnapshot,
    ) -> BackupResult<Vec<String>> {
        let mut stopped_services = Vec::new();
        
        // Get list of services that will be affected
        for (service_name, service_state) in &target_snapshot.service_states {
            if service_state.active {
                // Stop service
                let output = Command::new("systemctl")
                    .args(&["stop", service_name])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        stopped_services.push(service_name.clone());
                        println!("Stopped service: {}", service_name);
                    }
                    Ok(_) => {
                        println!("Warning: Failed to stop service: {}", service_name);
                    }
                    Err(e) => {
                        println!("Error stopping service {}: {}", service_name, e);
                    }
                }
            }
        }
        
        Ok(stopped_services)
    }
    
    /// Restart services after rollback
    fn restart_services(
        &self,
        stopped_services: &[String],
        target_snapshot: &SystemSnapshot,
    ) -> BackupResult<()> {
        for service_name in stopped_services {
            if let Some(service_state) = target_snapshot.service_states.get(service_name) {
                if service_state.active {
                    let output = Command::new("systemctl")
                        .args(&["start", service_name])
                        .output();
                    
                    match output {
                        Ok(result) if result.status.success() => {
                            println!("Restarted service: {}", service_name);
                        }
                        Ok(_) => {
                            println!("Warning: Failed to restart service: {}", service_name);
                        }
                        Err(e) => {
                            println!("Error restarting service {}: {}", service_name, e);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Verify system state before rollback
    fn verify_system_state(&self, current_snapshot: &SystemSnapshot) -> BackupResult<()> {
        println!("Verifying system state before rollback...");
        
        // Check disk space
        let available_space = self.get_available_disk_space()?;
        if available_space < 1024 * 1024 * 100 { // 100MB minimum
            return Err(BackupError::RollbackError(
                "Insufficient disk space for rollback".to_string()
            ));
        }
        
        // Check if critical services are running
        for (service_name, service_state) in &current_snapshot.service_states {
            if service_state.active && Self::is_critical_service(service_name) {
                println!("Verified critical service is running: {}", service_name);
            }
        }
        
        println!("System state verification completed");
        
        Ok(())
    }
    
    /// Verify rollback results
    fn verify_rollback(&self, target_snapshot: &SystemSnapshot) -> BackupResult<VerificationResults> {
        println!("Verifying rollback results...");
        
        let start_time = std::time::Instant::now();
        let mut files_verified = 0;
        let mut files_failed = 0;
        let mut services_verified = 0;
        let mut services_failed = 0;
        let mut failed_verifications = Vec::new();
        
        // Verify file states
        for (file_path, target_state) in &target_snapshot.file_states {
            if self.verify_file_state(file_path, target_state).is_ok() {
                files_verified += 1;
            } else {
                files_failed += 1;
                failed_verifications.push(format!("File verification failed: {}", file_path.display()));
            }
        }
        
        // Verify service states
        for (service_name, target_state) in &target_snapshot.service_states {
            if self.verify_service_state(service_name, target_state).is_ok() {
                services_verified += 1;
            } else {
                services_failed += 1;
                failed_verifications.push(format!("Service verification failed: {}", service_name));
            }
        }
        
        let verification_time = start_time.elapsed().as_secs_f64();
        let integrity_check_passed = files_failed == 0 && services_failed == 0;
        
        let results = VerificationResults {
            files_verified,
            files_failed,
            services_verified,
            services_failed,
            integrity_check_passed,
            verification_time_seconds: verification_time,
            failed_verifications,
        };
        
        println!("Rollback verification completed in {:.2} seconds", verification_time);
        println!("Files: {}/{} verified, Services: {}/{} verified", 
            files_verified, files_verified + files_failed,
            services_verified, services_verified + services_failed);
        
        Ok(results)
    }
    
    /// Verify a single file state
    fn verify_file_state(
        &self,
        file_path: &Path,
        target_state: &crate::backup::snapshot::FileState,
    ) -> BackupResult<()> {
        if !file_path.exists() {
            return Err(BackupError::RollbackError(
                format!("File does not exist: {}", file_path.display())
            ));
        }
        
        let metadata = fs::metadata(file_path)?;
        
        // Verify size
        if metadata.len() != target_state.size {
            return Err(BackupError::RollbackError(
                format!("File size mismatch for {}", file_path.display())
            ));
        }
        
        // Verify permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() != target_state.permissions {
                return Err(BackupError::RollbackError(
                    format!("Permissions mismatch for {}", file_path.display())
                ));
            }
        }
        
        Ok(())
    }
    
    /// Verify a single service state
    fn verify_service_state(
        &self,
        service_name: &str,
        target_state: &crate::backup::snapshot::ServiceState,
    ) -> BackupResult<()> {
        let output = Command::new("systemctl")
            .args(&["is-active", service_name])
            .output()
            .map_err(|e| BackupError::RollbackError(format!("Failed to check service status: {}", e)))?;
        
        let is_active = String::from_utf8_lossy(&output.stdout).trim() == "active";
        
        if is_active != target_state.active {
            return Err(BackupError::RollbackError(
                format!("Service state mismatch for {}: expected {}, got {}", 
                    service_name, target_state.active, is_active)
            ));
        }
        
        Ok(())
    }
    
    /// Create a safety snapshot before rollback
    fn create_safety_snapshot(&self, operation_id: &str) -> BackupResult<String> {
        let safety_snapshot = SystemSnapshot::create(
            crate::backup::snapshot::SnapshotType::Emergency,
            format!("Safety snapshot for rollback operation {}", operation_id),
            &[PathBuf::from("/etc"), PathBuf::from("/var/lib")],
        )?;
        
        let safety_id = safety_snapshot.metadata.id.clone();
        let mut safety_snapshot_mut = safety_snapshot;
        safety_snapshot_mut.save(&self.backup_dir, true)?;
        
        println!("Created safety snapshot: {}", safety_id);
        
        Ok(safety_id)
    }
    
    /// Load a snapshot from file
    fn load_snapshot(&self, snapshot_id: &str) -> BackupResult<SystemSnapshot> {
        let snapshot_file = self.backup_dir.join(format!("{}.snapshot.gz", snapshot_id));
        
        if !snapshot_file.exists() {
            let snapshot_file = self.backup_dir.join(format!("{}.snapshot", snapshot_id));
            if !snapshot_file.exists() {
                return Err(BackupError::BackupNotFound(snapshot_id.to_string()));
            }
        }
        
        SystemSnapshot::load(&snapshot_file)
    }
    
    /// Save rollback operation details
    fn save_rollback_operation(&self, operation: &RollbackOperation) -> BackupResult<()> {
        let operation_file = self.backup_dir.join("rollback_operations.json");
        
        let mut operations: Vec<RollbackOperation> = if operation_file.exists() {
            let content = fs::read_to_string(&operation_file)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        };
        
        operations.push(operation.clone());
        
        let content = serde_json::to_string_pretty(&operations)?;
        fs::write(&operation_file, content)?;
        
        Ok(())
    }
    
    /// Get available disk space
    fn get_available_disk_space(&self) -> BackupResult<u64> {
        // This is a simplified implementation
        // In a real implementation, you would use statvfs or similar
        Ok(1024 * 1024 * 1024) // Assume 1GB available
    }
    
    /// Check if a service is critical
    fn is_critical_service(service_name: &str) -> bool {
        matches!(service_name, 
            "ssh" | "sshd" | "systemd" | "dbus" | "networkmanager" | "network"
        )
    }
    
    /// List available snapshots for rollback
    pub fn list_available_snapshots(&self) -> BackupResult<Vec<String>> {
        let mut snapshots = Vec::new();
        
        if !self.backup_dir.exists() {
            return Ok(snapshots);
        }
        
        for entry in fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if let Some(extension) = path.extension() {
                if extension == "snapshot" || 
                   (extension == "gz" && path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.ends_with(".snapshot"))
                    .unwrap_or(false)) {
                    
                    if let Some(filename) = path.file_stem() {
                        let snapshot_id = filename.to_string_lossy()
                            .replace(".snapshot", "");
                        snapshots.push(snapshot_id);
                    }
                }
            }
        }
        
        snapshots.sort();
        Ok(snapshots)
    }
    
    /// Get rollback operation history
    pub fn get_rollback_history(&self) -> BackupResult<Vec<RollbackOperation>> {
        let operation_file = self.backup_dir.join("rollback_operations.json");
        
        if !operation_file.exists() {
            return Ok(Vec::new());
        }
        
        let content = fs::read_to_string(&operation_file)?;
        let operations: Vec<RollbackOperation> = serde_json::from_str(&content)
            .unwrap_or_default();
        
        Ok(operations)
    }
}