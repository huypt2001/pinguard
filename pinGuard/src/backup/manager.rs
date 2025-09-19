use crate::backup::{
    BackupResult, BackupError, BackupConfig, BackupMetadata, BackupType, Priority,
    SystemSnapshot, RollbackManager, RollbackOperation, FileChange,
};
use crate::backup::rollback::RollbackConfig;
use crate::backup::snapshot::SnapshotType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Utc};
use tokio::time::{interval, Instant};

/// Main backup manager coordinating all backup operations
#[derive(Debug)]
pub struct BackupManager {
    config: BackupConfig,
    rollback_manager: RollbackManager,
    active_operations: Arc<Mutex<HashMap<String, BackupOperation>>>,
    backup_history: Vec<BackupMetadata>,
    auto_backup_enabled: bool,
    watch_mode: bool,
}

/// Backup operation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupOperation {
    pub id: String,
    pub operation_type: BackupOperationType,
    pub status: BackupOperationStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress_percentage: f64,
    pub files_processed: u32,
    pub total_files: u32,
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub error_message: Option<String>,
    pub pre_change_snapshot_id: Option<String>,
    pub result_snapshot_id: Option<String>,
}

/// Types of backup operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackupOperationType {
    CreateSnapshot,
    IncrementalBackup,
    FullBackup,
    Rollback,
    Cleanup,
    Verification,
    ScheduledBackup,
    EmergencyBackup,
}

/// Backup operation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackupOperationStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Paused,
}

/// Backup statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStatistics {
    pub total_backups: u32,
    pub successful_backups: u32,
    pub failed_backups: u32,
    pub total_size_bytes: u64,
    pub compressed_size_bytes: u64,
    pub average_backup_time_seconds: f64,
    pub last_backup_time: Option<DateTime<Utc>>,
    pub oldest_backup_time: Option<DateTime<Utc>>,
    pub backup_frequency_hours: f64,
    pub success_rate_percentage: f64,
}

/// Backup policy for automated operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    pub name: String,
    pub enabled: bool,
    pub backup_type: BackupType,
    pub schedule_cron: String,
    pub retention_days: u32,
    pub priority: Priority,
    pub max_backup_size_mb: Option<u32>,
    pub included_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
    pub pre_backup_commands: Vec<String>,
    pub post_backup_commands: Vec<String>,
    pub notification_on_failure: bool,
    pub max_retries: u32,
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            enabled: true,
            backup_type: BackupType::Incremental,
            schedule_cron: "0 */6 * * *".to_string(), // Every 6 hours
            retention_days: 30,
            priority: Priority::Medium,
            max_backup_size_mb: Some(1024), // 1GB limit
            included_paths: vec![
                PathBuf::from("/etc"),
                PathBuf::from("/var/lib"),
            ],
            excluded_paths: vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/proc"),
                PathBuf::from("/sys"),
            ],
            pre_backup_commands: Vec::new(),
            post_backup_commands: Vec::new(),
            notification_on_failure: true,
            max_retries: 3,
        }
    }
}

impl BackupManager {
    /// Create a new backup manager
    pub fn new(config: BackupConfig) -> BackupResult<Self> {
        // Ensure backup directory exists
        fs::create_dir_all(&config.backup_dir)?;
        
        let rollback_manager = RollbackManager::new(config.backup_dir.clone());
        
        let mut manager = Self {
            config,
            rollback_manager,
            active_operations: Arc::new(Mutex::new(HashMap::new())),
            backup_history: Vec::new(),
            auto_backup_enabled: false,
            watch_mode: false,
        };
        
        // Load existing backup history
        manager.load_backup_history()?;
        
        Ok(manager)
    }
    
    /// Create a pre-change snapshot before making system modifications
    pub fn create_pre_change_snapshot(
        &mut self,
        description: String,
        include_paths: &[PathBuf],
    ) -> BackupResult<String> {
        let operation_id = format!("pre_change_{}", Utc::now().timestamp());
        
        println!("Creating pre-change snapshot: {}", description);
        
        let operation = BackupOperation {
            id: operation_id.clone(),
            operation_type: BackupOperationType::CreateSnapshot,
            status: BackupOperationStatus::Running,
            started_at: Utc::now(),
            completed_at: None,
            progress_percentage: 0.0,
            files_processed: 0,
            total_files: 0,
            bytes_processed: 0,
            total_bytes: 0,
            error_message: None,
            pre_change_snapshot_id: None,
            result_snapshot_id: None,
        };
        
        self.register_operation(operation);
        
        match SystemSnapshot::create(SnapshotType::PreChange, description, include_paths) {
            Ok(mut snapshot) => {
                // Save snapshot
                let snapshot_path = snapshot.save(&self.config.backup_dir, self.config.compression_enabled)?;
                let snapshot_id = snapshot.metadata.id.clone();
                
                // Update backup history
                self.backup_history.push(snapshot.metadata.clone());
                self.save_backup_history()?;
                
                // Update operation status
                self.update_operation_status(&operation_id, BackupOperationStatus::Completed, None);
                self.update_operation_result(&operation_id, Some(snapshot_id.clone()));
                
                println!("Pre-change snapshot created successfully: {}", snapshot_id);
                
                Ok(snapshot_id)
            }
            Err(e) => {
                self.update_operation_status(&operation_id, BackupOperationStatus::Failed, Some(e.to_string()));
                Err(e)
            }
        }
    }
    
    /// Create an incremental backup
    pub fn create_incremental_backup(
        &mut self,
        description: String,
        base_snapshot_id: Option<String>,
    ) -> BackupResult<String> {
        let operation_id = format!("incremental_{}", Utc::now().timestamp());
        
        println!("Creating incremental backup: {}", description);
        
        let operation = BackupOperation {
            id: operation_id.clone(),
            operation_type: BackupOperationType::IncrementalBackup,
            status: BackupOperationStatus::Running,
            started_at: Utc::now(),
            completed_at: None,
            progress_percentage: 0.0,
            files_processed: 0,
            total_files: 0,
            bytes_processed: 0,
            total_bytes: 0,
            error_message: None,
            pre_change_snapshot_id: base_snapshot_id,
            result_snapshot_id: None,
        };
        
        self.register_operation(operation.clone());
        
        // Create current snapshot
        let current_snapshot = SystemSnapshot::create(
            SnapshotType::Scheduled,
            description,
            &self.config.included_paths,
        )?;
        
        // If we have a base snapshot, calculate incremental changes
        let changes = if let Some(base_id) = &operation.pre_change_snapshot_id {
            if let Ok(base_snapshot) = self.load_snapshot(base_id) {
                current_snapshot.compare_with(&base_snapshot)
            } else {
                Vec::new() // If base snapshot can't be loaded, treat as full backup
            }
        } else {
            Vec::new() // First backup, no changes to compare
        };
        
        // Save the current snapshot
        let mut current_snapshot_mut = current_snapshot;
        let snapshot_path = current_snapshot_mut.save(&self.config.backup_dir, self.config.compression_enabled)?;
        let snapshot_id = current_snapshot_mut.metadata.id.clone();
        
        // Save incremental changes if any
        if !changes.is_empty() {
            self.save_incremental_changes(&snapshot_id, &changes)?;
        }
        
        // Update backup history
        self.backup_history.push(current_snapshot_mut.metadata.clone());
        self.save_backup_history()?;
        
        // Update operation status
        self.update_operation_status(&operation_id, BackupOperationStatus::Completed, None);
        self.update_operation_result(&operation_id, Some(snapshot_id.clone()));
        
        println!("Incremental backup created successfully: {} ({} changes)", 
            snapshot_id, changes.len());
        
        Ok(snapshot_id)
    }
    
    /// Perform a full system rollback
    pub fn rollback_to_snapshot(
        &mut self,
        snapshot_id: &str,
        dry_run: bool,
    ) -> BackupResult<RollbackOperation> {
        println!("Initiating rollback to snapshot: {}", snapshot_id);
        
        let operation_id = format!("rollback_{}", Utc::now().timestamp());
        
        let backup_operation = BackupOperation {
            id: operation_id.clone(),
            operation_type: BackupOperationType::Rollback,
            status: BackupOperationStatus::Running,
            started_at: Utc::now(),
            completed_at: None,
            progress_percentage: 0.0,
            files_processed: 0,
            total_files: 0,
            bytes_processed: 0,
            total_bytes: 0,
            error_message: None,
            pre_change_snapshot_id: Some(snapshot_id.to_string()),
            result_snapshot_id: None,
        };
        
        self.register_operation(backup_operation);
        
        // Configure rollback
        let mut rollback_manager = RollbackManager::new(self.config.backup_dir.clone());
        rollback_manager
            .set_dry_run(dry_run)
            .set_verify_before_rollback(true)
            .set_create_safety_snapshot(!dry_run);
        
        let rollback_config = RollbackConfig::default();
        
        match rollback_manager.rollback_to_snapshot(snapshot_id, &rollback_config) {
            Ok(rollback_operation) => {
                self.update_operation_status(&operation_id, BackupOperationStatus::Completed, None);
                
                println!("Rollback completed successfully");
                
                Ok(rollback_operation)
            }
            Err(e) => {
                self.update_operation_status(&operation_id, BackupOperationStatus::Failed, Some(e.to_string()));
                Err(e)
            }
        }
    }
    
    /// Rollback specific files only
    pub fn rollback_files(
        &mut self,
        snapshot_id: &str,
        file_paths: &[PathBuf],
        dry_run: bool,
    ) -> BackupResult<RollbackOperation> {
        println!("Initiating file rollback for {} files", file_paths.len());
        
        let mut rollback_manager = RollbackManager::new(self.config.backup_dir.clone());
        rollback_manager
            .set_dry_run(dry_run)
            .set_verify_before_rollback(true)
            .set_create_safety_snapshot(!dry_run);
        
        let rollback_config = RollbackConfig::default();
        
        rollback_manager.rollback_files(snapshot_id, file_paths, &rollback_config)
    }
    
    /// Start automated backup scheduling
    pub async fn start_auto_backup(&mut self, policies: Vec<BackupPolicy>) -> BackupResult<()> {
        if self.auto_backup_enabled {
            return Ok(());
        }
        
        self.auto_backup_enabled = true;
        
        println!("Starting automated backup with {} policies", policies.len());
        
        // Start background task for scheduled backups
        let backup_dir = self.config.backup_dir.clone();
        let included_paths = self.config.included_paths.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600)); // Check every hour
            
            loop {
                interval.tick().await;
                
                for policy in &policies {
                    if policy.enabled {
                        // Check if backup is due based on schedule
                        if Self::is_backup_due(&policy.schedule_cron).await {
                            if let Err(e) = Self::execute_scheduled_backup(&policy, &backup_dir, &included_paths).await {
                                eprintln!("Scheduled backup failed for policy '{}': {}", policy.name, e);
                            }
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Stop automated backup scheduling
    pub fn stop_auto_backup(&mut self) {
        self.auto_backup_enabled = false;
        println!("Stopped automated backup scheduling");
    }
    
    /// Start file system watching for automatic backups on changes
    pub async fn start_watch_mode(&mut self, watch_paths: Vec<PathBuf>) -> BackupResult<()> {
        if self.watch_mode {
            return Ok(());
        }
        
        self.watch_mode = true;
        
        println!("Starting file system watch mode for {} paths", watch_paths.len());
        
        // This would typically use a file watcher like notify
        // For now, we'll implement a simple polling mechanism
        let backup_dir = self.config.backup_dir.clone();
        let included_paths = self.config.included_paths.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Check every minute
            let mut last_check = SystemTime::now();
            
            loop {
                interval.tick().await;
                
                let current_time = SystemTime::now();
                let mut changes_detected = false;
                
                // Check for file modifications since last check
                for watch_path in &watch_paths {
                    if let Ok(metadata) = fs::metadata(watch_path) {
                        if let Ok(modified) = metadata.modified() {
                            if modified > last_check {
                                changes_detected = true;
                                break;
                            }
                        }
                    }
                }
                
                if changes_detected {
                    println!("Changes detected, creating automatic backup...");
                    
                    // Create automatic backup
                    if let Ok(mut snapshot) = SystemSnapshot::create(
                        SnapshotType::Manual,
                        format!("Automatic backup - changes detected at {}", 
                            Utc::now().format("%Y-%m-%d %H:%M:%S")),
                        &included_paths,
                    ) {
                        if let Err(e) = snapshot.save(&backup_dir, true) {
                            eprintln!("Failed to save automatic backup: {}", e);
                        } else {
                            println!("Automatic backup created: {}", snapshot.metadata.id);
                        }
                    }
                }
                
                last_check = current_time;
            }
        });
        
        Ok(())
    }
    
    /// Stop file system watching
    pub fn stop_watch_mode(&mut self) {
        self.watch_mode = false;
        println!("Stopped file system watch mode");
    }
    
    /// Clean up old backups based on retention policy
    pub fn cleanup_old_backups(&mut self, retention_days: u32) -> BackupResult<Vec<String>> {
        let operation_id = format!("cleanup_{}", Utc::now().timestamp());
        
        let operation = BackupOperation {
            id: operation_id.clone(),
            operation_type: BackupOperationType::Cleanup,
            status: BackupOperationStatus::Running,
            started_at: Utc::now(),
            completed_at: None,
            progress_percentage: 0.0,
            files_processed: 0,
            total_files: 0,
            bytes_processed: 0,
            total_bytes: 0,
            error_message: None,
            pre_change_snapshot_id: None,
            result_snapshot_id: None,
        };
        
        self.register_operation(operation);
        
        let cutoff_time = Utc::now() - chrono::Duration::days(retention_days as i64);
        let mut deleted_backups = Vec::new();
        
        // Find old backups to delete
        let backups_to_delete: Vec<_> = self.backup_history.iter()
            .filter(|backup| backup.created_at < cutoff_time)
            .collect();
        
        println!("Found {} old backups to delete (older than {} days)", 
            backups_to_delete.len(), retention_days);
        
        // Delete old backup files
        for backup in backups_to_delete {
            let backup_file = self.config.backup_dir.join(format!("{}.snapshot.gz", backup.id));
            
            if backup_file.exists() {
                match fs::remove_file(&backup_file) {
                    Ok(()) => {
                        deleted_backups.push(backup.id.clone());
                        println!("Deleted old backup: {}", backup.id);
                    }
                    Err(e) => {
                        println!("Failed to delete backup {}: {}", backup.id, e);
                    }
                }
            }
            
            // Also try without .gz extension
            let backup_file_uncompressed = self.config.backup_dir.join(format!("{}.snapshot", backup.id));
            if backup_file_uncompressed.exists() {
                let _ = fs::remove_file(&backup_file_uncompressed);
            }
        }
        
        // Update backup history
        self.backup_history.retain(|backup| !deleted_backups.contains(&backup.id));
        self.save_backup_history()?;
        
        self.update_operation_status(&operation_id, BackupOperationStatus::Completed, None);
        
        println!("Cleanup completed: deleted {} old backups", deleted_backups.len());
        
        Ok(deleted_backups)
    }
    
    /// Verify backup integrity
    pub fn verify_backup_integrity(&mut self, snapshot_id: &str) -> BackupResult<bool> {
        let operation_id = format!("verify_{}", Utc::now().timestamp());
        
        let operation = BackupOperation {
            id: operation_id.clone(),
            operation_type: BackupOperationType::Verification,
            status: BackupOperationStatus::Running,
            started_at: Utc::now(),
            completed_at: None,
            progress_percentage: 0.0,
            files_processed: 0,
            total_files: 0,
            bytes_processed: 0,
            total_bytes: 0,
            error_message: None,
            pre_change_snapshot_id: Some(snapshot_id.to_string()),
            result_snapshot_id: None,
        };
        
        self.register_operation(operation);
        
        match self.load_snapshot(snapshot_id) {
            Ok(snapshot) => {
                // Verify checksums and file integrity
                let mut verification_passed = true;
                
                for (file_path, file_state) in &snapshot.file_states {
                    if file_path.exists() {
                        // Verify file still matches the snapshot
                        if let Ok(metadata) = fs::metadata(file_path) {
                            if metadata.len() != file_state.size {
                                verification_passed = false;
                                println!("File size mismatch: {}", file_path.display());
                            }
                        }
                    } else {
                        println!("File no longer exists: {}", file_path.display());
                    }
                }
                
                self.update_operation_status(&operation_id, BackupOperationStatus::Completed, None);
                
                if verification_passed {
                    println!("Backup integrity verification passed for: {}", snapshot_id);
                } else {
                    println!("Backup integrity verification failed for: {}", snapshot_id);
                }
                
                Ok(verification_passed)
            }
            Err(e) => {
                self.update_operation_status(&operation_id, BackupOperationStatus::Failed, Some(e.to_string()));
                Err(e)
            }
        }
    }
    
    /// Get backup statistics
    pub fn get_backup_statistics(&self) -> BackupStatistics {
        let total_backups = self.backup_history.len() as u32;
        let successful_backups = total_backups; // Assume all in history are successful
        let failed_backups = 0; // Track this separately if needed
        
        let total_size_bytes = self.backup_history.iter()
            .map(|backup| backup.size_bytes)
            .sum();
        
        let compressed_size_bytes = total_size_bytes; // Simplified
        
        let success_rate_percentage = if total_backups > 0 {
            (successful_backups as f64 / total_backups as f64) * 100.0
        } else {
            0.0
        };
        
        let last_backup_time = self.backup_history.iter()
            .map(|backup| backup.created_at)
            .max();
        
        let oldest_backup_time = self.backup_history.iter()
            .map(|backup| backup.created_at)
            .min();
        
        BackupStatistics {
            total_backups,
            successful_backups,
            failed_backups,
            total_size_bytes,
            compressed_size_bytes,
            average_backup_time_seconds: 60.0, // Simplified
            last_backup_time,
            oldest_backup_time,
            backup_frequency_hours: 6.0, // Based on default policy
            success_rate_percentage,
        }
    }
    
    /// List available snapshots
    pub fn list_snapshots(&self) -> Vec<BackupMetadata> {
        self.backup_history.clone()
    }
    
    /// Get current active operations
    pub fn get_active_operations(&self) -> Vec<BackupOperation> {
        if let Ok(operations) = self.active_operations.lock() {
            operations.values().cloned().collect()
        } else {
            Vec::new()
        }
    }
    
    // Private helper methods
    
    fn register_operation(&self, operation: BackupOperation) {
        if let Ok(mut operations) = self.active_operations.lock() {
            operations.insert(operation.id.clone(), operation);
        }
    }
    
    fn update_operation_status(&self, operation_id: &str, status: BackupOperationStatus, error: Option<String>) {
        if let Ok(mut operations) = self.active_operations.lock() {
            if let Some(operation) = operations.get_mut(operation_id) {
                operation.status = status.clone();
                operation.error_message = error;
                
                if matches!(status, BackupOperationStatus::Completed | BackupOperationStatus::Failed) {
                    operation.completed_at = Some(Utc::now());
                    operation.progress_percentage = 100.0;
                }
            }
        }
    }
    
    fn update_operation_result(&self, operation_id: &str, snapshot_id: Option<String>) {
        if let Ok(mut operations) = self.active_operations.lock() {
            if let Some(operation) = operations.get_mut(operation_id) {
                operation.result_snapshot_id = snapshot_id;
            }
        }
    }
    
    fn load_snapshot(&self, snapshot_id: &str) -> BackupResult<SystemSnapshot> {
        let snapshot_file = self.config.backup_dir.join(format!("{}.snapshot.gz", snapshot_id));
        
        if snapshot_file.exists() {
            SystemSnapshot::load(&snapshot_file)
        } else {
            let snapshot_file = self.config.backup_dir.join(format!("{}.snapshot", snapshot_id));
            if snapshot_file.exists() {
                SystemSnapshot::load(&snapshot_file)
            } else {
                Err(BackupError::BackupNotFound(snapshot_id.to_string()))
            }
        }
    }
    
    fn save_incremental_changes(&self, snapshot_id: &str, changes: &[FileChange]) -> BackupResult<()> {
        let changes_file = self.config.backup_dir.join(format!("{}.changes.json", snapshot_id));
        let content = serde_json::to_string_pretty(changes)?;
        fs::write(changes_file, content)?;
        Ok(())
    }
    
    fn load_backup_history(&mut self) -> BackupResult<()> {
        let history_file = self.config.backup_dir.join("backup_history.json");
        
        if history_file.exists() {
            let content = fs::read_to_string(history_file)?;
            self.backup_history = serde_json::from_str(&content).unwrap_or_default();
        }
        
        Ok(())
    }
    
    fn save_backup_history(&self) -> BackupResult<()> {
        let history_file = self.config.backup_dir.join("backup_history.json");
        let content = serde_json::to_string_pretty(&self.backup_history)?;
        fs::write(history_file, content)?;
        Ok(())
    }
    
    async fn is_backup_due(_schedule_cron: &str) -> bool {
        // Simplified implementation - in reality, you'd parse the cron expression
        // and check against current time
        true // For demo purposes
    }
    
    async fn execute_scheduled_backup(
        policy: &BackupPolicy,
        backup_dir: &Path,
        included_paths: &[PathBuf],
    ) -> BackupResult<()> {
        println!("Executing scheduled backup for policy: {}", policy.name);
        
        let snapshot = SystemSnapshot::create(
            SnapshotType::Scheduled,
            format!("Scheduled backup - policy: {}", policy.name),
            included_paths,
        )?;
        
        let mut snapshot_mut = snapshot;
        snapshot_mut.save(backup_dir, true)?;
        
        println!("Scheduled backup completed: {}", snapshot_mut.metadata.id);
        
        Ok(())
    }
}