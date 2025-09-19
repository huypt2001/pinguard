pub mod manager;
pub mod snapshot;
pub mod rollback;
pub mod versioning;
pub mod integrity;
pub mod rpo;

pub use manager::BackupManager;
pub use snapshot::{SystemSnapshot, SnapshotType};
pub use rollback::{RollbackManager, RollbackOperation};
pub use versioning::{VersionManager, ConfigVersion};
pub use integrity::{IntegrityChecker, BackupIntegrity};
pub use rpo::{RPOManager, BackupPolicy};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use chrono::{DateTime, Utc};

/// Main backup result type
pub type BackupResult<T> = Result<T, BackupError>;

/// Backup system errors
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Compression error: {0}")]
    CompressionError(String),
    #[error("Integrity check failed: {0}")]
    IntegrityError(String),
    #[error("Rollback failed: {0}")]
    RollbackError(String),
    #[error("Snapshot creation failed: {0}")]
    SnapshotError(String),
    #[error("Version management error: {0}")]
    VersionError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Permission denied: {0}")]
    PermissionError(String),
    #[error("Backup not found: {0}")]
    BackupNotFound(String),
    #[error("Invalid backup format: {0}")]
    InvalidFormat(String),
}

/// Backup metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub backup_type: BackupType,
    pub description: String,
    pub size_bytes: u64,
    pub checksum: String,
    pub version: String,
    pub tags: Vec<String>,
    pub files_included: Vec<PathBuf>,
    pub compression_ratio: f64,
    pub pre_change_snapshot: bool,
}

/// Types of backups
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackupType {
    Full,
    Incremental,
    Differential,
    Snapshot,
    Configuration,
    System,
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub backup_dir: PathBuf,
    pub max_backups: usize,
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
    pub integrity_checks: bool,
    pub auto_cleanup: bool,
    pub retention_days: u32,
    pub backup_schedule: Option<String>,
    pub excluded_paths: Vec<PathBuf>,
    pub included_paths: Vec<PathBuf>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            backup_dir: PathBuf::from("/var/lib/pinGuard/backups"),
            max_backups: 50,
            compression_enabled: true,
            encryption_enabled: false,
            integrity_checks: true,
            auto_cleanup: true,
            retention_days: 30,
            backup_schedule: None,
            excluded_paths: vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/proc"),
                PathBuf::from("/sys"),
                PathBuf::from("/dev"),
            ],
            included_paths: vec![
                PathBuf::from("/etc"),
                PathBuf::from("/var/lib"),
                PathBuf::from("/usr/local/etc"),
            ],
        }
    }
}

/// File change information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
    pub old_content: Option<Vec<u8>>,
    pub new_content: Option<Vec<u8>>,
    pub old_permissions: Option<u32>,
    pub new_permissions: Option<u32>,
    pub timestamp: DateTime<Utc>,
    pub checksum_before: Option<String>,
    pub checksum_after: Option<String>,
}

/// Types of file changes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
    Moved,
    PermissionChanged,
    OwnershipChanged,
}

/// Recovery point objective settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RPOSettings {
    pub max_data_loss_minutes: u32,
    pub backup_frequency_minutes: u32,
    pub critical_files: Vec<PathBuf>,
    pub priority_level: Priority,
    pub auto_backup_on_changes: bool,
}

/// Priority levels for backups
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for RPOSettings {
    fn default() -> Self {
        Self {
            max_data_loss_minutes: 60,
            backup_frequency_minutes: 30,
            critical_files: vec![
                PathBuf::from("/etc/passwd"),
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/etc/sudoers"),
                PathBuf::from("/etc/ssh"),
            ],
            priority_level: Priority::High,
            auto_backup_on_changes: true,
        }
    }
}