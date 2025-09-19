use crate::backup::{BackupResult, BackupError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};

/// Version manager for tracking configuration changes
#[derive(Debug)]
pub struct VersionManager {
    versions_dir: PathBuf,
    max_versions: usize,
}

/// Configuration version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVersion {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub description: String,
    pub author: String,
    pub config_files: HashMap<PathBuf, ConfigFileVersion>,
    pub parent_version_id: Option<String>,
    pub tags: Vec<String>,
    pub is_rollback_safe: bool,
    pub validation_status: ValidationStatus,
}

/// Individual configuration file version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFileVersion {
    pub file_path: PathBuf,
    pub content: String,
    pub checksum: String,
    pub size_bytes: u64,
    pub permissions: u32,
    pub last_modified: DateTime<Utc>,
    pub encoding: String,
    pub syntax_valid: bool,
}

/// Validation status for configurations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidationStatus {
    NotValidated,
    Valid,
    Invalid(String),
    Warning(String),
}

/// Version comparison result
#[derive(Debug, Clone)]
pub struct VersionDiff {
    pub from_version: String,
    pub to_version: String,
    pub file_changes: Vec<FileChange>,
    pub summary: DiffSummary,
}

/// File change in version diff
#[derive(Debug, Clone)]
pub struct FileChange {
    pub file_path: PathBuf,
    pub change_type: FileChangeType,
    pub old_content: Option<String>,
    pub new_content: Option<String>,
    pub line_changes: Vec<LineChange>,
}

/// Types of file changes
#[derive(Debug, Clone, PartialEq)]
pub enum FileChangeType {
    Added,
    Modified,
    Deleted,
    Renamed(PathBuf), // Old path
}

/// Line-level changes
#[derive(Debug, Clone)]
pub struct LineChange {
    pub line_number: usize,
    pub change_type: LineChangeType,
    pub old_content: Option<String>,
    pub new_content: Option<String>,
}

/// Types of line changes
#[derive(Debug, Clone, PartialEq)]
pub enum LineChangeType {
    Added,
    Deleted,
    Modified,
    Context, // Unchanged line for context
}

/// Summary of version differences
#[derive(Debug, Clone)]
pub struct DiffSummary {
    pub files_added: u32,
    pub files_modified: u32,
    pub files_deleted: u32,
    pub lines_added: u32,
    pub lines_deleted: u32,
    pub lines_modified: u32,
    pub critical_changes: Vec<String>,
}

impl VersionManager {
    /// Create a new version manager
    pub fn new(versions_dir: PathBuf, max_versions: usize) -> BackupResult<Self> {
        fs::create_dir_all(&versions_dir)?;
        
        Ok(Self {
            versions_dir,
            max_versions,
        })
    }
    
    /// Create a new configuration version
    pub fn create_version(
        &self,
        description: String,
        author: String,
        config_paths: &[PathBuf],
        parent_version_id: Option<String>,
    ) -> BackupResult<ConfigVersion> {
        let version_id = format!("v_{}", Utc::now().timestamp());
        let created_at = Utc::now();
        
        println!("Creating configuration version: {}", description);
        
        let mut config_files = HashMap::new();
        
        // Capture all configuration files
        for config_path in config_paths {
            if config_path.exists() {
                let file_version = self.capture_config_file(config_path)?;
                config_files.insert(config_path.clone(), file_version);
            }
        }
        
        // Validate configurations
        let validation_status = self.validate_configurations(&config_files)?;
        
        let version = ConfigVersion {
            id: version_id.clone(),
            created_at,
            description,
            author,
            config_files,
            parent_version_id,
            tags: Vec::new(),
            is_rollback_safe: matches!(validation_status, ValidationStatus::Valid),
            validation_status,
        };
        
        // Save version
        self.save_version(&version)?;
        
        // Cleanup old versions if needed
        self.cleanup_old_versions()?;
        
        println!("Configuration version created: {}", version_id);
        
        Ok(version)
    }
    
    /// Capture a single configuration file
    fn capture_config_file(&self, file_path: &Path) -> BackupResult<ConfigFileVersion> {
        let content = fs::read_to_string(file_path)?;
        let metadata = fs::metadata(file_path)?;
        
        let checksum = self.calculate_checksum(&content);
        let size_bytes = metadata.len();
        let last_modified = DateTime::from(metadata.modified()?);
        
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::MetadataExt;
            metadata.mode()
        };
        
        #[cfg(not(unix))]
        let permissions = 0o644;
        
        // Detect encoding (simplified)
        let encoding = if content.is_ascii() {
            "ASCII".to_string()
        } else {
            "UTF-8".to_string()
        };
        
        // Basic syntax validation based on file extension
        let syntax_valid = self.validate_syntax(file_path, &content);
        
        Ok(ConfigFileVersion {
            file_path: file_path.to_path_buf(),
            content,
            checksum,
            size_bytes,
            permissions,
            last_modified,
            encoding,
            syntax_valid,
        })
    }
    
    /// Validate configuration syntax
    fn validate_syntax(&self, file_path: &Path, content: &str) -> bool {
        if let Some(extension) = file_path.extension().and_then(|e| e.to_str()) {
            match extension {
                "yaml" | "yml" => {
                    serde_yaml::from_str::<serde_yaml::Value>(content).is_ok()
                }
                "json" => {
                    serde_json::from_str::<serde_json::Value>(content).is_ok()
                }
                "toml" => {
                    // Would need toml crate for proper validation
                    !content.trim().is_empty()
                }
                "conf" | "config" => {
                    // Basic validation for config files
                    !content.trim().is_empty()
                }
                _ => true, // Assume valid for unknown types
            }
        } else {
            true
        }
    }
    
    /// Validate all configurations in a version
    fn validate_configurations(
        &self,
        config_files: &HashMap<PathBuf, ConfigFileVersion>,
    ) -> BackupResult<ValidationStatus> {
        let mut invalid_files = Vec::new();
        let mut warning_files = Vec::new();
        
        for (path, file_version) in config_files {
            if !file_version.syntax_valid {
                invalid_files.push(path.display().to_string());
            }
            
            // Check for potential issues
            if file_version.content.contains("TODO") || file_version.content.contains("FIXME") {
                warning_files.push(format!("{}: Contains TODO/FIXME", path.display()));
            }
            
            // Check for security issues
            if file_version.content.contains("password") && file_version.content.contains("=") {
                warning_files.push(format!("{}: May contain hardcoded passwords", path.display()));
            }
        }
        
        if !invalid_files.is_empty() {
            Ok(ValidationStatus::Invalid(
                format!("Invalid syntax in files: {}", invalid_files.join(", "))
            ))
        } else if !warning_files.is_empty() {
            Ok(ValidationStatus::Warning(
                format!("Warnings: {}", warning_files.join("; "))
            ))
        } else {
            Ok(ValidationStatus::Valid)
        }
    }
    
    /// Calculate checksum for content
    fn calculate_checksum(&self, content: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Save version to disk
    fn save_version(&self, version: &ConfigVersion) -> BackupResult<()> {
        let version_file = self.versions_dir.join(format!("{}.json", version.id));
        let content = serde_json::to_string_pretty(version)?;
        fs::write(version_file, content)?;
        
        // Also save individual config files for easy access
        let version_dir = self.versions_dir.join(&version.id);
        fs::create_dir_all(&version_dir)?;
        
        for (original_path, file_version) in &version.config_files {
            let filename = original_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("config");
            let file_path = version_dir.join(filename);
            fs::write(file_path, &file_version.content)?;
        }
        
        Ok(())
    }
    
    /// Load a version from disk
    pub fn load_version(&self, version_id: &str) -> BackupResult<ConfigVersion> {
        let version_file = self.versions_dir.join(format!("{}.json", version_id));
        
        if !version_file.exists() {
            return Err(BackupError::BackupNotFound(version_id.to_string()));
        }
        
        let content = fs::read_to_string(version_file)?;
        let version: ConfigVersion = serde_json::from_str(&content)?;
        
        Ok(version)
    }
    
    /// Compare two versions and generate a diff
    pub fn compare_versions(
        &self,
        from_version_id: &str,
        to_version_id: &str,
    ) -> BackupResult<VersionDiff> {
        let from_version = self.load_version(from_version_id)?;
        let to_version = self.load_version(to_version_id)?;
        
        let mut file_changes = Vec::new();
        let mut summary = DiffSummary {
            files_added: 0,
            files_modified: 0,
            files_deleted: 0,
            lines_added: 0,
            lines_deleted: 0,
            lines_modified: 0,
            critical_changes: Vec::new(),
        };
        
        // Find all unique file paths
        let mut all_paths = std::collections::HashSet::new();
        all_paths.extend(from_version.config_files.keys().cloned());
        all_paths.extend(to_version.config_files.keys().cloned());
        
        for path in all_paths {
            let from_file = from_version.config_files.get(&path);
            let to_file = to_version.config_files.get(&path);
            
            match (from_file, to_file) {
                (None, Some(to_file)) => {
                    // File added
                    file_changes.push(FileChange {
                        file_path: path.clone(),
                        change_type: FileChangeType::Added,
                        old_content: None,
                        new_content: Some(to_file.content.clone()),
                        line_changes: self.calculate_line_changes("", &to_file.content),
                    });
                    summary.files_added += 1;
                }
                (Some(from_file), None) => {
                    // File deleted
                    file_changes.push(FileChange {
                        file_path: path.clone(),
                        change_type: FileChangeType::Deleted,
                        old_content: Some(from_file.content.clone()),
                        new_content: None,
                        line_changes: self.calculate_line_changes(&from_file.content, ""),
                    });
                    summary.files_deleted += 1;
                }
                (Some(from_file), Some(to_file)) => {
                    // File potentially modified
                    if from_file.checksum != to_file.checksum {
                        let line_changes = self.calculate_line_changes(&from_file.content, &to_file.content);
                        
                        file_changes.push(FileChange {
                            file_path: path.clone(),
                            change_type: FileChangeType::Modified,
                            old_content: Some(from_file.content.clone()),
                            new_content: Some(to_file.content.clone()),
                            line_changes: line_changes.clone(),
                        });
                        summary.files_modified += 1;
                        
                        // Count line changes
                        for line_change in &line_changes {
                            match line_change.change_type {
                                LineChangeType::Added => summary.lines_added += 1,
                                LineChangeType::Deleted => summary.lines_deleted += 1,
                                LineChangeType::Modified => summary.lines_modified += 1,
                                LineChangeType::Context => {}
                            }
                        }
                        
                        // Check for critical changes
                        if self.is_critical_change(&path, &from_file.content, &to_file.content) {
                            summary.critical_changes.push(
                                format!("Critical change in {}", path.display())
                            );
                        }
                    }
                }
                (None, None) => {
                    // This shouldn't happen
                }
            }
        }
        
        Ok(VersionDiff {
            from_version: from_version_id.to_string(),
            to_version: to_version_id.to_string(),
            file_changes,
            summary,
        })
    }
    
    /// Calculate line-by-line changes
    fn calculate_line_changes(&self, old_content: &str, new_content: &str) -> Vec<LineChange> {
        let old_lines: Vec<&str> = old_content.lines().collect();
        let new_lines: Vec<&str> = new_content.lines().collect();
        
        let mut changes = Vec::new();
        
        // Simple diff algorithm (LCS would be better for production)
        let mut old_idx = 0;
        let mut new_idx = 0;
        
        while old_idx < old_lines.len() || new_idx < new_lines.len() {
            if old_idx < old_lines.len() && new_idx < new_lines.len() {
                if old_lines[old_idx] == new_lines[new_idx] {
                    // Same line - context
                    changes.push(LineChange {
                        line_number: new_idx + 1,
                        change_type: LineChangeType::Context,
                        old_content: Some(old_lines[old_idx].to_string()),
                        new_content: Some(new_lines[new_idx].to_string()),
                    });
                    old_idx += 1;
                    new_idx += 1;
                } else {
                    // Lines differ - assume modification for now
                    changes.push(LineChange {
                        line_number: new_idx + 1,
                        change_type: LineChangeType::Modified,
                        old_content: Some(old_lines[old_idx].to_string()),
                        new_content: Some(new_lines[new_idx].to_string()),
                    });
                    old_idx += 1;
                    new_idx += 1;
                }
            } else if old_idx < old_lines.len() {
                // Old line deleted
                changes.push(LineChange {
                    line_number: old_idx + 1,
                    change_type: LineChangeType::Deleted,
                    old_content: Some(old_lines[old_idx].to_string()),
                    new_content: None,
                });
                old_idx += 1;
            } else {
                // New line added
                changes.push(LineChange {
                    line_number: new_idx + 1,
                    change_type: LineChangeType::Added,
                    old_content: None,
                    new_content: Some(new_lines[new_idx].to_string()),
                });
                new_idx += 1;
            }
        }
        
        changes
    }
    
    /// Check if a change is critical
    fn is_critical_change(&self, path: &Path, old_content: &str, new_content: &str) -> bool {
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        // Critical files
        if matches!(filename, 
            "passwd" | "shadow" | "sudoers" | "ssh_config" | "sshd_config" |
            "fstab" | "hosts" | "resolv.conf"
        ) {
            return true;
        }
        
        // Check for critical configuration changes
        let critical_keywords = [
            "password", "secret", "key", "token", "credential",
            "root", "admin", "sudo", "wheel",
            "firewall", "iptables", "ufw",
            "ssl", "tls", "certificate",
            "port", "listen", "bind",
        ];
        
        for keyword in &critical_keywords {
            let old_has = old_content.to_lowercase().contains(keyword);
            let new_has = new_content.to_lowercase().contains(keyword);
            
            if old_has != new_has {
                return true; // Security-related keyword added or removed
            }
        }
        
        false
    }
    
    /// Rollback to a specific version
    pub fn rollback_to_version(
        &self,
        version_id: &str,
        dry_run: bool,
    ) -> BackupResult<Vec<PathBuf>> {
        let version = self.load_version(version_id)?;
        
        if !version.is_rollback_safe && !dry_run {
            return Err(BackupError::RollbackError(
                format!("Version {} is not marked as rollback safe", version_id)
            ));
        }
        
        let mut restored_files = Vec::new();
        
        println!("Rolling back configurations to version: {}", version_id);
        
        for (file_path, file_version) in &version.config_files {
            if dry_run {
                println!("DRY RUN: Would restore {}", file_path.display());
                restored_files.push(file_path.clone());
            } else {
                // Create backup of current file
                if file_path.exists() {
                    let backup_path = file_path.with_extension(
                        format!("{}.backup.{}", 
                            file_path.extension().and_then(|e| e.to_str()).unwrap_or(""),
                            Utc::now().timestamp()
                        )
                    );
                    fs::copy(file_path, backup_path)?;
                }
                
                // Restore file content
                if let Some(parent) = file_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                
                fs::write(file_path, &file_version.content)?;
                
                // Restore permissions
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let permissions = std::fs::Permissions::from_mode(file_version.permissions);
                    fs::set_permissions(file_path, permissions)?;
                }
                
                restored_files.push(file_path.clone());
                println!("Restored: {}", file_path.display());
            }
        }
        
        if dry_run {
            println!("DRY RUN: Configuration rollback simulation completed");
        } else {
            println!("Configuration rollback completed: {} files restored", restored_files.len());
        }
        
        Ok(restored_files)
    }
    
    /// List all available versions
    pub fn list_versions(&self) -> BackupResult<Vec<ConfigVersion>> {
        let mut versions = Vec::new();
        
        if !self.versions_dir.exists() {
            return Ok(versions);
        }
        
        for entry in fs::read_dir(&self.versions_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(version) = self.load_version(
                    path.file_stem().and_then(|s| s.to_str()).unwrap_or("")
                ) {
                    versions.push(version);
                }
            }
        }
        
        // Sort by creation time (newest first)
        versions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        
        Ok(versions)
    }
    
    /// Add tags to a version
    pub fn tag_version(&self, version_id: &str, tags: Vec<String>) -> BackupResult<()> {
        let mut version = self.load_version(version_id)?;
        version.tags = tags;
        self.save_version(&version)?;
        Ok(())
    }
    
    /// Delete a version
    pub fn delete_version(&self, version_id: &str) -> BackupResult<()> {
        let version_file = self.versions_dir.join(format!("{}.json", version_id));
        let version_dir = self.versions_dir.join(version_id);
        
        if version_file.exists() {
            fs::remove_file(version_file)?;
        }
        
        if version_dir.exists() {
            fs::remove_dir_all(version_dir)?;
        }
        
        println!("Deleted version: {}", version_id);
        
        Ok(())
    }
    
    /// Cleanup old versions based on max_versions limit
    fn cleanup_old_versions(&self) -> BackupResult<()> {
        let mut versions = self.list_versions()?;
        
        if versions.len() > self.max_versions {
            // Sort by creation time (oldest first for deletion)
            versions.sort_by(|a, b| a.created_at.cmp(&b.created_at));
            
            let to_delete = versions.len() - self.max_versions;
            
            for version in &versions[..to_delete] {
                self.delete_version(&version.id)?;
            }
            
            println!("Cleaned up {} old configuration versions", to_delete);
        }
        
        Ok(())
    }
    
    /// Export version history
    pub fn export_history(&self, output_path: &Path) -> BackupResult<()> {
        let versions = self.list_versions()?;
        let content = serde_json::to_string_pretty(&versions)?;
        fs::write(output_path, content)?;
        
        println!("Version history exported to: {}", output_path.display());
        
        Ok(())
    }
}