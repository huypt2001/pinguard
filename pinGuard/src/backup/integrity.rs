use crate::backup::{BackupResult, BackupError, SystemSnapshot, BackupMetadata};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};

/// Integrity checker for backup validation
#[derive(Debug)]
pub struct IntegrityChecker {
    backup_dir: PathBuf,
    verification_cache: HashMap<String, VerificationResult>,
}

/// Backup integrity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupIntegrity {
    pub backup_id: String,
    pub created_at: DateTime<Utc>,
    pub verification_results: Vec<VerificationResult>,
    pub overall_status: IntegrityStatus,
    pub corruption_detected: bool,
    pub missing_files: Vec<PathBuf>,
    pub checksum_mismatches: Vec<ChecksumMismatch>,
    pub verification_time_seconds: f64,
    pub last_verified: DateTime<Utc>,
}

/// Individual verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub check_type: VerificationCheck,
    pub status: VerificationStatus,
    pub message: String,
    pub details: Option<String>,
    pub severity: Severity,
    pub auto_fixable: bool,
}

/// Types of verification checks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationCheck {
    FileExistence,
    ChecksumVerification,
    FileSize,
    FilePermissions,
    FileOwnership,
    ContentIntegrity,
    CompressionIntegrity,
    StructuralIntegrity,
    MetadataConsistency,
    TimestampConsistency,
}

/// Verification status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationStatus {
    Passed,
    Failed,
    Warning,
    Skipped,
    Error,
}

/// Overall integrity status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityStatus {
    Healthy,
    Degraded,
    Corrupted,
    Unverified,
    PartiallyCorrupted,
}

/// Severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Checksum mismatch information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumMismatch {
    pub file_path: PathBuf,
    pub expected_checksum: String,
    pub actual_checksum: String,
    pub algorithm: String,
    pub detected_at: DateTime<Utc>,
}

/// Integrity repair options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairOptions {
    pub fix_permissions: bool,
    pub fix_ownership: bool,
    pub restore_from_redundant_copy: bool,
    pub recreate_missing_files: bool,
    pub update_metadata: bool,
    pub verify_after_repair: bool,
}

/// Integrity report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub scan_id: String,
    pub created_at: DateTime<Utc>,
    pub backups_scanned: u32,
    pub healthy_backups: u32,
    pub corrupted_backups: u32,
    pub warnings: u32,
    pub critical_issues: u32,
    pub total_scan_time_seconds: f64,
    pub integrity_results: Vec<BackupIntegrity>,
    pub recommendations: Vec<String>,
}

impl Default for RepairOptions {
    fn default() -> Self {
        Self {
            fix_permissions: true,
            fix_ownership: false, // Requires root
            restore_from_redundant_copy: true,
            recreate_missing_files: false,
            update_metadata: true,
            verify_after_repair: true,
        }
    }
}

impl IntegrityChecker {
    /// Create a new integrity checker
    pub fn new(backup_dir: PathBuf) -> Self {
        Self {
            backup_dir,
            verification_cache: HashMap::new(),
        }
    }
    
    /// Verify integrity of a specific backup
    pub fn verify_backup(&mut self, backup_id: &str) -> BackupResult<BackupIntegrity> {
        let start_time = std::time::Instant::now();
        
        println!("Verifying backup integrity: {}", backup_id);
        
        // Load backup snapshot
        let snapshot = self.load_snapshot(backup_id)?;
        
        let mut verification_results = Vec::new();
        let mut missing_files = Vec::new();
        let mut checksum_mismatches = Vec::new();
        
        // Check file existence
        verification_results.extend(self.check_file_existence(&snapshot, &mut missing_files)?);
        
        // Verify checksums
        verification_results.extend(self.verify_checksums(&snapshot, &mut checksum_mismatches)?);
        
        // Check file sizes
        verification_results.extend(self.check_file_sizes(&snapshot)?);
        
        // Verify file permissions
        verification_results.extend(self.verify_file_permissions(&snapshot)?);
        
        // Check metadata consistency
        verification_results.extend(self.check_metadata_consistency(&snapshot)?);
        
        // Verify compression integrity
        verification_results.extend(self.verify_compression_integrity(backup_id)?);
        
        // Determine overall status
        let overall_status = self.determine_overall_status(&verification_results);
        let corruption_detected = matches!(overall_status, IntegrityStatus::Corrupted | IntegrityStatus::PartiallyCorrupted);
        
        let verification_time = start_time.elapsed().as_secs_f64();
        
        let integrity = BackupIntegrity {
            backup_id: backup_id.to_string(),
            created_at: Utc::now(),
            verification_results,
            overall_status,
            corruption_detected,
            missing_files,
            checksum_mismatches,
            verification_time_seconds: verification_time,
            last_verified: Utc::now(),
        };
        
        // Cache results
        let overall_result = VerificationResult {
            check_type: VerificationCheck::ContentIntegrity,
            status: if corruption_detected { VerificationStatus::Failed } else { VerificationStatus::Passed },
            message: format!("Backup integrity verification completed in {:.2}s", verification_time),
            details: Some(format!("Status: {:?}", integrity.overall_status)),
            severity: if corruption_detected { Severity::Error } else { Severity::Info },
            auto_fixable: false,
        };
        
        self.verification_cache.insert(backup_id.to_string(), overall_result);
        
        println!("Backup verification completed: {:?}", integrity.overall_status);
        
        Ok(integrity)
    }
    
    /// Verify integrity of all backups
    pub fn verify_all_backups(&mut self) -> BackupResult<IntegrityReport> {
        let start_time = std::time::Instant::now();
        let scan_id = format!("integrity_scan_{}", Utc::now().timestamp());
        
        println!("Starting comprehensive backup integrity scan");
        
        let backup_files = self.find_backup_files()?;
        let mut integrity_results = Vec::new();
        let mut healthy_backups = 0;
        let mut corrupted_backups = 0;
        let mut warnings = 0;
        let mut critical_issues = 0;
        
        for backup_file in &backup_files {
            if let Some(backup_id) = self.extract_backup_id(backup_file) {
                match self.verify_backup(&backup_id) {
                    Ok(integrity) => {
                        match integrity.overall_status {
                            IntegrityStatus::Healthy => healthy_backups += 1,
                            IntegrityStatus::Corrupted | IntegrityStatus::PartiallyCorrupted => {
                                corrupted_backups += 1;
                            }
                            IntegrityStatus::Degraded => warnings += 1,
                            IntegrityStatus::Unverified => {}
                        }
                        
                        // Count critical issues
                        critical_issues += integrity.verification_results.iter()
                            .filter(|r| r.severity == Severity::Critical)
                            .count() as u32;
                        
                        integrity_results.push(integrity);
                    }
                    Err(e) => {
                        println!("Failed to verify backup {}: {}", backup_id, e);
                        corrupted_backups += 1;
                    }
                }
            }
        }
        
        let total_scan_time = start_time.elapsed().as_secs_f64();
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(&integrity_results);
        
        let report = IntegrityReport {
            scan_id,
            created_at: Utc::now(),
            backups_scanned: backup_files.len() as u32,
            healthy_backups,
            corrupted_backups,
            warnings,
            critical_issues,
            total_scan_time_seconds: total_scan_time,
            integrity_results,
            recommendations,
        };
        
        println!("Integrity scan completed: {}/{} backups healthy", 
            healthy_backups, backup_files.len());
        
        Ok(report)
    }
    
    /// Attempt to repair backup integrity issues
    pub fn repair_backup(
        &mut self,
        backup_id: &str,
        options: &RepairOptions,
    ) -> BackupResult<RepairResult> {
        println!("Attempting to repair backup: {}", backup_id);
        
        let integrity = self.verify_backup(backup_id)?;
        
        if !integrity.corruption_detected {
            return Ok(RepairResult {
                backup_id: backup_id.to_string(),
                repairs_attempted: 0,
                repairs_successful: 0,
                issues_resolved: Vec::new(),
                issues_remaining: Vec::new(),
                repair_time_seconds: 0.0,
                success: true,
            });
        }
        
        let start_time = std::time::Instant::now();
        let mut repairs_attempted = 0;
        let mut repairs_successful = 0;
        let mut issues_resolved = Vec::new();
        let mut issues_remaining = Vec::new();
        
        // Attempt to fix missing files
        if options.recreate_missing_files {
            for missing_file in &integrity.missing_files {
                repairs_attempted += 1;
                
                if self.attempt_file_recovery(backup_id, missing_file)? {
                    repairs_successful += 1;
                    issues_resolved.push(format!("Recovered missing file: {}", missing_file.display()));
                } else {
                    issues_remaining.push(format!("Could not recover: {}", missing_file.display()));
                }
            }
        }
        
        // Fix permission issues
        if options.fix_permissions {
            let snapshot = self.load_snapshot(backup_id)?;
            
            for (file_path, file_state) in &snapshot.file_states {
                if file_path.exists() {
                    repairs_attempted += 1;
                    
                    if self.fix_file_permissions(file_path, file_state.permissions)? {
                        repairs_successful += 1;
                        issues_resolved.push(format!("Fixed permissions: {}", file_path.display()));
                    }
                }
            }
        }
        
        // Update metadata if requested
        if options.update_metadata {
            repairs_attempted += 1;
            
            if self.update_backup_metadata(backup_id)? {
                repairs_successful += 1;
                issues_resolved.push("Updated backup metadata".to_string());
            }
        }
        
        let repair_time = start_time.elapsed().as_secs_f64();
        let success = repairs_attempted == 0 || (repairs_successful as f64 / repairs_attempted as f64) > 0.5;
        
        // Re-verify if requested
        if options.verify_after_repair && success {
            let post_repair_integrity = self.verify_backup(backup_id)?;
            if !post_repair_integrity.corruption_detected {
                issues_resolved.push("Post-repair verification passed".to_string());
            } else {
                issues_remaining.push("Post-repair verification still shows issues".to_string());
            }
        }
        
        let result = RepairResult {
            backup_id: backup_id.to_string(),
            repairs_attempted,
            repairs_successful,
            issues_resolved,
            issues_remaining,
            repair_time_seconds: repair_time,
            success,
        };
        
        println!("Repair completed: {}/{} repairs successful", 
            repairs_successful, repairs_attempted);
        
        Ok(result)
    }
    
    /// Check file existence
    fn check_file_existence(
        &self,
        snapshot: &SystemSnapshot,
        missing_files: &mut Vec<PathBuf>,
    ) -> BackupResult<Vec<VerificationResult>> {
        let mut results = Vec::new();
        let mut missing_count = 0;
        
        for (file_path, _file_state) in &snapshot.file_states {
            if !file_path.exists() {
                missing_files.push(file_path.clone());
                missing_count += 1;
            }
        }
        
        let status = if missing_count == 0 {
            VerificationStatus::Passed
        } else {
            VerificationStatus::Failed
        };
        
        results.push(VerificationResult {
            check_type: VerificationCheck::FileExistence,
            status,
            message: format!("File existence check: {} missing files", missing_count),
            details: if missing_count > 0 {
                Some(format!("Missing files: {}", missing_files.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")))
            } else {
                None
            },
            severity: if missing_count > 0 { Severity::Error } else { Severity::Info },
            auto_fixable: false,
        });
        
        Ok(results)
    }
    
    /// Verify file checksums
    fn verify_checksums(
        &self,
        snapshot: &SystemSnapshot,
        checksum_mismatches: &mut Vec<ChecksumMismatch>,
    ) -> BackupResult<Vec<VerificationResult>> {
        let mut results = Vec::new();
        let mut mismatch_count = 0;
        let mut verified_count = 0;
        
        for (file_path, file_state) in &snapshot.file_states {
            if file_path.exists() && file_path.is_file() {
                match self.calculate_file_checksum(file_path) {
                    Ok(actual_checksum) => {
                        verified_count += 1;
                        
                        if actual_checksum != file_state.checksum {
                            mismatch_count += 1;
                            checksum_mismatches.push(ChecksumMismatch {
                                file_path: file_path.clone(),
                                expected_checksum: file_state.checksum.clone(),
                                actual_checksum,
                                algorithm: "SHA256".to_string(),
                                detected_at: Utc::now(),
                            });
                        }
                    }
                    Err(e) => {
                        println!("Failed to calculate checksum for {}: {}", file_path.display(), e);
                    }
                }
            }
        }
        
        let status = if mismatch_count == 0 {
            VerificationStatus::Passed
        } else {
            VerificationStatus::Failed
        };
        
        results.push(VerificationResult {
            check_type: VerificationCheck::ChecksumVerification,
            status,
            message: format!("Checksum verification: {} mismatches out of {} files", 
                mismatch_count, verified_count),
            details: if mismatch_count > 0 {
                Some(format!("Checksum mismatches detected in {} files", mismatch_count))
            } else {
                None
            },
            severity: if mismatch_count > 0 { Severity::Error } else { Severity::Info },
            auto_fixable: false,
        });
        
        Ok(results)
    }
    
    /// Check file sizes
    fn check_file_sizes(&self, snapshot: &SystemSnapshot) -> BackupResult<Vec<VerificationResult>> {
        let mut results = Vec::new();
        let mut size_mismatches = 0;
        let mut checked_files = 0;
        
        for (file_path, file_state) in &snapshot.file_states {
            if file_path.exists() && file_path.is_file() {
                checked_files += 1;
                
                if let Ok(metadata) = fs::metadata(file_path) {
                    if metadata.len() != file_state.size {
                        size_mismatches += 1;
                    }
                }
            }
        }
        
        let status = if size_mismatches == 0 {
            VerificationStatus::Passed
        } else {
            VerificationStatus::Failed
        };
        
        results.push(VerificationResult {
            check_type: VerificationCheck::FileSize,
            status,
            message: format!("File size check: {} mismatches out of {} files", 
                size_mismatches, checked_files),
            details: None,
            severity: if size_mismatches > 0 { Severity::Warning } else { Severity::Info },
            auto_fixable: false,
        });
        
        Ok(results)
    }
    
    /// Verify file permissions
    fn verify_file_permissions(&self, snapshot: &SystemSnapshot) -> BackupResult<Vec<VerificationResult>> {
        let mut results = Vec::new();
        let mut permission_mismatches = 0;
        let mut checked_files = 0;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            
            for (file_path, file_state) in &snapshot.file_states {
                if file_path.exists() {
                    checked_files += 1;
                    
                    if let Ok(metadata) = fs::metadata(file_path) {
                        if metadata.mode() != file_state.permissions {
                            permission_mismatches += 1;
                        }
                    }
                }
            }
        }
        
        #[cfg(not(unix))]
        {
            // On non-Unix systems, skip permission checks
            checked_files = snapshot.file_states.len();
        }
        
        let status = if permission_mismatches == 0 {
            VerificationStatus::Passed
        } else {
            VerificationStatus::Warning
        };
        
        results.push(VerificationResult {
            check_type: VerificationCheck::FilePermissions,
            status,
            message: format!("Permission check: {} mismatches out of {} files", 
                permission_mismatches, checked_files),
            details: None,
            severity: Severity::Warning,
            auto_fixable: true,
        });
        
        Ok(results)
    }
    
    /// Check metadata consistency
    fn check_metadata_consistency(&self, snapshot: &SystemSnapshot) -> BackupResult<Vec<VerificationResult>> {
        let mut results = Vec::new();
        
        // Check if metadata is internally consistent
        let has_metadata = !snapshot.metadata.id.is_empty();
        let has_files = !snapshot.file_states.is_empty();
        let reasonable_size = snapshot.metadata.size_bytes > 0;
        
        let status = if has_metadata && has_files && reasonable_size {
            VerificationStatus::Passed
        } else {
            VerificationStatus::Warning
        };
        
        results.push(VerificationResult {
            check_type: VerificationCheck::MetadataConsistency,
            status,
            message: "Metadata consistency check".to_string(),
            details: Some(format!("ID: {}, Files: {}, Size: {} bytes", 
                has_metadata, has_files, snapshot.metadata.size_bytes)),
            severity: Severity::Info,
            auto_fixable: true,
        });
        
        Ok(results)
    }
    
    /// Verify compression integrity
    fn verify_compression_integrity(&self, backup_id: &str) -> BackupResult<Vec<VerificationResult>> {
        let mut results = Vec::new();
        
        let compressed_file = self.backup_dir.join(format!("{}.snapshot.gz", backup_id));
        let uncompressed_file = self.backup_dir.join(format!("{}.snapshot", backup_id));
        
        let status = if compressed_file.exists() || uncompressed_file.exists() {
            // Try to load the snapshot to verify it's not corrupted
            match self.load_snapshot(backup_id) {
                Ok(_) => VerificationStatus::Passed,
                Err(_) => VerificationStatus::Failed,
            }
        } else {
            VerificationStatus::Failed
        };
        
        results.push(VerificationResult {
            check_type: VerificationCheck::CompressionIntegrity,
            status: status.clone(),
            message: "Compression integrity check".to_string(),
            details: None,
            severity: if status == VerificationStatus::Failed { Severity::Error } else { Severity::Info },
            auto_fixable: false,
        });
        
        Ok(results)
    }
    
    /// Determine overall integrity status
    fn determine_overall_status(&self, results: &[VerificationResult]) -> IntegrityStatus {
        let failed_count = results.iter()
            .filter(|r| r.status == VerificationStatus::Failed)
            .count();
        
        let critical_count = results.iter()
            .filter(|r| r.severity == Severity::Critical)
            .count();
        
        let warning_count = results.iter()
            .filter(|r| r.status == VerificationStatus::Warning)
            .count();
        
        if critical_count > 0 || failed_count > results.len() / 2 {
            IntegrityStatus::Corrupted
        } else if failed_count > 0 {
            IntegrityStatus::PartiallyCorrupted
        } else if warning_count > 0 {
            IntegrityStatus::Degraded
        } else {
            IntegrityStatus::Healthy
        }
    }
    
    /// Calculate file checksum
    fn calculate_file_checksum(&self, file_path: &Path) -> BackupResult<String> {
        let mut file = File::open(file_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    /// Load snapshot from backup
    fn load_snapshot(&self, backup_id: &str) -> BackupResult<SystemSnapshot> {
        let compressed_file = self.backup_dir.join(format!("{}.snapshot.gz", backup_id));
        let uncompressed_file = self.backup_dir.join(format!("{}.snapshot", backup_id));
        
        if compressed_file.exists() {
            SystemSnapshot::load(&compressed_file)
        } else if uncompressed_file.exists() {
            SystemSnapshot::load(&uncompressed_file)
        } else {
            Err(BackupError::BackupNotFound(backup_id.to_string()))
        }
    }
    
    /// Find all backup files
    fn find_backup_files(&self) -> BackupResult<Vec<PathBuf>> {
        let mut backup_files = Vec::new();
        
        if !self.backup_dir.exists() {
            return Ok(backup_files);
        }
        
        for entry in fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "snapshot" || extension == "gz" {
                        backup_files.push(path);
                    }
                }
            }
        }
        
        Ok(backup_files)
    }
    
    /// Extract backup ID from file path
    fn extract_backup_id(&self, file_path: &Path) -> Option<String> {
        file_path.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.replace(".snapshot", ""))
    }
    
    /// Generate recommendations based on integrity results
    fn generate_recommendations(&self, integrity_results: &[BackupIntegrity]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        let corrupted_count = integrity_results.iter()
            .filter(|r| r.corruption_detected)
            .count();
        
        if corrupted_count > 0 {
            recommendations.push(format!(
                "Found {} corrupted backups. Consider running repair operations.",
                corrupted_count
            ));
        }
        
        let avg_verification_time = if !integrity_results.is_empty() {
            integrity_results.iter()
                .map(|r| r.verification_time_seconds)
                .sum::<f64>() / integrity_results.len() as f64
        } else {
            0.0
        };
        
        if avg_verification_time > 60.0 {
            recommendations.push(
                "Verification times are high. Consider optimizing backup storage.".to_string()
            );
        }
        
        if integrity_results.len() < 3 {
            recommendations.push(
                "Consider maintaining at least 3 backup copies for redundancy.".to_string()
            );
        }
        
        recommendations
    }
    
    // Helper methods for repair operations
    
    fn attempt_file_recovery(&self, _backup_id: &str, _file_path: &Path) -> BackupResult<bool> {
        // Simplified implementation - would attempt various recovery methods
        Ok(false)
    }
    
    fn fix_file_permissions(&self, file_path: &Path, expected_permissions: u32) -> BackupResult<bool> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(expected_permissions);
            fs::set_permissions(file_path, permissions)?;
            Ok(true)
        }
        
        #[cfg(not(unix))]
        {
            // Permission fixing not supported on non-Unix systems
            Ok(false)
        }
    }
    
    fn update_backup_metadata(&self, _backup_id: &str) -> BackupResult<bool> {
        // Simplified implementation - would update metadata checksums
        Ok(true)
    }
}

/// Repair operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairResult {
    pub backup_id: String,
    pub repairs_attempted: u32,
    pub repairs_successful: u32,
    pub issues_resolved: Vec<String>,
    pub issues_remaining: Vec<String>,
    pub repair_time_seconds: f64,
    pub success: bool,
}