use super::{Fixer, FixResult, FixError, FixPlan, FixStatus, RiskLevel, execute_command, create_backup};
use crate::scanners::Finding;
use std::time::{Duration, Instant};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct PermissionFixer;

impl Fixer for PermissionFixer {
    fn name(&self) -> &'static str {
        "Permission Fixer"
    }

    fn can_fix(&self, finding: &Finding) -> bool {
        // Permission ile ilgili bulguları düzeltebilir
        finding.id.starts_with("PERM-") || 
        finding.id.starts_with("SUID-") ||
        finding.id.starts_with("SGID-") ||
        finding.title.contains("permission") ||
        finding.title.contains("writable") ||
        finding.title.contains("SUID") ||
        finding.title.contains("SGID")
    }

    fn fix(&self, finding: &Finding, _config: &crate::core::config::Config) -> Result<FixResult, FixError> {
        let start_time = Instant::now();
        let mut result = FixResult::new(finding.id.clone(), self.name().to_string());

        tracing::info!("Permission fix başlatılıyor: {}", finding.title);

        // Finding türüne göre uygun düzeltme yöntemini seç
        if finding.id.starts_with("PERM-WORLD-WRITABLE") {
            self.fix_world_writable_file(finding, &mut result)?;
        } else if finding.id.starts_with("PERM-SUID") {
            self.fix_risky_suid_file(finding, &mut result)?;
        } else if finding.id.starts_with("PERM-SGID") {
            self.fix_risky_sgid_file(finding, &mut result)?;
        } else if finding.id.starts_with("PERM-") {
            self.fix_generic_permission(finding, &mut result)?;
        } else {
            return Err(FixError::UnsupportedFix(format!("Unsupported permission fix: {}", finding.id)));
        }

        result = result.set_duration(start_time);
        tracing::info!("Permission fix tamamlandı: {}", result.message);
        
        Ok(result)
    }

    fn dry_run(&self, finding: &Finding) -> Result<FixPlan, FixError> {
        let mut plan = FixPlan::new(
            finding.id.clone(),
            self.name().to_string(),
            format!("Fix file permissions: {}", finding.title)
        );

        let file_path = self.extract_file_path(&finding.affected_item)?;
        
        plan = plan
            .requires_backup()
            .add_file(file_path.clone())
            .set_duration(Duration::from_secs(30));

        if finding.id.starts_with("PERM-WORLD-WRITABLE") {
            plan = plan
                .add_command(format!("chmod o-w '{}'", file_path))
                .set_risk(RiskLevel::Low);
        } else if finding.id.starts_with("PERM-SUID") {
            plan = plan
                .add_command(format!("chmod u-s '{}'", file_path))
                .set_risk(RiskLevel::Medium);
        } else if finding.id.starts_with("PERM-SGID") {
            plan = plan
                .add_command(format!("chmod g-s '{}'", file_path))
                .set_risk(RiskLevel::Medium);
        } else {
            plan = plan
                .add_command(format!("chmod 644 '{}'", file_path))
                .set_risk(RiskLevel::Low);
        }

        Ok(plan)
    }
}

impl PermissionFixer {
    /// World-writable dosyayı düzelt
    fn fix_world_writable_file(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let file_path = self.extract_file_path(&finding.affected_item)?;
        
        tracing::info!("World-writable dosya düzeltiliyor: {}", file_path);

        // Backup oluştur
        if Path::new(&file_path).is_file() {
            let backup_path = create_backup(&file_path)?;
            result.backup_created = Some(backup_path);
        }

        // Mevcut izinleri al
        let metadata = fs::metadata(&file_path)
            .map_err(|e| FixError::FileError(format!("Cannot read file metadata: {}", e)))?;
        
        let current_mode = metadata.permissions().mode();
        tracing::info!("Mevcut izinler: {:o}", current_mode);

        // World write iznini kaldır (o-w)
        let new_mode = current_mode & !0o002;
        tracing::info!("Yeni izinler: {:o}", new_mode);

        // İzinleri uygula
        let _output = execute_command("chmod", &[&format!("{:o}", new_mode), &file_path])?;
        result.commands_executed.push(format!("chmod {:o} '{}'", new_mode, file_path));
        result.files_modified.push(file_path.clone());

        result.status = FixStatus::Success;
        result.message = format!("Removed world-write permission from: {}", file_path);

        Ok(())
    }

    /// Riskli SUID dosyasını düzelt
    fn fix_risky_suid_file(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let file_path = self.extract_file_path(&finding.affected_item)?;
        
        tracing::info!("Riskli SUID dosyası düzeltiliyor: {}", file_path);

        // Bu dosyanın gerçekten SUID'a ihtiyacı var mı kontrol et
        if self.is_legitimate_suid_file(&file_path) {
            result.status = FixStatus::Skipped;
            result.message = format!("SUID file appears legitimate, skipping: {}", file_path);
            return Ok(());
        }

        // Backup oluştur
        let backup_path = create_backup(&file_path)?;
        result.backup_created = Some(backup_path);

        // SUID bitini kaldır (u-s)
        let _output = execute_command("chmod", &["u-s", &file_path])?;
        result.commands_executed.push(format!("chmod u-s '{}'", file_path));
        result.files_modified.push(file_path.clone());

        result.status = FixStatus::Success;
        result.message = format!("Removed SUID bit from: {}", file_path);

        Ok(())
    }

    /// Riskli SGID dosyasını düzelt
    fn fix_risky_sgid_file(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let file_path = self.extract_file_path(&finding.affected_item)?;
        
        tracing::info!("Riskli SGID dosyası düzeltiliyor: {}", file_path);

        // Bu dosyanın gerçekten SGID'a ihtiyacı var mı kontrol et
        if self.is_legitimate_sgid_file(&file_path) {
            result.status = FixStatus::Skipped;
            result.message = format!("SGID file appears legitimate, skipping: {}", file_path);
            return Ok(());
        }

        // Backup oluştur
        let backup_path = create_backup(&file_path)?;
        result.backup_created = Some(backup_path);

        // SGID bitini kaldır (g-s)
        let _output = execute_command("chmod", &["g-s", &file_path])?;
        result.commands_executed.push(format!("chmod g-s '{}'", file_path));
        result.files_modified.push(file_path.clone());

        result.status = FixStatus::Success;
        result.message = format!("Removed SGID bit from: {}", file_path);

        Ok(())
    }

    /// Genel permission düzeltmesi
    fn fix_generic_permission(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let file_path = self.extract_file_path(&finding.affected_item)?;
        
        tracing::info!("Genel permission düzeltmesi: {}", file_path);

        // Backup oluştur
        if Path::new(&file_path).is_file() {
            let backup_path = create_backup(&file_path)?;
            result.backup_created = Some(backup_path);
        }

        // Dosya türüne göre uygun izinleri belirle
        let new_permissions = if Path::new(&file_path).is_dir() {
            "755" // Klasörler için
        } else if self.is_executable_file(&file_path)? {
            "755" // Executable dosyalar için
        } else {
            "644" // Normal dosyalar için
        };

        // İzinleri uygula
        let _output = execute_command("chmod", &[new_permissions, &file_path])?;
        result.commands_executed.push(format!("chmod {} '{}'", new_permissions, file_path));
        result.files_modified.push(file_path.clone());

        result.status = FixStatus::Success;
        result.message = format!("Set secure permissions ({}) on: {}", new_permissions, file_path);

        Ok(())
    }

    /// Dosya yolunu bulgudaki affected_item'dan çıkar
    fn extract_file_path(&self, affected_item: &str) -> Result<String, FixError> {
        // "File: /path/to/file" formatından yolu çıkar
        if affected_item.starts_with("File: ") {
            return Ok(affected_item.replace("File: ", "").trim().to_string());
        }

        // "Path: /path/to/file" formatından yolu çıkar
        if affected_item.starts_with("Path: ") {
            return Ok(affected_item.replace("Path: ", "").trim().to_string());
        }

        // Doğrudan dosya yolu ise
        if affected_item.starts_with("/") {
            return Ok(affected_item.trim().to_string());
        }

        Err(FixError::ConfigError(format!("Cannot extract file path from: {}", affected_item)))
    }

    /// Dosyanın legitimate SUID dosyası olup olmadığını kontrol et
    fn is_legitimate_suid_file(&self, file_path: &str) -> bool {
        let legitimate_suid_files = vec![
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/passwd",
            "/usr/bin/gpasswd",
            "/usr/bin/newgrp",
            "/usr/bin/chsh",
            "/usr/bin/chfn",
            "/usr/lib/openssh/ssh-keysign",
            "/usr/bin/mount",
            "/usr/bin/umount",
            "/usr/bin/ping",
            "/usr/bin/ping6",
        ];

        legitimate_suid_files.iter().any(|&path| file_path == path)
    }

    /// Dosyanın legitimate SGID dosyası olup olmadığını kontrol et
    fn is_legitimate_sgid_file(&self, file_path: &str) -> bool {
        let legitimate_sgid_files = vec![
            "/usr/bin/wall",
            "/usr/bin/write",
            "/usr/bin/locate",
            "/usr/bin/mlocate",
            "/var/mail",
            "/var/spool/mail",
        ];

        legitimate_sgid_files.iter().any(|&path| file_path.starts_with(path))
    }

    /// Dosyanın executable olup olmadığını kontrol et
    fn is_executable_file(&self, file_path: &str) -> Result<bool, FixError> {
        let metadata = fs::metadata(file_path)
            .map_err(|e| FixError::FileError(format!("Cannot read file metadata: {}", e)))?;
        
        let mode = metadata.permissions().mode();
        Ok((mode & 0o111) != 0)
    }

    /// Kritik sistem dosyalarının izinlerini toplu olarak düzelt
    pub fn fix_system_file_permissions(&self) -> Result<Vec<FixResult>, FixError> {
        let mut results = Vec::new();

        let critical_files = vec![
            ("/etc/passwd", 0o644),
            ("/etc/shadow", 0o600),
            ("/etc/group", 0o644),
            ("/etc/gshadow", 0o600),
            ("/etc/ssh/sshd_config", 0o600),
            ("/etc/sudoers", 0o440),
            ("/root", 0o700),
            ("/home", 0o755),
        ];

        for (file_path, expected_mode) in critical_files {
            if Path::new(file_path).exists() {
                match self.fix_file_permission(file_path, expected_mode) {
                    Ok(result) => results.push(result),
                    Err(e) => tracing::warn!("Failed to fix permissions for {}: {}", file_path, e),
                }
            }
        }

        Ok(results)
    }

    /// Belirli bir dosyanın izinlerini düzelt
    fn fix_file_permission(&self, file_path: &str, expected_mode: u32) -> Result<FixResult, FixError> {
        let start_time = Instant::now();
        let mut result = FixResult::new(
            format!("PERM-SYSTEM-{}", file_path.replace("/", "_")),
            self.name().to_string()
        );

        let metadata = fs::metadata(file_path)
            .map_err(|e| FixError::FileError(format!("Cannot read metadata for {}: {}", file_path, e)))?;

        let current_mode = metadata.permissions().mode() & 0o777;
        
        if current_mode != expected_mode {
            tracing::info!("Fixing permissions for {}: {:o} -> {:o}", file_path, current_mode, expected_mode);

            // Backup oluştur
            if Path::new(file_path).is_file() {
                let backup_path = create_backup(file_path)?;
                result.backup_created = Some(backup_path);
            }

            // İzinleri düzelt
            let _output = execute_command("chmod", &[&format!("{:o}", expected_mode), file_path])?;
            result.commands_executed.push(format!("chmod {:o} '{}'", expected_mode, file_path));
            result.files_modified.push(file_path.to_string());

            result.status = FixStatus::Success;
            result.message = format!("Fixed permissions for {}: {:o} -> {:o}", file_path, current_mode, expected_mode);
        } else {
            result.status = FixStatus::Skipped;
            result.message = format!("Permissions already correct for {}: {:o}", file_path, current_mode);
        }

        result.duration = start_time.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Tüm world-writable dosyaları bul ve düzelt
    pub fn fix_all_world_writable_files(&self, base_paths: &[&str]) -> Result<Vec<FixResult>, FixError> {
        let mut results = Vec::new();

        for base_path in base_paths {
            if !Path::new(base_path).exists() {
                continue;
            }

            let output = execute_command("find", &[
                base_path,
                "-type", "f",
                "-perm", "-002",
                "-not", "-path", "*/proc/*",
                "-not", "-path", "*/sys/*",
                "-not", "-path", "*/dev/*"
            ])?;

            for line in output.lines() {
                let file_path = line.trim();
                if !file_path.is_empty() {
                    match self.fix_world_writable_single_file(file_path) {
                        Ok(result) => results.push(result),
                        Err(e) => tracing::warn!("Failed to fix world-writable file {}: {}", file_path, e),
                    }
                }
            }
        }

        Ok(results)
    }

    /// Tek bir world-writable dosyayı düzelt
    fn fix_world_writable_single_file(&self, file_path: &str) -> Result<FixResult, FixError> {
        let start_time = Instant::now();
        let mut result = FixResult::new(
            format!("PERM-WORLD-WRITABLE-{}", file_path.replace("/", "_")),
            self.name().to_string()
        );

        let metadata = fs::metadata(file_path)
            .map_err(|e| FixError::FileError(format!("Cannot read metadata for {}: {}", file_path, e)))?;

        let current_mode = metadata.permissions().mode();
        let new_mode = current_mode & !0o002; // Remove world write bit

        if current_mode != new_mode {
            // Backup oluştur
            let backup_path = create_backup(file_path)?;
            result.backup_created = Some(backup_path);

            // İzinleri düzelt
            let _output = execute_command("chmod", &[&format!("{:o}", new_mode), file_path])?;
            result.commands_executed.push(format!("chmod {:o} '{}'", new_mode, file_path));
            result.files_modified.push(file_path.to_string());

            result.status = FixStatus::Success;
            result.message = format!("Removed world-write permission from: {}", file_path);
        } else {
            result.status = FixStatus::Skipped;
            result.message = format!("File already secure: {}", file_path);
        }

        result.duration = start_time.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Tüm kritik izinleri düzelt
    pub fn fix_all_critical_permissions(&self) -> Result<Vec<FixResult>, FixError> {
        let mut results = Vec::new();

        // Kritik system dizinleri
        let critical_paths = vec![
            "/etc", "/boot", "/usr/bin", "/usr/sbin", "/bin", "/sbin"
        ];

        // World-writable dosyaları düzelt
        match self.fix_all_world_writable_files(&critical_paths) {
            Ok(mut world_writable_results) => results.append(&mut world_writable_results),
            Err(e) => tracing::error!("Failed to fix world-writable files: {}", e),
        }

        Ok(results)
    }
}