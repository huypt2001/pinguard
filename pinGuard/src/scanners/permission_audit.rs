use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Instant;

pub struct PermissionAudit;

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct FilePermission {
    path: String,
    mode: u32,
    owner: String,
    group: String,
    size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PermissionRule {
    path: String,
    expected_mode: u32,
    max_mode: Option<u32>,
    expected_owner: Option<String>,
    description: String,
    severity: Severity,
}

impl Scanner for PermissionAudit {
    fn name(&self) -> &'static str {
        "permission_audit"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"permission_audit".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Permission Audit".to_string());

        tracing::info!("Starting permission audit scan...");

        // Kritik dosya ve dizinlerin listesi
        let critical_paths = self.get_critical_paths();
        result.set_items_scanned(critical_paths.len() as u32);

        // Her bir kritik yolu kontrol et
        for rule in &critical_paths {
            if let Err(e) = self.check_path_permissions(rule, &mut result) {
                tracing::warn!("Permission check failed for {}: {}", rule.path, e);
            }
        }

        // Dünya yazılabilir dosyaları bul
        self.find_world_writable_files(&mut result)?;

        // SUID/SGID dosyaları kontrol et
        self.check_suid_sgid_files(&mut result)?;

        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;

        tracing::info!(
            "Permission audit tamamlandı: {} bulgu",
            result.findings.len()
        );

        Ok(result)
    }
}

impl PermissionAudit {
    /// Return list of critical files and directories
    fn get_critical_paths(&self) -> Vec<PermissionRule> {
        vec![
            // System dizinler
            PermissionRule {
                path: "/etc".to_string(),
                expected_mode: 0o755,
                max_mode: Some(0o755),
                expected_owner: Some("root".to_string()),
                description: "System configuration directory".to_string(),
                severity: Severity::High,
            },
            PermissionRule {
                path: "/etc/passwd".to_string(),
                expected_mode: 0o644,
                max_mode: Some(0o644),
                expected_owner: Some("root".to_string()),
                description: "User account information".to_string(),
                severity: Severity::Critical,
            },
            PermissionRule {
                path: "/etc/shadow".to_string(),
                expected_mode: 0o640,
                max_mode: Some(0o640),
                expected_owner: Some("root".to_string()),
                description: "User password hashes".to_string(),
                severity: Severity::Critical,
            },
            PermissionRule {
                path: "/etc/gshadow".to_string(),
                expected_mode: 0o640,
                max_mode: Some(0o640),
                expected_owner: Some("root".to_string()),
                description: "Group password hashes".to_string(),
                severity: Severity::High,
            },
            PermissionRule {
                path: "/etc/group".to_string(),
                expected_mode: 0o644,
                max_mode: Some(0o644),
                expected_owner: Some("root".to_string()),
                description: "Group information".to_string(),
                severity: Severity::High,
            },
            PermissionRule {
                path: "/etc/hosts".to_string(),
                expected_mode: 0o644,
                max_mode: Some(0o644),
                expected_owner: Some("root".to_string()),
                description: "Host name resolution file".to_string(),
                severity: Severity::Medium,
            },
            PermissionRule {
                path: "/etc/ssh/sshd_config".to_string(),
                expected_mode: 0o600,
                max_mode: Some(0o644),
                expected_owner: Some("root".to_string()),
                description: "SSH daemon configuration".to_string(),
                severity: Severity::High,
            },
            PermissionRule {
                path: "/etc/sudoers".to_string(),
                expected_mode: 0o440,
                max_mode: Some(0o440),
                expected_owner: Some("root".to_string()),
                description: "Sudo configuration".to_string(),
                severity: Severity::Critical,
            },
            // Boot dizini
            PermissionRule {
                path: "/boot".to_string(),
                expected_mode: 0o755,
                max_mode: Some(0o755),
                expected_owner: Some("root".to_string()),
                description: "Boot files directory".to_string(),
                severity: Severity::High,
            },
            // Log dizinleri
            PermissionRule {
                path: "/var/log".to_string(),
                expected_mode: 0o755,
                max_mode: Some(0o755),
                expected_owner: Some("root".to_string()),
                description: "System log directory".to_string(),
                severity: Severity::Medium,
            },
            // Root home
            PermissionRule {
                path: "/root".to_string(),
                expected_mode: 0o700,
                max_mode: Some(0o700),
                expected_owner: Some("root".to_string()),
                description: "Root user home directory".to_string(),
                severity: Severity::Critical,
            },
        ]
    }

    /// Belirli bir yolun izinlerini kontrol et
    fn check_path_permissions(
        &self,
        rule: &PermissionRule,
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        let path = Path::new(&rule.path);

        if !path.exists() {
            // Dosya yoksa skip et
            return Ok(());
        }

        let metadata = fs::metadata(path).map_err(ScanError::IoError)?;

        let permissions = metadata.permissions();
        let mode = permissions.mode() & 0o777; // Sadece permission bitlerini al

        // İzin kontrolü
        if let Some(max_mode) = rule.max_mode {
            if mode > max_mode {
                let finding = Finding {
                    id: format!("PERM-{}", rule.path.replace('/', "-")),
                    title: format!("Unsafe file permissions: {}", rule.path),
                    description: format!(
                        "File '{}' has overly permissive permissions. Current: {:o}, Expected: {:o} or stricter. {}",
                        rule.path, mode, rule.expected_mode, rule.description
                    ),
                    severity: rule.severity.clone(),
                    category: Category::Permission,
                    affected_item: rule.path.clone(),
                    current_value: Some(format!("{:o}", mode)),
                    recommended_value: Some(format!("{:o}", rule.expected_mode)),
                    references: vec![
                        "https://wiki.archlinux.org/title/File_permissions_and_attributes".to_string(),
                        "https://www.cyberciti.biz/tips/understanding-linux-unix-umask-value-usage.html".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        // Dünya yazılabilir kontrolü
        if mode & 0o002 != 0 && rule.severity == Severity::Critical {
            let finding = Finding {
                id: format!("PERM-WORLD-WRITE-{}", rule.path.replace('/', "-")),
                title: format!("World-writable critical file: {}", rule.path),
                description: format!(
                    "Critical file '{}' is world-writable. This poses a serious security risk.",
                    rule.path
                ),
                severity: Severity::Critical,
                category: Category::Permission,
                affected_item: rule.path.clone(),
                current_value: Some(format!("{:o}", mode)),
                recommended_value: Some("Remove world-write permission".to_string()),
                references: vec!["https://www.cisecurity.org/controls/".to_string()],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        Ok(())
    }

    /// Find world-writable files
    fn find_world_writable_files(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking world-writable files...");

        let suspicious_dirs = vec!["/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64"];

        for dir in suspicious_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        let permissions = metadata.permissions();
                        let mode = permissions.mode() & 0o777;

                        // Dünya yazılabilir mi?
                        if mode & 0o002 != 0 {
                            let path = entry.path();
                            let finding = Finding {
                                id: format!("PERM-WORLD-{}", path.to_string_lossy().replace('/', "-")),
                                title: "World-writable file in system directory".to_string(),
                                description: format!(
                                    "File '{}' in system directory is world-writable (permissions: {:o})",
                                    path.display(), mode
                                ),
                                severity: Severity::High,
                                category: Category::Permission,
                                affected_item: path.to_string_lossy().to_string(),
                                current_value: Some(format!("{:o}", mode)),
                                recommended_value: Some("Remove world-write permission".to_string()),
                                references: vec![
                                    "https://www.cisecurity.org/controls/".to_string(),
                                ],
                                cve_ids: vec![],
                                fix_available: true,
                            };
                            result.add_finding(finding);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check SUID/SGID files
    fn check_suid_sgid_files(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking SUID/SGID files...");

        let search_dirs = vec!["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

        for dir in search_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        let permissions = metadata.permissions();
                        let mode = permissions.mode();

                        // SUID bit kontrol et
                        if mode & 0o4000 != 0 {
                            let path = entry.path();
                            let finding = Finding {
                                id: format!("PERM-SUID-{}", path.file_name().unwrap_or_default().to_string_lossy().replace('/', "-")),
                                title: "SUID executable found".to_string(),
                                description: format!(
                                    "File '{}' has SUID bit set. Review if this is necessary for security.",
                                    path.display()
                                ),
                                severity: Severity::Medium,
                                category: Category::Permission,
                                affected_item: path.to_string_lossy().to_string(),
                                current_value: Some(format!("{:o}", mode & 0o7777)),
                                recommended_value: Some("Review SUID necessity".to_string()),
                                references: vec![
                                    "https://www.redhat.com/sysadmin/suid-sgid-sticky-bit".to_string(),
                                ],
                                cve_ids: vec![],
                                fix_available: false, // Manuel review gerekli
                            };
                            result.add_finding(finding);
                        }

                        // SGID bit kontrol et
                        if mode & 0o2000 != 0 {
                            let path = entry.path();
                            let finding = Finding {
                                id: format!("PERM-SGID-{}", path.file_name().unwrap_or_default().to_string_lossy().replace('/', "-")),
                                title: "SGID executable found".to_string(),
                                description: format!(
                                    "File '{}' has SGID bit set. Review if this is necessary for security.",
                                    path.display()
                                ),
                                severity: Severity::Low,
                                category: Category::Permission,
                                affected_item: path.to_string_lossy().to_string(),
                                current_value: Some(format!("{:o}", mode & 0o7777)),
                                recommended_value: Some("Review SGID necessity".to_string()),
                                references: vec![
                                    "https://www.redhat.com/sysadmin/suid-sgid-sticky-bit".to_string(),
                                ],
                                cve_ids: vec![],
                                fix_available: false, // Manuel review gerekli
                            };
                            result.add_finding(finding);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
