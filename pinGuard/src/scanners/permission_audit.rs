use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
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
    acl_info: Option<AclInfo>,
    capabilities: Vec<String>,
    extended_attributes: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct AclInfo {
    has_acl: bool,
    user_permissions: HashMap<String, String>,
    group_permissions: HashMap<String, String>,
    mask: Option<String>,
    default_acl: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct CapabilityInfo {
    effective: HashSet<String>,
    permitted: HashSet<String>,
    inheritable: HashSet<String>,
    bounding: HashSet<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct SensitiveFile {
    path: String,
    risk_level: Severity,
    reason: String,
    contains_credentials: bool,
    contains_keys: bool,
    world_accessible: bool,
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

        tracing::info!("Starting enhanced permission audit scan...");

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

        // ACL kontrolü
        self.check_acl_permissions(&mut result)?;

        // Capability analizi
        self.analyze_file_capabilities(&mut result)?;

        // Sensitive dosya kontrolü
        self.check_sensitive_files(&mut result)?;

        // Extended attribute kontrolü
        self.check_extended_attributes(&mut result)?;

        // Sticky bit kontrolü
        self.check_sticky_bits(&mut result)?;

        // Umask analizi
        self.analyze_umask_settings(&mut result)?;

        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;

        tracing::info!(
            "Enhanced permission audit tamamlandı: {} bulgu",
            result.findings.len()
        );

        Ok(result)
    }
}

impl PermissionAudit {
    /// Check ACL permissions on critical files
    fn check_acl_permissions(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking ACL permissions...");

        let acl_sensitive_paths = vec![
            "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/group",
            "/etc/ssh", "/root", "/var/log", "/home"
        ];

        for path_str in acl_sensitive_paths {
            let path = Path::new(path_str);
            if !path.exists() {
                continue;
            }

            // Check if getfacl command is available
            if let Ok(output) = Command::new("getfacl")
                .arg(path_str)
                .output() {
                
                let acl_output = String::from_utf8_lossy(&output.stdout);
                
                // Look for extended ACLs (more than basic user/group/other)
                if acl_output.contains("user:") || acl_output.contains("group:") || acl_output.contains("mask:") {
                    let finding = Finding {
                        id: format!("PERM-ACL-{}", path_str.replace('/', "-")),
                        title: format!("Extended ACL found on: {}", path_str),
                        description: format!(
                            "File '{}' has extended ACL permissions. Review if these are necessary for security.",
                            path_str
                        ),
                        severity: Severity::Medium,
                        category: Category::Permission,
                        affected_item: path_str.to_string(),
                        current_value: Some("Extended ACL present".to_string()),
                        recommended_value: Some("Review ACL necessity".to_string()),
                        references: vec![
                            "https://wiki.archlinux.org/title/Access_Control_Lists".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: false,
                    };
                    result.add_finding(finding);
                }

                // Check for world-accessible ACL entries
                if acl_output.contains("other::") && acl_output.contains("rwx") {
                    let finding = Finding {
                        id: format!("PERM-ACL-WORLD-{}", path_str.replace('/', "-")),
                        title: format!("World-accessible ACL on: {}", path_str),
                        description: format!(
                            "File '{}' has world-accessible ACL permissions which may be a security risk.",
                            path_str
                        ),
                        severity: Severity::High,
                        category: Category::Permission,
                        affected_item: path_str.to_string(),
                        current_value: Some("World-accessible ACL".to_string()),
                        recommended_value: Some("Restrict ACL permissions".to_string()),
                        references: vec![
                            "https://www.redhat.com/sysadmin/linux-access-control-lists".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }
            }
        }

        Ok(())
    }

    /// Analyze file capabilities
    fn analyze_file_capabilities(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing file capabilities...");

        let search_dirs = vec!["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];

        for dir in search_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten().take(50) { // Limit to avoid performance issues
                    let path = entry.path();
                    
                    // Check if getcap command is available
                    if let Ok(output) = Command::new("getcap")
                        .arg(&path)
                        .output() {
                        
                        let cap_output = String::from_utf8_lossy(&output.stdout);
                        
                        if !cap_output.trim().is_empty() && cap_output.contains("=") {
                            // Parse capabilities
                            let caps = cap_output.trim().split_whitespace()
                                .filter(|s| s.contains("cap_"))
                                .collect::<Vec<_>>();

                            if !caps.is_empty() {
                                let severity = if caps.iter().any(|c| c.contains("cap_sys_admin") || 
                                                                     c.contains("cap_dac_override") ||
                                                                     c.contains("cap_setuid")) {
                                    Severity::High
                                } else {
                                    Severity::Medium
                                };

                                let finding = Finding {
                                    id: format!("PERM-CAP-{}", path.file_name().unwrap_or_default().to_string_lossy().replace('/', "-")),
                                    title: format!("File capabilities found: {}", path.display()),
                                    description: format!(
                                        "File '{}' has capabilities: {}. Review if these are necessary.",
                                        path.display(), caps.join(", ")
                                    ),
                                    severity,
                                    category: Category::Permission,
                                    affected_item: path.to_string_lossy().to_string(),
                                    current_value: Some(caps.join(", ")),
                                    recommended_value: Some("Review capability necessity".to_string()),
                                    references: vec![
                                        "https://man7.org/linux/man-pages/man7/capabilities.7.html".to_string(),
                                    ],
                                    cve_ids: vec![],
                                    fix_available: false,
                                };
                                result.add_finding(finding);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check for sensitive files with inappropriate permissions
    fn check_sensitive_files(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking sensitive files...");

        // Check SSH keys directly
        self.check_ssh_keys(result, "/home")?;
        self.check_ssh_keys(result, "/root")?;

        Ok(())
    }

    /// Check SSH key permissions specifically
    fn check_ssh_keys(&self, result: &mut ScanResult, base_path: &str) -> Result<(), ScanError> {
        let ssh_paths = vec![
            format!("{}/.ssh", base_path),
            "/etc/ssh".to_string(),
        ];

        for ssh_path in ssh_paths {
            if let Ok(entries) = fs::read_dir(&ssh_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let filename = path.file_name().unwrap_or_default().to_string_lossy();
                    
                    if filename.contains("_rsa") || filename.contains("_dsa") || filename.contains("_ecdsa") || filename.contains("_ed25519") {
                        if let Ok(metadata) = entry.metadata() {
                            let permissions = metadata.permissions();
                            let mode = permissions.mode() & 0o777;

                            // Private keys should be 600 or 400
                            if mode & 0o077 != 0 {
                                let finding = Finding {
                                    id: format!("PERM-SSH-KEY-{}", filename.replace('/', "-")),
                                    title: format!("Insecure SSH key permissions: {}", filename),
                                    description: format!(
                                        "SSH private key '{}' has inappropriate permissions ({}). Should be 600 or 400.",
                                        path.display(), format!("{:o}", mode)
                                    ),
                                    severity: Severity::High,
                                    category: Category::Permission,
                                    affected_item: path.to_string_lossy().to_string(),
                                    current_value: Some(format!("{:o}", mode)),
                                    recommended_value: Some("600".to_string()),
                                    references: vec![
                                        "https://www.ssh.com/academy/ssh/chmod".to_string(),
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
        }

        Ok(())
    }

    /// Check extended attributes
    fn check_extended_attributes(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking extended attributes...");

        let critical_files = vec![
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/bin/su", "/usr/bin/sudo"
        ];

        for file_path in critical_files {
            if Path::new(file_path).exists() {
                if let Ok(output) = Command::new("getfattr")
                    .arg("-d")
                    .arg(file_path)
                    .output() {
                    
                    let attr_output = String::from_utf8_lossy(&output.stdout);
                    
                    if !attr_output.trim().is_empty() {
                        let finding = Finding {
                            id: format!("PERM-XATTR-{}", file_path.replace('/', "-")),
                            title: format!("Extended attributes found: {}", file_path),
                            description: format!(
                                "File '{}' has extended attributes. Review for security implications.",
                                file_path
                            ),
                            severity: Severity::Low,
                            category: Category::Permission,
                            affected_item: file_path.to_string(),
                            current_value: Some("Extended attributes present".to_string()),
                            recommended_value: Some("Review attributes".to_string()),
                            references: vec![
                                "https://man7.org/linux/man-pages/man7/xattr.7.html".to_string(),
                            ],
                            cve_ids: vec![],
                            fix_available: false,
                        };
                        result.add_finding(finding);
                    }
                }
            }
        }

        Ok(())
    }

    /// Check sticky bits on directories
    fn check_sticky_bits(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking sticky bits...");

        let check_dirs = vec!["/tmp", "/var/tmp", "/dev/shm"];

        for dir_path in check_dirs {
            if let Ok(metadata) = fs::metadata(dir_path) {
                let permissions = metadata.permissions();
                let mode = permissions.mode();

                // Check if sticky bit is NOT set (should be set for these directories)
                if mode & 0o1000 == 0 {
                    let finding = Finding {
                        id: format!("PERM-STICKY-{}", dir_path.replace('/', "-")),
                        title: format!("Missing sticky bit: {}", dir_path),
                        description: format!(
                            "Directory '{}' should have sticky bit set for security. Current permissions: {:o}",
                            dir_path, mode & 0o7777
                        ),
                        severity: Severity::Medium,
                        category: Category::Permission,
                        affected_item: dir_path.to_string(),
                        current_value: Some(format!("{:o}", mode & 0o7777)),
                        recommended_value: Some("Add sticky bit (+t)".to_string()),
                        references: vec![
                            "https://www.redhat.com/sysadmin/suid-sgid-sticky-bit".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }
            }
        }

        Ok(())
    }

    /// Analyze umask settings
    fn analyze_umask_settings(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing umask settings...");

        // Check system-wide umask settings
        let umask_files = vec![
            "/etc/profile",
            "/etc/bash.bashrc",
            "/etc/login.defs",
            "/etc/pam.d/common-session",
        ];

        for file_path in umask_files {
            if let Ok(content) = fs::read_to_string(file_path) {
                // Look for umask settings
                for line in content.lines() {
                    if line.trim_start().starts_with("umask") && !line.trim_start().starts_with("#") {
                        if let Some(umask_value) = line.split_whitespace().nth(1) {
                            // Parse umask value
                            if let Ok(umask_val) = u32::from_str_radix(umask_value, 8) {
                                // Check if umask is too permissive (less than 022)
                                if umask_val < 0o022 {
                                    let finding = Finding {
                                        id: format!("PERM-UMASK-{}", file_path.replace('/', "-")),
                                        title: format!("Permissive umask setting: {}", file_path),
                                        description: format!(
                                            "File '{}' contains permissive umask setting: {}. This may create files with overly permissive permissions.",
                                            file_path, umask_value
                                        ),
                                        severity: Severity::Medium,
                                        category: Category::Permission,
                                        affected_item: file_path.to_string(),
                                        current_value: Some(umask_value.to_string()),
                                        recommended_value: Some("022 or more restrictive".to_string()),
                                        references: vec![
                                            "https://www.cyberciti.biz/tips/understanding-linux-unix-umask-value-usage.html".to_string(),
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
            }
        }

        Ok(())
    }

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
