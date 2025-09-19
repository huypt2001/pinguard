use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Instant;
use std::process::Command;
use std::collections::{HashMap, HashSet};

pub struct UserAudit;

#[derive(Debug, Serialize, Deserialize)]
struct UserAccount {
    username: String,
    uid: u32,
    gid: u32,
    home_dir: String,
    shell: String,
    password_status: PasswordStatus,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct GroupInfo {
    name: String,
    gid: u32,
    members: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
enum PasswordStatus {
    Locked,
    Empty,
    Set,
    Disabled,
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordPolicy {
    min_length: Option<u32>,
    max_age: Option<u32>,
    min_age: Option<u32>,
    warn_age: Option<u32>,
    require_uppercase: bool,
    require_lowercase: bool,
    require_digits: bool,
    require_special: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SudoConfiguration {
    user: String,
    commands: Vec<String>,
    nopasswd: bool,
    timestamp_timeout: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserSession {
    username: String,
    session_type: String,
    login_time: String,
    idle_time: Option<String>,
    terminal: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccountSecurity {
    failed_login_attempts: u32,
    last_login: Option<String>,
    password_last_changed: Option<String>,
    account_expiry: Option<String>,
}

impl Scanner for UserAudit {
    fn name(&self) -> &'static str {
        "user_audit"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"user_audit".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Enhanced User Security Audit".to_string());

        tracing::info!("Starting enhanced user audit scan...");

        // Kullanıcı hesaplarını al
        let users = self.get_user_accounts()?;
        result.set_items_scanned(users.len() as u32);

        tracing::info!("{} kullanıcı hesabı tespit edildi", users.len());

        // Temel güvenlik kontrolları
        self.check_user_security(&users, &mut result)?;
        self.check_password_files(&mut result)?;
        self.check_group_memberships(&mut result)?;
        self.check_home_directories(&users, &mut result)?;
        self.check_login_security(&mut result)?;

        // Gelişmiş güvenlik analizleri
        self.analyze_password_policies(&mut result)?;
        self.analyze_sudo_configurations(&mut result)?;
        self.monitor_user_sessions(&mut result)?;
        self.check_account_security_features(&users, &mut result)?;
        self.analyze_ssh_access_patterns(&mut result)?;

        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;

        tracing::info!(
            "Enhanced user audit completed: {} findings",
            result.findings.len()
        );

        Ok(result)
    }
}

impl UserAudit {
    /// List user accounts
    fn get_user_accounts(&self) -> Result<Vec<UserAccount>, ScanError> {
        let passwd_content = fs::read_to_string("/etc/passwd").map_err(ScanError::IoError)?;

        let shadow_content = fs::read_to_string("/etc/shadow").unwrap_or_default(); // Shadow dosyası okunamayabilir

        let mut users = Vec::new();

        for line in passwd_content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                let username = parts[0];
                let uid: u32 = parts[2].parse().unwrap_or(0);
                let gid: u32 = parts[3].parse().unwrap_or(0);

                // Shadow dosyasından parola durumunu al
                let password_status = self.get_password_status(username, &shadow_content);

                users.push(UserAccount {
                    username: username.to_string(),
                    uid,
                    gid,
                    home_dir: parts[5].to_string(),
                    shell: parts[6].to_string(),
                    password_status,
                });
            }
        }

        Ok(users)
    }

    /// Shadow dosyasından parola durumunu kontrol et
    fn get_password_status(&self, username: &str, shadow_content: &str) -> PasswordStatus {
        for line in shadow_content.lines() {
            if line.starts_with(&format!("{}:", username)) {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let password_field = parts[1];
                    return match password_field {
                        "" => PasswordStatus::Empty,
                        "!" | "*" => PasswordStatus::Locked,
                        "!!" => PasswordStatus::Disabled,
                        _ => PasswordStatus::Set,
                    };
                }
            }
        }
        PasswordStatus::Set
    }

    /// Kullanıcı güvenlik kontrolları
    fn check_user_security(
        &self,
        users: &[UserAccount],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        tracing::info!("Kullanıcı güvenlik kontrolü yapılıyor...");

        for user in users {
            // Boş parola kontrolü
            if matches!(user.password_status, PasswordStatus::Empty) {
                let finding = Finding {
                    id: format!("USER-EMPTY-PASS-{}", user.username.to_uppercase()),
                    title: format!("User with empty password: {}", user.username),
                    description: format!(
                        "User '{}' has an empty password, which is a serious security risk.",
                        user.username
                    ),
                    severity: Severity::Critical,
                    category: Category::User,
                    affected_item: user.username.clone(),
                    current_value: Some("empty password".to_string()),
                    recommended_value: Some("Set strong password".to_string()),
                    references: vec!["https://www.cisecurity.org/controls/".to_string()],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }

            // UID 0 kontrolü (root dışında)
            if user.uid == 0 && user.username != "root" {
                let finding = Finding {
                    id: format!("USER-UID-ZERO-{}", user.username.to_uppercase()),
                    title: format!("Non-root user with UID 0: {}", user.username),
                    description: format!(
                        "User '{}' has UID 0 (root privileges) but is not the root user.",
                        user.username
                    ),
                    severity: Severity::Critical,
                    category: Category::User,
                    affected_item: user.username.clone(),
                    current_value: Some("UID 0".to_string()),
                    recommended_value: Some("Change to unique UID".to_string()),
                    references: vec!["https://www.cisecurity.org/controls/".to_string()],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }

            // Shell kontrolü - riskli shell'ler
            if (user.shell.contains("bash")
                || user.shell.contains("sh")
                || user.shell.contains("zsh"))
                && user.uid < 1000
                && user.username != "root"
            {
                let finding = Finding {
                        id: format!("USER-SYSTEM-SHELL-{}", user.username.to_uppercase()),
                        title: format!("System user with interactive shell: {}", user.username),
                        description: format!(
                            "System user '{}' (UID: {}) has an interactive shell '{}'. System users should typically use /usr/sbin/nologin.",
                            user.username, user.uid, user.shell
                        ),
                        severity: Severity::Medium,
                        category: Category::User,
                        affected_item: user.username.clone(),
                        current_value: Some(user.shell.clone()),
                        recommended_value: Some("/usr/sbin/nologin".to_string()),
                        references: vec![
                            "https://www.cyberciti.biz/tips/howto-linux-shell-restricting-access.html".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                result.add_finding(finding);
            }

            // Home directory kontrolü
            if user.uid >= 1000 && !user.home_dir.starts_with("/home/") && user.username != "nobody"
            {
                let finding = Finding {
                    id: format!("USER-HOME-DIR-{}", user.username.to_uppercase()),
                    title: format!("Unusual home directory: {}", user.username),
                    description: format!(
                        "User '{}' has an unusual home directory: '{}'. Regular users should have home directories under /home/.",
                        user.username, user.home_dir
                    ),
                    severity: Severity::Low,
                    category: Category::User,
                    affected_item: user.username.clone(),
                    current_value: Some(user.home_dir.clone()),
                    recommended_value: Some(format!("/home/{}", user.username)),
                    references: vec![
                        "https://www.pathname.com/fhs/pub/fhs-2.3.html".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Root yetkili kullanıcıları kontrol et
    fn check_privileged_users(
        &self,
        _users: &[UserAccount],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        tracing::info!("Checking privileged users...");

        // sudo grubu üyelerini kontrol et
        if let Ok(group_content) = fs::read_to_string("/etc/group") {
            for line in group_content.lines() {
                if line.starts_with("sudo:")
                    || line.starts_with("wheel:")
                    || line.starts_with("admin:")
                {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 4 && !parts[3].is_empty() {
                        let members: Vec<&str> = parts[3].split(',').collect();

                        for member in members {
                            if !member.trim().is_empty() {
                                let finding = Finding {
                                    id: format!("USER-SUDO-MEMBER-{}", member.trim().to_uppercase()),
                                    title: format!("User with sudo privileges: {}", member.trim()),
                                    description: format!(
                                        "User '{}' is a member of privileged group '{}'. Ensure this is necessary and user is trusted.",
                                        member.trim(), parts[0]
                                    ),
                                    severity: Severity::Medium,
                                    category: Category::User,
                                    affected_item: member.trim().to_string(),
                                    current_value: Some(format!("member of {}", parts[0])),
                                    recommended_value: Some("Review necessity".to_string()),
                                    references: vec![
                                        "https://www.sudo.ws/security/".to_string(),
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
        }

        Ok(())
    }

    /// Check group memberships
    fn check_group_memberships(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking group memberships...");

        if let Ok(group_content) = fs::read_to_string("/etc/group") {
            let sensitive_groups = [
                "root", "shadow", "adm", "disk", "sys", "lp", "mail", "news", "uucp",
            ];

            for line in group_content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 4 {
                    let group_name = parts[0];
                    let members = parts[3];

                    if sensitive_groups.contains(&group_name) && !members.is_empty() {
                        let finding = Finding {
                            id: format!("GROUP-SENSITIVE-{}", group_name.to_uppercase()),
                            title: format!("Users in sensitive group: {}", group_name),
                            description: format!(
                                "Sensitive group '{}' has members: {}. Review if these memberships are necessary.",
                                group_name, members
                            ),
                            severity: Severity::Medium,
                            category: Category::User,
                            affected_item: format!("Group {}", group_name),
                            current_value: Some(members.to_string()),
                            recommended_value: Some("Review memberships".to_string()),
                            references: vec![
                                "https://www.cisecurity.org/controls/".to_string(),
                            ],
                            cve_ids: vec![],
                            fix_available: false, // Manuel review gerekli
                        };
                        result.add_finding(finding);
                    }
                }
            }
        }

        Ok(())
    }

    /// Check shadow file
    fn check_shadow_file(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking shadow file...");

        // Shadow dosyası izinleri
        if let Ok(metadata) = fs::metadata("/etc/shadow") {
            let permissions = metadata.permissions();
            let mode = permissions.mode() & 0o777;

            if mode > 0o640 {
                let finding = Finding {
                    id: "SHADOW-PERMISSIONS".to_string(),
                    title: "Shadow file has overly permissive permissions".to_string(),
                    description: format!(
                        "/etc/shadow file has permissions {:o}, which may allow unauthorized access to password hashes.",
                        mode
                    ),
                    severity: Severity::High,
                    category: Category::User,
                    affected_item: "/etc/shadow".to_string(),
                    current_value: Some(format!("{:o}", mode)),
                    recommended_value: Some("640 or stricter".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Sudo konfigürasyonunu kontrol et
    fn check_sudo_configuration(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking sudo configuration...");

        if let Ok(sudoers_content) = fs::read_to_string("/etc/sudoers") {
            for line in sudoers_content.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }

                // NOPASSWD kontrolü
                if line.contains("NOPASSWD") {
                    let finding = Finding {
                        id: "SUDO-NOPASSWD".to_string(),
                        title: "Sudo NOPASSWD configuration found".to_string(),
                        description: format!(
                            "Sudo configuration allows passwordless execution: '{}'. This may pose security risks.",
                            line
                        ),
                        severity: Severity::Medium,
                        category: Category::User,
                        affected_item: "Sudo Configuration".to_string(),
                        current_value: Some(line.to_string()),
                        recommended_value: Some("Require password for sudo".to_string()),
                        references: vec![
                            "https://www.sudo.ws/security/".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }

                // ALL=(ALL:ALL) ALL kontrolü
                if line.contains("ALL=(ALL:ALL) ALL") && !line.starts_with("root") {
                    let finding = Finding {
                        id: "SUDO-ALL-ACCESS".to_string(),
                        title: "Sudo full access configuration".to_string(),
                        description: format!(
                            "User has full sudo access: '{}'. Consider limiting sudo permissions.",
                            line
                        ),
                        severity: Severity::Medium,
                        category: Category::User,
                        affected_item: "Sudo Configuration".to_string(),
                        current_value: Some(line.to_string()),
                        recommended_value: Some("Limit sudo permissions".to_string()),
                        references: vec!["https://www.sudo.ws/security/".to_string()],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }
            }
        }

        Ok(())
    }

    /// Check password files security
    fn check_password_files(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking password files security...");

        // Check /etc/passwd permissions
        if let Ok(metadata) = fs::metadata("/etc/passwd") {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o022 != 0 {
                let finding = Finding {
                    id: "USER-PASSWD-WRITABLE".to_string(),
                    title: "Password file is writable by others".to_string(),
                    description: "The /etc/passwd file has write permissions for group or others, which is a security risk.".to_string(),
                    severity: Severity::High,
                    category: Category::User,
                    affected_item: "/etc/passwd".to_string(),
                    current_value: Some(format!("{:o}", mode)),
                    recommended_value: Some("644".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        // Check for backup password files
        let backup_files = vec!["/etc/passwd-", "/etc/shadow-", "/etc/group-"];
        for backup_file in backup_files {
            if fs::metadata(backup_file).is_ok() {
                let finding = Finding {
                    id: format!("USER-BACKUP-FILE-{}", backup_file.replace('/', "-")),
                    title: format!("Backup password file exists: {}", backup_file),
                    description: format!(
                        "Backup password file '{}' exists and may contain sensitive information.",
                        backup_file
                    ),
                    severity: Severity::Medium,
                    category: Category::User,
                    affected_item: backup_file.to_string(),
                    current_value: Some("Exists".to_string()),
                    recommended_value: Some("Review and secure backup files".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Check home directories security
    fn check_home_directories(&self, users: &[UserAccount], result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking home directories security...");

        for user in users {
            if user.home_dir.starts_with("/home/") || user.home_dir == "/root" {
                // Check home directory permissions
                if let Ok(metadata) = fs::metadata(&user.home_dir) {
                    let mode = metadata.permissions().mode() & 0o777;
                    if mode & 0o022 != 0 {
                        let finding = Finding {
                            id: format!("USER-HOME-PERM-{}", user.username.to_uppercase()),
                            title: format!("Home directory permissions too permissive: {}", user.username),
                            description: format!(
                                "Home directory '{}' has write permissions for group or others ({:o}).",
                                user.home_dir, mode
                            ),
                            severity: Severity::Medium,
                            category: Category::User,
                            affected_item: user.home_dir.clone(),
                            current_value: Some(format!("{:o}", mode)),
                            recommended_value: Some("750 or stricter".to_string()),
                            references: vec![
                                "https://www.cisecurity.org/controls/".to_string(),
                            ],
                            cve_ids: vec![],
                            fix_available: true,
                        };
                        result.add_finding(finding);
                    }
                }

                // Check for .ssh directory
                let ssh_dir = format!("{}/.ssh", user.home_dir);
                if let Ok(metadata) = fs::metadata(&ssh_dir) {
                    let mode = metadata.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        let finding = Finding {
                            id: format!("USER-SSH-DIR-PERM-{}", user.username.to_uppercase()),
                            title: format!("SSH directory permissions too permissive: {}", user.username),
                            description: format!(
                                "SSH directory '{}' has incorrect permissions ({:o}). Should be 700.",
                                ssh_dir, mode
                            ),
                            severity: Severity::High,
                            category: Category::User,
                            affected_item: ssh_dir.clone(),
                            current_value: Some(format!("{:o}", mode)),
                            recommended_value: Some("700".to_string()),
                            references: vec![
                                "https://www.ssh.com/academy/ssh/keygen".to_string(),
                            ],
                            cve_ids: vec![],
                            fix_available: true,
                        };
                        result.add_finding(finding);
                    }

                    // Check SSH keys
                    if let Ok(entries) = fs::read_dir(&ssh_dir) {
                        for entry in entries.flatten() {
                            if let Some(filename) = entry.file_name().to_str() {
                                if filename.starts_with("id_") && !filename.ends_with(".pub") {
                                    if let Ok(key_metadata) = fs::metadata(entry.path()) {
                                        let key_mode = key_metadata.permissions().mode() & 0o777;
                                        if key_mode & 0o077 != 0 {
                                            let finding = Finding {
                                                id: format!("USER-SSH-KEY-PERM-{}-{}", user.username.to_uppercase(), filename.to_uppercase()),
                                                title: format!("SSH private key permissions too permissive: {}", filename),
                                                description: format!(
                                                    "SSH private key '{}' has incorrect permissions ({:o}). Should be 600.",
                                                    entry.path().display(), key_mode
                                                ),
                                                severity: Severity::High,
                                                category: Category::User,
                                                affected_item: entry.path().to_string_lossy().to_string(),
                                                current_value: Some(format!("{:o}", key_mode)),
                                                recommended_value: Some("600".to_string()),
                                                references: vec![
                                                    "https://www.ssh.com/academy/ssh/keygen".to_string(),
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
            }
        }

        Ok(())
    }

    /// Check login security settings
    fn check_login_security(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking login security settings...");

        // Check login.defs
        if let Ok(login_defs) = fs::read_to_string("/etc/login.defs") {
            let mut pass_max_days = None;
            let mut pass_min_days = None;
            let mut pass_warn_age = None;

            for line in login_defs.lines() {
                let line = line.trim();
                if line.starts_with("PASS_MAX_DAYS") {
                    if let Some(value) = line.split_whitespace().nth(1) {
                        pass_max_days = value.parse::<u32>().ok();
                    }
                }
                if line.starts_with("PASS_MIN_DAYS") {
                    if let Some(value) = line.split_whitespace().nth(1) {
                        pass_min_days = value.parse::<u32>().ok();
                    }
                }
                if line.starts_with("PASS_WARN_AGE") {
                    if let Some(value) = line.split_whitespace().nth(1) {
                        pass_warn_age = value.parse::<u32>().ok();
                    }
                }
            }

            if pass_max_days.is_none() || pass_max_days > Some(90) {
                let finding = Finding {
                    id: "USER-PASSWORD-MAX-AGE".to_string(),
                    title: "Password maximum age not set or too high".to_string(),
                    description: "Password maximum age is not configured or set too high. Consider setting PASS_MAX_DAYS to 90 or less.".to_string(),
                    severity: Severity::Medium,
                    category: Category::User,
                    affected_item: "Password Policy".to_string(),
                    current_value: Some(pass_max_days.map_or("Not set".to_string(), |v| v.to_string())),
                    recommended_value: Some("90 days or less".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }

            if pass_min_days.is_none() || pass_min_days < Some(1) {
                let finding = Finding {
                    id: "USER-PASSWORD-MIN-AGE".to_string(),
                    title: "Password minimum age not set".to_string(),
                    description: "Password minimum age is not configured or too low. Consider setting PASS_MIN_DAYS to at least 1.".to_string(),
                    severity: Severity::Low,
                    category: Category::User,
                    affected_item: "Password Policy".to_string(),
                    current_value: Some(pass_min_days.map_or("Not set".to_string(), |v| v.to_string())),
                    recommended_value: Some("1 day or more".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Analyze password policies
    fn analyze_password_policies(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing password policies...");

        // Check PAM configuration for password complexity
        let pam_files = vec![
            "/etc/pam.d/common-password",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
        ];

        let mut has_complexity_rules = false;
        let mut has_history_check = false;

        for pam_file in pam_files {
            if let Ok(pam_content) = fs::read_to_string(pam_file) {
                for line in pam_content.lines() {
                    if line.contains("pam_pwquality") || line.contains("pam_cracklib") {
                        has_complexity_rules = true;
                        
                        // Check for specific complexity requirements
                        if !line.contains("minlen=") {
                            let finding = Finding {
                                id: "USER-PASSWORD-NO-MINLEN".to_string(),
                                title: "Password minimum length not enforced".to_string(),
                                description: "PAM password module does not enforce minimum password length.".to_string(),
                                severity: Severity::Medium,
                                category: Category::User,
                                affected_item: pam_file.to_string(),
                                current_value: Some("No minlen requirement".to_string()),
                                recommended_value: Some("Add minlen=8 or higher".to_string()),
                                references: vec![
                                    "https://linux.die.net/man/8/pam_pwquality".to_string(),
                                ],
                                cve_ids: vec![],
                                fix_available: true,
                            };
                            result.add_finding(finding);
                        }
                    }

                    if line.contains("pam_unix") && line.contains("remember=") {
                        has_history_check = true;
                    }
                }
            }
        }

        if !has_complexity_rules {
            let finding = Finding {
                id: "USER-NO-PASSWORD-COMPLEXITY".to_string(),
                title: "No password complexity rules configured".to_string(),
                description: "System does not have password complexity rules configured in PAM. Weak passwords may be allowed.".to_string(),
                severity: Severity::High,
                category: Category::User,
                affected_item: "PAM Configuration".to_string(),
                current_value: Some("No complexity rules".to_string()),
                recommended_value: Some("Configure pam_pwquality".to_string()),
                references: vec![
                    "https://linux.die.net/man/8/pam_pwquality".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        if !has_history_check {
            let finding = Finding {
                id: "USER-NO-PASSWORD-HISTORY".to_string(),
                title: "Password history not enforced".to_string(),
                description: "System does not prevent password reuse. Users can reuse previous passwords.".to_string(),
                severity: Severity::Medium,
                category: Category::User,
                affected_item: "PAM Configuration".to_string(),
                current_value: Some("No history check".to_string()),
                recommended_value: Some("Add remember= parameter".to_string()),
                references: vec![
                    "https://linux.die.net/man/8/pam_unix".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        Ok(())
    }

    /// Analyze sudo configurations
    fn analyze_sudo_configurations(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing sudo configurations...");

        if let Ok(output) = Command::new("sudo").args(&["-l", "-U", "root"]).output() {
            let sudo_list = String::from_utf8_lossy(&output.stdout);
            
            if sudo_list.contains("NOPASSWD") {
                let finding = Finding {
                    id: "USER-SUDO-ROOT-NOPASSWD".to_string(),
                    title: "Root has NOPASSWD sudo access".to_string(),
                    description: "Root user has passwordless sudo access configured, which may be unnecessary.".to_string(),
                    severity: Severity::Low,
                    category: Category::User,
                    affected_item: "Sudo Configuration".to_string(),
                    current_value: Some("NOPASSWD enabled for root".to_string()),
                    recommended_value: Some("Review necessity".to_string()),
                    references: vec![
                        "https://www.sudo.ws/security/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        // Check for sudo timestamp timeout
        if let Ok(sudoers_content) = fs::read_to_string("/etc/sudoers") {
            if !sudoers_content.contains("timestamp_timeout") {
                let finding = Finding {
                    id: "USER-SUDO-NO-TIMEOUT".to_string(),
                    title: "Sudo timestamp timeout not configured".to_string(),
                    description: "Sudo timestamp timeout is not explicitly configured. Default timeout may be too long.".to_string(),
                    severity: Severity::Low,
                    category: Category::User,
                    affected_item: "Sudo Configuration".to_string(),
                    current_value: Some("Default timeout".to_string()),
                    recommended_value: Some("Set timestamp_timeout=5".to_string()),
                    references: vec![
                        "https://www.sudo.ws/man/1.8.17/sudoers.man.html".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Monitor user sessions
    fn monitor_user_sessions(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Monitoring user sessions...");

        // Check currently logged in users
        if let Ok(output) = Command::new("who").output() {
            let who_output = String::from_utf8_lossy(&output.stdout);
            let mut session_count = 0;
            let mut root_sessions = 0;

            for line in who_output.lines() {
                session_count += 1;
                if line.starts_with("root ") {
                    root_sessions += 1;
                }
            }

            if session_count > 10 {
                let finding = Finding {
                    id: "USER-MANY-SESSIONS".to_string(),
                    title: format!("Many active user sessions ({})", session_count),
                    description: format!(
                        "System has {} active user sessions. Review if all sessions are legitimate.",
                        session_count
                    ),
                    severity: Severity::Low,
                    category: Category::User,
                    affected_item: "User Sessions".to_string(),
                    current_value: Some(session_count.to_string()),
                    recommended_value: Some("Review active sessions".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: false,
                };
                result.add_finding(finding);
            }

            if root_sessions > 1 {
                let finding = Finding {
                    id: "USER-MULTIPLE-ROOT-SESSIONS".to_string(),
                    title: format!("Multiple root sessions active ({})", root_sessions),
                    description: format!(
                        "There are {} active root sessions. Multiple root sessions may indicate suspicious activity.",
                        root_sessions
                    ),
                    severity: Severity::Medium,
                    category: Category::User,
                    affected_item: "Root Sessions".to_string(),
                    current_value: Some(root_sessions.to_string()),
                    recommended_value: Some("Limit root sessions".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: false,
                };
                result.add_finding(finding);
            }
        }

        // Check for idle sessions
        if let Ok(output) = Command::new("w").output() {
            let w_output = String::from_utf8_lossy(&output.stdout);
            let mut idle_sessions = 0;

            for line in w_output.lines().skip(2) { // Skip header lines
                if line.contains("days") || line.contains("hours") {
                    idle_sessions += 1;
                }
            }

            if idle_sessions > 0 {
                let finding = Finding {
                    id: "USER-IDLE-SESSIONS".to_string(),
                    title: format!("Idle user sessions detected ({})", idle_sessions),
                    description: format!(
                        "Found {} sessions that have been idle for hours or days. Consider implementing automatic logout.",
                        idle_sessions
                    ),
                    severity: Severity::Low,
                    category: Category::User,
                    affected_item: "User Sessions".to_string(),
                    current_value: Some(format!("{} idle sessions", idle_sessions)),
                    recommended_value: Some("Configure automatic logout".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Check account security features
    fn check_account_security_features(&self, users: &[UserAccount], result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking account security features...");

        // Check for accounts without password aging
        if let Ok(shadow_content) = fs::read_to_string("/etc/shadow") {
            for line in shadow_content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 5 {
                    let username = parts[0];
                    let max_days = parts[4];
                    
                    if max_days.is_empty() || max_days == "99999" {
                        if let Some(user) = users.iter().find(|u| u.username == username) {
                            if user.uid >= 1000 && user.uid != 65534 { // Regular user
                                let finding = Finding {
                                    id: format!("USER-NO-PASSWORD-AGING-{}", username.to_uppercase()),
                                    title: format!("No password aging for user: {}", username),
                                    description: format!(
                                        "User '{}' does not have password aging configured. Password never expires.",
                                        username
                                    ),
                                    severity: Severity::Medium,
                                    category: Category::User,
                                    affected_item: username.to_string(),
                                    current_value: Some("No expiration".to_string()),
                                    recommended_value: Some("Set password expiration".to_string()),
                                    references: vec![
                                        "https://linux.die.net/man/8/chage".to_string(),
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

        // Check for failed login attempts
        if let Ok(output) = Command::new("lastb").args(&["-n", "10"]).output() {
            let lastb_output = String::from_utf8_lossy(&output.stdout);
            if !lastb_output.trim().is_empty() {
                let failed_attempts = lastb_output.lines().count();
                if failed_attempts > 5 {
                    let finding = Finding {
                        id: "USER-FAILED-LOGINS".to_string(),
                        title: format!("Recent failed login attempts ({})", failed_attempts),
                        description: format!(
                            "Found {} recent failed login attempts. This could indicate brute force attacks.",
                            failed_attempts
                        ),
                        severity: Severity::Medium,
                        category: Category::User,
                        affected_item: "Authentication".to_string(),
                        current_value: Some(format!("{} failed attempts", failed_attempts)),
                        recommended_value: Some("Review failed login attempts".to_string()),
                        references: vec![
                            "https://www.cisecurity.org/controls/".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: false,
                    };
                    result.add_finding(finding);
                }
            }
        }

        Ok(())
    }

    /// Analyze SSH access patterns
    fn analyze_ssh_access_patterns(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing SSH access patterns...");

        // Check SSH configuration
        if let Ok(sshd_config) = fs::read_to_string("/etc/ssh/sshd_config") {
            let mut permit_root_login = None;
            let mut password_auth = None;
            let mut permit_empty_passwords = None;

            for line in sshd_config.lines() {
                let line = line.trim();
                if line.starts_with("PermitRootLogin") && !line.starts_with('#') {
                    permit_root_login = line.split_whitespace().nth(1);
                }
                if line.starts_with("PasswordAuthentication") && !line.starts_with('#') {
                    password_auth = line.split_whitespace().nth(1);
                }
                if line.starts_with("PermitEmptyPasswords") && !line.starts_with('#') {
                    permit_empty_passwords = line.split_whitespace().nth(1);
                }
            }

            if permit_root_login == Some("yes") {
                let finding = Finding {
                    id: "USER-SSH-ROOT-LOGIN".to_string(),
                    title: "SSH root login enabled".to_string(),
                    description: "SSH is configured to allow root login directly, which is a security risk.".to_string(),
                    severity: Severity::High,
                    category: Category::User,
                    affected_item: "SSH Configuration".to_string(),
                    current_value: Some("PermitRootLogin yes".to_string()),
                    recommended_value: Some("PermitRootLogin no".to_string()),
                    references: vec![
                        "https://www.ssh.com/academy/ssh/sshd_config".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }

            if permit_empty_passwords == Some("yes") {
                let finding = Finding {
                    id: "USER-SSH-EMPTY-PASSWORDS".to_string(),
                    title: "SSH allows empty passwords".to_string(),
                    description: "SSH is configured to allow empty passwords, which is a significant security risk.".to_string(),
                    severity: Severity::High,
                    category: Category::User,
                    affected_item: "SSH Configuration".to_string(),
                    current_value: Some("PermitEmptyPasswords yes".to_string()),
                    recommended_value: Some("PermitEmptyPasswords no".to_string()),
                    references: vec![
                        "https://www.ssh.com/academy/ssh/sshd_config".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }

            if password_auth == Some("yes") {
                let finding = Finding {
                    id: "USER-SSH-PASSWORD-AUTH".to_string(),
                    title: "SSH password authentication enabled".to_string(),
                    description: "SSH allows password authentication. Consider using key-based authentication only.".to_string(),
                    severity: Severity::Medium,
                    category: Category::User,
                    affected_item: "SSH Configuration".to_string(),
                    current_value: Some("PasswordAuthentication yes".to_string()),
                    recommended_value: Some("Use key-based authentication".to_string()),
                    references: vec![
                        "https://www.ssh.com/academy/ssh/public-key-authentication".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        // Check SSH log for suspicious activity
        let ssh_log_files = vec!["/var/log/auth.log", "/var/log/secure"];
        for log_file in ssh_log_files {
            if let Ok(log_content) = fs::read_to_string(log_file) {
                let mut failed_ssh_attempts = 0;
                let mut successful_logins = 0;

                for line in log_content.lines().rev().take(1000) { // Check last 1000 lines
                    if line.contains("ssh") && line.contains("Failed") {
                        failed_ssh_attempts += 1;
                    }
                    if line.contains("ssh") && line.contains("Accepted") {
                        successful_logins += 1;
                    }
                }

                if failed_ssh_attempts > 50 {
                    let finding = Finding {
                        id: "USER-SSH-FAILED-ATTEMPTS".to_string(),
                        title: format!("Many failed SSH attempts ({})", failed_ssh_attempts),
                        description: format!(
                            "Found {} failed SSH login attempts in recent logs. This could indicate brute force attacks.",
                            failed_ssh_attempts
                        ),
                        severity: Severity::High,
                        category: Category::User,
                        affected_item: "SSH Access".to_string(),
                        current_value: Some(format!("{} failed attempts", failed_ssh_attempts)),
                        recommended_value: Some("Implement fail2ban or similar protection".to_string()),
                        references: vec![
                            "https://www.fail2ban.org/".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }

                break; // Only check the first existing log file
            }
        }

        Ok(())
    }
}
