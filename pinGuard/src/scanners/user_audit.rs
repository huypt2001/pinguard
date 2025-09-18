use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

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

impl Scanner for UserAudit {
    fn name(&self) -> &'static str {
        "User Audit"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"user_audit".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("User Audit".to_string());

        tracing::info!("Starting user audit scan...");

        // Kullanıcı hesaplarını al
        let users = self.get_user_accounts()?;
        result.set_items_scanned(users.len() as u32);

        tracing::info!("{} kullanıcı hesabı tespit edildi", users.len());

        // Kullanıcı güvenlik kontrolları
        self.check_user_security(&users, &mut result)?;

        // Root yetkili kullanıcıları kontrol et
        self.check_privileged_users(&users, &mut result)?;

        // Grup üyeliklerini kontrol et
        self.check_group_memberships(&mut result)?;

        // Shadow dosyası kontrolü
        self.check_shadow_file(&mut result)?;

        // Sudo konfigürasyonunu kontrol et
        self.check_sudo_configuration(&mut result)?;

        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;

        tracing::info!("User audit completed: {} findings", result.findings.len());

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
}
