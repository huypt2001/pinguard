use super::{Fixer, FixResult, FixError, FixPlan, FixStatus, RiskLevel, execute_command, create_backup};
use crate::scanners::Finding;
use std::time::{Duration, Instant};
use std::fs;

pub struct UserPolicyFixer;

impl Fixer for UserPolicyFixer {
    fn name(&self) -> &'static str {
        "User Policy Fixer"
    }

    fn can_fix(&self, finding: &Finding) -> bool {
        // Kullanıcı politikası ile ilgili bulguları düzeltebilir
        finding.id.starts_with("USR-") ||
        finding.affected_item.contains("user") ||
        finding.affected_item.contains("password") ||
        finding.title.contains("password") ||
        finding.title.contains("user") ||
        finding.title.contains("sudo")
    }

    fn fix(&self, finding: &Finding, _config: &crate::core::config::Config) -> Result<FixResult, FixError> {
        let start_time = Instant::now();
        let mut result = FixResult::new(finding.id.clone(), self.name().to_string());

        tracing::info!("User policy hardening başlatılıyor: {}", finding.title);

        // Finding türüne göre uygun düzeltme yöntemini seç
        if finding.id.starts_with("USR-WEAK-PASSWORD") {
            self.enforce_password_policy(&mut result)?;
        } else if finding.id.starts_with("USR-NO-PASSWORD-EXPIRY") {
            self.set_password_expiry(finding, &mut result)?;
        } else if finding.id.starts_with("USR-SUDO-NOPASSWD") {
            self.fix_sudo_nopasswd(finding, &mut result)?;
        } else if finding.id.starts_with("USR-INACTIVE-USER") {
            self.disable_inactive_user(finding, &mut result)?;
        } else if finding.id.starts_with("USR-ROOT-LOGIN") {
            self.disable_root_login(&mut result)?;
        } else if finding.id.starts_with("USR-SHARED-ACCOUNT") {
            self.secure_shared_account(finding, &mut result)?;
        } else {
            return Err(FixError::UnsupportedFix(format!("Unsupported user policy fix: {}", finding.id)));
        }

        result = result.set_duration(start_time);
        tracing::info!("User policy hardening tamamlandı: {}", result.message);
        
        Ok(result)
    }

    fn dry_run(&self, finding: &Finding) -> Result<FixPlan, FixError> {
        let mut plan = FixPlan::new(
            finding.id.clone(),
            self.name().to_string(),
            format!("Fix user policy issue: {}", finding.title)
        );

        if finding.id.starts_with("USR-WEAK-PASSWORD") {
            plan = plan
                .requires_backup()
                .add_file("/etc/login.defs".to_string())
                .add_file("/etc/pam.d/common-password".to_string())
                .set_risk(RiskLevel::Medium)
                .set_duration(Duration::from_secs(180));
        } else if finding.id.starts_with("USR-NO-PASSWORD-EXPIRY") {
            let username = self.extract_username(&finding.affected_item)?;
            plan = plan
                .add_command(format!("chage -M 90 {}", username))
                .set_risk(RiskLevel::Low)
                .set_duration(Duration::from_secs(30));
        } else if finding.id.starts_with("USR-SUDO-NOPASSWD") {
            plan = plan
                .requires_backup()
                .add_file("/etc/sudoers".to_string())
                .add_command("visudo -c".to_string())
                .set_risk(RiskLevel::High)
                .set_duration(Duration::from_secs(120));
        } else if finding.id.starts_with("USR-ROOT-LOGIN") {
            plan = plan
                .requires_backup()
                .add_file("/etc/passwd".to_string())
                .add_command("passwd -l root".to_string())
                .set_risk(RiskLevel::High)
                .set_duration(Duration::from_secs(60));
        }

        Ok(plan)
    }
}

impl UserPolicyFixer {
    /// Güçlü parola politikası uygula
    fn enforce_password_policy(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Güçlü parola politikası uygulanıyor...");

        // /etc/login.defs backup ve düzenleme
        let login_defs_path = "/etc/login.defs";
        let backup_path = create_backup(login_defs_path)?;
        result.backup_created = Some(backup_path);

        let content = fs::read_to_string(login_defs_path)
            .map_err(|e| FixError::FileError(format!("Cannot read login.defs: {}", e)))?;

        let mut new_content = content.clone();
        let mut changes_made = false;

        // Parola ayarlarını güncelle
        let password_settings = vec![
            ("PASS_MAX_DAYS", "90"),      // Maksimum parola yaşı
            ("PASS_MIN_DAYS", "1"),       // Minimum parola yaşı
            ("PASS_WARN_AGE", "7"),       // Parola süresi uyarısı
            ("PASS_MIN_LEN", "8"),        // Minimum parola uzunluğu
        ];

        for (setting, value) in password_settings {
            let pattern = format!("^{}\\s+\\d+", setting);
            let replacement = format!("{}\t{}", setting, value);

            let lines: Vec<&str> = new_content.lines().collect();
            let mut new_lines = Vec::new();
            let mut found = false;

            for line in lines {
                if line.trim().starts_with(setting) && !line.trim().starts_with("#") {
                    new_lines.push(replacement.clone());
                    found = true;
                    changes_made = true;
                } else {
                    new_lines.push(line.to_string());
                }
            }

            if !found {
                new_lines.push(replacement);
                changes_made = true;
            }

            new_content = new_lines.join("\n");
        }

        if changes_made {
            fs::write(login_defs_path, new_content)
                .map_err(|e| FixError::FileError(format!("Cannot write login.defs: {}", e)))?;
            result.files_modified.push(login_defs_path.to_string());
        }

        // PAM configuration for password complexity
        self.configure_pam_password_complexity(result)?;

        result.status = FixStatus::Success;
        result.message = "Strong password policy enforced".to_string();

        Ok(())
    }

    /// PAM parola karmaşıklığını yapılandır
    fn configure_pam_password_complexity(&self, result: &mut FixResult) -> Result<(), FixError> {
        let pam_password_path = "/etc/pam.d/common-password";
        
        // Backup oluştur
        let backup_path = create_backup(pam_password_path)?;
        if result.backup_created.is_none() {
            result.backup_created = Some(backup_path);
        }

        let content = fs::read_to_string(pam_password_path)
            .map_err(|e| FixError::FileError(format!("Cannot read PAM password config: {}", e)))?;

        let mut new_content = content;

        // pam_pwquality modülünü ekle
        let pwquality_line = "password requisite pam_pwquality.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1";
        
        if !new_content.contains("pam_pwquality.so") {
            // pam_unix satırından önce ekle
            let lines: Vec<&str> = new_content.lines().collect();
            let mut new_lines = Vec::new();
            
            for line in lines {
                if line.contains("pam_unix.so") && line.contains("password") {
                    new_lines.push(pwquality_line.to_string());
                }
                new_lines.push(line.to_string());
            }
            
            new_content = new_lines.join("\n");
            
            fs::write(pam_password_path, new_content)
                .map_err(|e| FixError::FileError(format!("Cannot write PAM password config: {}", e)))?;
            
            result.files_modified.push(pam_password_path.to_string());
        }

        Ok(())
    }

    /// Parola süresi ayarla
    fn set_password_expiry(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let username = self.extract_username(&finding.affected_item)?;
        
        tracing::info!("Parola süresi ayarlanıyor: {}", username);

        // Maksimum parola yaşı 90 gün
        let _output = execute_command("chage", &["-M", "90", &username])?;
        result.commands_executed.push(format!("chage -M 90 {}", username));

        // Parola değiştirme uyarısı 7 gün önce
        let _output = execute_command("chage", &["-W", "7", &username])?;
        result.commands_executed.push(format!("chage -W 7 {}", username));

        result.status = FixStatus::Success;
        result.message = format!("Password expiry set for user: {}", username);

        Ok(())
    }

    /// Sudo NOPASSWD güvenlik açığını düzelt
    fn fix_sudo_nopasswd(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Sudo NOPASSWD güvenlik açığı düzeltiliyor...");

        let sudoers_path = "/etc/sudoers";
        let backup_path = create_backup(sudoers_path)?;
        result.backup_created = Some(backup_path);

        let content = fs::read_to_string(sudoers_path)
            .map_err(|e| FixError::FileError(format!("Cannot read sudoers: {}", e)))?;

        let lines: Vec<&str> = content.lines().collect();
        let mut new_lines = Vec::new();
        let mut changes_made = false;

        for line in lines {
            if line.contains("NOPASSWD") && !line.trim().starts_with("#") {
                // NOPASSWD satırını yorum satırı yap
                new_lines.push(format!("# {}", line));
                changes_made = true;
            } else {
                new_lines.push(line.to_string());
            }
        }

        if changes_made {
            let new_content = new_lines.join("\n");
            fs::write(sudoers_path, new_content)
                .map_err(|e| FixError::FileError(format!("Cannot write sudoers: {}", e)))?;
            
            result.files_modified.push(sudoers_path.to_string());

            // Sudoers dosyasını doğrula
            let test_output = execute_command("visudo", &["-c"])?;
            if !test_output.contains("parsed OK") {
                return Err(FixError::ConfigError("Sudoers file validation failed".to_string()));
            }

            result.status = FixStatus::Success;
            result.message = "Sudo NOPASSWD entries disabled".to_string();
        } else {
            result.status = FixStatus::Skipped;
            result.message = "No NOPASSWD entries found".to_string();
        }

        Ok(())
    }

    /// İnaktif kullanıcıyı devre dışı bırak
    fn disable_inactive_user(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let username = self.extract_username(&finding.affected_item)?;
        
        tracing::info!("İnaktif kullanıcı devre dışı bırakılıyor: {}", username);

        // Kullanıcı hesabını kilitle
        let _output = execute_command("passwd", &["-l", &username])?;
        result.commands_executed.push(format!("passwd -l {}", username));

        // Hesap süresi geçmiş olarak işaretle
        let _output = execute_command("chage", &["-E", "1", &username])?;
        result.commands_executed.push(format!("chage -E 1 {}", username));

        result.status = FixStatus::Success;
        result.message = format!("Inactive user '{}' disabled", username);

        Ok(())
    }

    /// Root login'i devre dışı bırak
    fn disable_root_login(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Root login devre dışı bırakılıyor...");

        // Root hesabını kilitle
        let _output = execute_command("passwd", &["-l", "root"])?;
        result.commands_executed.push("passwd -l root".to_string());

        // /etc/passwd'da root shell'ini değiştir
        let passwd_path = "/etc/passwd";
        let backup_path = create_backup(passwd_path)?;
        result.backup_created = Some(backup_path);

        let content = fs::read_to_string(passwd_path)
            .map_err(|e| FixError::FileError(format!("Cannot read passwd: {}", e)))?;

        let lines: Vec<&str> = content.lines().collect();
        let mut new_lines = Vec::new();

        for line in lines {
            if line.starts_with("root:") {
                // Root shell'ini /usr/sbin/nologin olarak değiştir
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 7 {
                    let mut new_parts = parts.clone();
                    new_parts[6] = "/usr/sbin/nologin";
                    new_lines.push(new_parts.join(":"));
                } else {
                    new_lines.push(line.to_string());
                }
            } else {
                new_lines.push(line.to_string());
            }
        }

        let new_content = new_lines.join("\n");
        fs::write(passwd_path, new_content)
            .map_err(|e| FixError::FileError(format!("Cannot write passwd: {}", e)))?;
        
        result.files_modified.push(passwd_path.to_string());
        result.status = FixStatus::Success;
        result.message = "Root login disabled".to_string();

        Ok(())
    }

    /// Paylaşımlı hesabı güvenli hale getir
    fn secure_shared_account(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let username = self.extract_username(&finding.affected_item)?;
        
        tracing::info!("Paylaşımlı hesap güvenliği artırılıyor: {}", username);

        // Zorunlu parola değişikliği
        let _output = execute_command("chage", &["-d", "0", &username])?;
        result.commands_executed.push(format!("chage -d 0 {}", username));

        // Parola süresi kısa tut
        let _output = execute_command("chage", &["-M", "30", &username])?;
        result.commands_executed.push(format!("chage -M 30 {}", username));

        result.status = FixStatus::RequiresUserAction;
        result.message = format!("Shared account '{}' configured for mandatory password change. Consider creating individual accounts.", username);

        Ok(())
    }

    /// Bulgudaki kullanıcı adını çıkar
    fn extract_username(&self, affected_item: &str) -> Result<String, FixError> {
        // "User: username" formatından kullanıcı adını çıkar
        if affected_item.starts_with("User: ") {
            return Ok(affected_item.replace("User: ", "").trim().to_string());
        }

        // "username" doğrudan ise
        if !affected_item.contains("/") && !affected_item.contains(" ") {
            return Ok(affected_item.trim().to_string());
        }

        Err(FixError::ConfigError(format!("Cannot extract username from: {}", affected_item)))
    }

    /// Tüm sistemdeki zayıf parola politikalarını düzelt
    pub fn fix_all_password_policies(&self) -> Result<Vec<FixResult>, FixError> {
        let mut results = Vec::new();

        // Genel parola politikası
        let mut general_result = FixResult::new("USR-WEAK-PASSWORD-GENERAL".to_string(), self.name().to_string());
        if let Err(e) = self.enforce_password_policy(&mut general_result) {
            tracing::error!("Failed to enforce password policy: {}", e);
        }
        results.push(general_result);

        // Süresi dolmuş parolaları kontrol et
        let output = execute_command("awk", &["-F:", "$5 == \"\" {print $1}", "/etc/shadow"])?;
        for username in output.lines() {
            if !username.is_empty() && username != "root" {
                let mut expiry_result = FixResult::new(
                    format!("USR-NO-PASSWORD-EXPIRY-{}", username.to_uppercase()),
                    self.name().to_string()
                );
                
                if let Err(e) = self.set_password_expiry_for_user(username, &mut expiry_result) {
                    tracing::warn!("Failed to set password expiry for {}: {}", username, e);
                }
                results.push(expiry_result);
            }
        }

        Ok(results)
    }

    /// Belirli kullanıcı için parola süresi ayarla
    fn set_password_expiry_for_user(&self, username: &str, result: &mut FixResult) -> Result<(), FixError> {
        let _output = execute_command("chage", &["-M", "90", username])?;
        result.commands_executed.push(format!("chage -M 90 {}", username));

        let _output = execute_command("chage", &["-W", "7", username])?;
        result.commands_executed.push(format!("chage -W 7 {}", username));

        result.status = FixStatus::Success;
        result.message = format!("Password expiry set for user: {}", username);

        Ok(())
    }
}