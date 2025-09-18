use super::{Fixer, FixResult, FixError, FixPlan, FixStatus, RiskLevel, execute_command, create_backup};
use crate::scanners::Finding;
use std::time::{Duration, Instant};
use std::fs;

pub struct ServiceHardener;

impl Fixer for ServiceHardener {
    fn name(&self) -> &'static str {
        "Service Hardener"
    }

    fn can_fix(&self, finding: &Finding) -> bool {
        // Can fix service-related findings
        finding.id.starts_with("SVC-") || 
        finding.affected_item.contains("service") ||
        finding.title.contains("service") ||
        finding.title.contains("SSH") ||
        finding.title.contains("risky")
    }

    fn fix(&self, finding: &Finding, _config: &crate::core::config::Config) -> Result<FixResult, FixError> {
        let start_time = Instant::now();
        let mut result = FixResult::new(finding.id.clone(), self.name().to_string());

        tracing::info!("Starting service hardening: {}", finding.title);

        // Select appropriate fix method based on finding type
        if finding.id.starts_with("SVC-RISKY-SERVICE") {
            self.disable_risky_service(finding, &mut result)?;
        } else if finding.id.starts_with("SVC-SSH") {
            self.harden_ssh_config(finding, &mut result)?;
        } else if finding.id.starts_with("SVC-UNNECESSARY") {
            self.disable_unnecessary_service(finding, &mut result)?;
        } else if finding.id.starts_with("SVC-INSECURE") {
            self.secure_service_config(finding, &mut result)?;
        } else {
            return Err(FixError::UnsupportedFix(format!("Unsupported service fix: {}", finding.id)));
        }

        result = result.set_duration(start_time);
        tracing::info!("Service hardening completed: {}", result.message);
        
        Ok(result)
    }

    fn dry_run(&self, finding: &Finding) -> Result<FixPlan, FixError> {
        let mut plan = FixPlan::new(
            finding.id.clone(),
            self.name().to_string(),
            format!("Harden service configuration: {}", finding.title)
        );

        if finding.id.starts_with("SVC-RISKY-SERVICE") {
            let service_name = self.extract_service_name(&finding.affected_item)?;
            plan = plan
                .add_command(format!("systemctl stop {}", service_name))
                .add_command(format!("systemctl disable {}", service_name))
                .set_risk(RiskLevel::Medium)
                .set_duration(Duration::from_secs(60));
        } else if finding.id.starts_with("SVC-SSH") {
            plan = plan
                .requires_backup()
                .add_file("/etc/ssh/sshd_config".to_string())
                .add_command("systemctl restart ssh".to_string())
                .set_risk(RiskLevel::High)
                .set_duration(Duration::from_secs(120));
        } else if finding.id.starts_with("SVC-UNNECESSARY") {
            let service_name = self.extract_service_name(&finding.affected_item)?;
            plan = plan
                .add_command(format!("systemctl disable {}", service_name))
                .set_risk(RiskLevel::Low)
                .set_duration(Duration::from_secs(30));
        }

        Ok(plan)
    }
}

impl ServiceHardener {
    /// Stop and disable risky service
    fn disable_risky_service(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let service_name = self.extract_service_name(&finding.affected_item)?;
        
        tracing::info!("Disabling risky service: {}", service_name);

        // First stop the service
        let _output = execute_command("systemctl", &["stop", &service_name])?;
        result.commands_executed.push(format!("systemctl stop {}", service_name));

        // Check service status
        let status_output = execute_command("systemctl", &["is-active", &service_name])
            .unwrap_or_else(|_| "inactive".to_string());

        if status_output.trim() == "inactive" {
            // Permanently disable the service
            let _output = execute_command("systemctl", &["disable", &service_name])?;
            result.commands_executed.push(format!("systemctl disable {}", service_name));

            result.status = FixStatus::Success;
            result.message = format!("Risky service '{}' stopped and disabled", service_name);
        } else {
            result.status = FixStatus::Failed;
            result.message = format!("Failed to stop risky service '{}'", service_name);
        }

        Ok(())
    }

    /// Harden SSH configuration
    fn harden_ssh_config(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Hardening SSH configuration...");

        let ssh_config_path = "/etc/ssh/sshd_config";
        
        // Create backup
        let backup_path = create_backup(ssh_config_path)?;
        result.backup_created = Some(backup_path);

        // Read SSH config
        let config_content = fs::read_to_string(ssh_config_path)
            .map_err(|e| FixError::FileError(format!("Cannot read SSH config: {}", e)))?;

        let mut new_config = config_content.clone();
        let mut changes_made = false;

        // Apply security settings
        let security_settings = vec![
            ("PermitRootLogin", "no"),
            ("PasswordAuthentication", "no"),
            ("PermitEmptyPasswords", "no"),
            ("X11Forwarding", "no"),
            ("Protocol", "2"),
            ("ClientAliveInterval", "300"),
            ("ClientAliveCountMax", "2"),
            ("MaxAuthTries", "3"),
            ("AllowUsers", ""), // This is left empty, administrator adds it themselves
        ];

        for (setting, value) in security_settings {
            if setting == "AllowUsers" {
                continue; // Administrator should manually add AllowUsers
            }

            let pattern = format!("^{}\\s+", setting);
            let replacement = if value.is_empty() {
                format!("#{} ", setting)
            } else {
                format!("{} {}", setting, value)
            };

            // Find existing line and replace
            let lines: Vec<&str> = new_config.lines().collect();
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

            // If setting not found, add to end
            if !found && !value.is_empty() {
                new_lines.push(replacement);
                changes_made = true;
            }

            new_config = new_lines.join("\n");
        }

        if changes_made {
            // Write new config
            fs::write(ssh_config_path, new_config)
                .map_err(|e| FixError::FileError(format!("Cannot write SSH config: {}", e)))?;
            
            result.files_modified.push(ssh_config_path.to_string());

            // Test SSH config
            let test_output = execute_command("sshd", &["-t"])?;
            if !test_output.is_empty() {
                return Err(FixError::ConfigError(format!("SSH config test failed: {}", test_output)));
            }

            // Restart SSH service
            let _output = execute_command("systemctl", &["restart", "ssh"])?;
            result.commands_executed.push("systemctl restart ssh".to_string());

            result.status = FixStatus::Success;
            result.message = "SSH configuration hardened successfully".to_string();
        } else {
            result.status = FixStatus::Skipped;
            result.message = "SSH configuration already secure".to_string();
        }

        Ok(())
    }

    /// Disable unnecessary service
    fn disable_unnecessary_service(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let service_name = self.extract_service_name(&finding.affected_item)?;
        
        tracing::info!("Disabling unnecessary service: {}", service_name);

        // Disable service (but don't stop)
        let _output = execute_command("systemctl", &["disable", &service_name])?;
        result.commands_executed.push(format!("systemctl disable {}", service_name));

        // Check service enable status
        let status_output = execute_command("systemctl", &["is-enabled", &service_name])
            .unwrap_or_else(|_| "disabled".to_string());

        if status_output.trim() == "disabled" {
            result.status = FixStatus::Success;
            result.message = format!("Unnecessary service '{}' disabled", service_name);
        } else {
            result.status = FixStatus::Failed;
            result.message = format!("Failed to disable unnecessary service '{}'", service_name);
        }

        Ok(())
    }

    /// Fix insecure service configuration
    fn secure_service_config(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let service_name = self.extract_service_name(&finding.affected_item)?;
        
        tracing::info!("Increasing service configuration security: {}", service_name);

        // Special hardening for specific services
        match service_name.as_str() {
            "apache2" | "httpd" => self.harden_apache_config(result)?,
            "nginx" => self.harden_nginx_config(result)?,
            "mysql" | "mysqld" => self.harden_mysql_config(result)?,
            "postgresql" => self.harden_postgresql_config(result)?,
            _ => {
                result.status = FixStatus::Skipped;
                result.message = format!("No specific hardening available for service: {}", service_name);
            }
        }

        Ok(())
    }

    /// Harden Apache configuration
    fn harden_apache_config(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Hardening Apache configuration...");

        // Create Apache security config file
        let security_config = r#"
# Security headers
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# Hide Apache version
ServerTokens Prod
ServerSignature Off

# Disable TRACE method
TraceEnable Off
"#;

        let config_path = "/etc/apache2/conf-available/security-hardening.conf";
        fs::write(config_path, security_config)
            .map_err(|e| FixError::FileError(format!("Cannot write Apache security config: {}", e)))?;

        result.files_modified.push(config_path.to_string());

        // Enable security config
        let _output = execute_command("a2enconf", &["security-hardening"])?;
        result.commands_executed.push("a2enconf security-hardening".to_string());

        // Restart Apache
        let _output = execute_command("systemctl", &["restart", "apache2"])?;
        result.commands_executed.push("systemctl restart apache2".to_string());

        result.status = FixStatus::Success;
        result.message = "Apache configuration hardened successfully".to_string();

        Ok(())
    }

    /// Harden Nginx configuration
    fn harden_nginx_config(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Hardening Nginx configuration...");

        let security_config = r#"
# Security headers
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Hide Nginx version
server_tokens off;

# Disable server signature
more_clear_headers Server;
"#;

        let config_path = "/etc/nginx/conf.d/security-hardening.conf";
        fs::write(config_path, security_config)
            .map_err(|e| FixError::FileError(format!("Cannot write Nginx security config: {}", e)))?;

        result.files_modified.push(config_path.to_string());

        // Test Nginx config
        let _output = execute_command("nginx", &["-t"])?;

        // Restart Nginx
        let _output = execute_command("systemctl", &["restart", "nginx"])?;
        result.commands_executed.push("systemctl restart nginx".to_string());

        result.status = FixStatus::Success;
        result.message = "Nginx configuration hardened successfully".to_string();

        Ok(())
    }

    /// Harden MySQL configuration
    fn harden_mysql_config(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Hardening MySQL configuration...");

        // Operations similar to mysql_secure_installation
        result.status = FixStatus::RequiresUserAction;
        result.message = "MySQL hardening requires manual intervention. Run: mysql_secure_installation".to_string();

        Ok(())
    }

    /// Harden PostgreSQL configuration
    fn harden_postgresql_config(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Hardening PostgreSQL configuration...");

        result.status = FixStatus::RequiresUserAction;
        result.message = "PostgreSQL hardening requires manual configuration review".to_string();

        Ok(())
    }

    /// Extract service name from finding
    fn extract_service_name(&self, affected_item: &str) -> Result<String, FixError> {
        // Extract service name from "Service: servicename" format
        if affected_item.starts_with("Service: ") {
            return Ok(affected_item.replace("Service: ", "").trim().to_string());
        }

        // Extract service name from "servicename.service" format
        if affected_item.ends_with(".service") {
            return Ok(affected_item.replace(".service", "").trim().to_string());
        }

        // If it's a direct service name
        if !affected_item.contains("/") && !affected_item.contains(" ") {
            return Ok(affected_item.trim().to_string());
        }

        Err(FixError::ConfigError(format!("Cannot extract service name from: {}", affected_item)))
    }

    /// Disable all risky services in batch
    pub fn disable_all_risky_services(&self) -> Result<Vec<FixResult>, FixError> {
        let mut results = Vec::new();

        let risky_services = vec![
            "telnet",
            "ftp", 
            "tftp",
            "rsh",
            "rlogin",
            "rexec",
            "finger",
            "echo",
            "discard",
            "chargen",
            "daytime",
            "time",
        ];

        for service in risky_services {
            // Check if service exists
            if self.service_exists(service)? {
                match self.disable_single_risky_service(service) {
                    Ok(result) => results.push(result),
                    Err(e) => tracing::warn!("Failed to disable risky service {}: {}", service, e),
                }
            }
        }

        Ok(results)
    }

    /// Check if service exists
    fn service_exists(&self, service_name: &str) -> Result<bool, FixError> {
        let output = execute_command("systemctl", &["list-unit-files", "--type=service"])?;
        Ok(output.contains(&format!("{}.service", service_name)))
    }

    /// Disable a single risky service
    fn disable_single_risky_service(&self, service_name: &str) -> Result<FixResult, FixError> {
        let start_time = Instant::now();
        let mut result = FixResult::new(
            format!("SVC-RISKY-{}", service_name.to_uppercase()),
            self.name().to_string()
        );

        // Stop service
        let _stop_output = execute_command("systemctl", &["stop", service_name]);
        result.commands_executed.push(format!("systemctl stop {}", service_name));

        // Disable service
        let _disable_output = execute_command("systemctl", &["disable", service_name]);
        result.commands_executed.push(format!("systemctl disable {}", service_name));

        result.status = FixStatus::Success;
        result.message = format!("Risky service '{}' stopped and disabled", service_name);
        result.duration = start_time.elapsed().as_millis() as u64;

        Ok(result)
    }
}