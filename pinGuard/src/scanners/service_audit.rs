use super::{Scanner, ScanResult, ScanError, Finding, Severity, Category, ScanStatus};
use std::process::Command;
use serde::{Deserialize, Serialize};
use std::time::Instant;

pub struct ServiceAudit;

#[derive(Debug, Serialize, Deserialize)]
struct SystemService {
    name: String,
    enabled: bool,
    active: bool,
    state: String,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RiskyService {
    name: String,
    reason: String,
    severity: Severity,
    recommendation: String,
}

impl Scanner for ServiceAudit {
    fn name(&self) -> &'static str {
        "Service Audit"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config.scanner.enabled_modules.contains(&"service_audit".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Service Audit".to_string());
        
        tracing::info!("Starting service audit scan...");
        
        // Aktif servisleri listele
        let services = self.get_active_services()?;
        result.set_items_scanned(services.len() as u32);
        
        tracing::info!("{} aktif servis tespit edildi", services.len());
        
        // Riskli servisleri kontrol et
        self.check_risky_services(&services, &mut result)?;
        
        // Gereksiz servisleri kontrol et
        self.check_unnecessary_services(&services, &mut result)?;
        
        // SSH servis konfigürasyonunu kontrol et
        self.check_ssh_configuration(&mut result)?;
        
        // Network servislerini kontrol et
        self.check_network_services(&services, &mut result)?;
        
        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;
        
        tracing::info!("Service audit tamamlandı: {} bulgu", result.findings.len());
        
        Ok(result)
    }
}

impl ServiceAudit {
    /// List active services
    fn get_active_services(&self) -> Result<Vec<SystemService>, ScanError> {
        let output = Command::new("systemctl")
            .args(&["list-units", "--type=service", "--state=active", "--no-pager", "--plain"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("systemctl failed: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError("systemctl command failed".to_string()));
        }

        let services_text = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();

        for line in services_text.lines() {
            if line.contains(".service") && !line.trim().is_empty() && !line.starts_with("UNIT") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let service_name = parts[0].trim_end_matches(".service");
                    services.push(SystemService {
                        name: service_name.to_string(),
                        enabled: true, // Active servisleri kontrol ediyoruz
                        active: parts[2] == "active",
                        state: parts[3].to_string(),
                        description: parts.get(4..).unwrap_or(&[]).join(" "),
                    });
                }
            }
        }

        Ok(services)
    }

    /// Bilinen riskli servisleri kontrol et
    fn check_risky_services(&self, services: &[SystemService], result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking risky services...");
        
        let risky_services = self.get_risky_service_patterns();
        
        for service in services {
            for risky in &risky_services {
                if service.name.contains(&risky.name) {
                    let finding = Finding {
                        id: format!("SVC-RISK-{}", service.name.to_uppercase().replace('-', "_")),
                        title: format!("Potentially risky service: {}", service.name),
                        description: format!(
                            "Service '{}' is running and may pose security risks. Reason: {}. Recommendation: {}",
                            service.name, risky.reason, risky.recommendation
                        ),
                        severity: risky.severity.clone(),
                        category: Category::Service,
                        affected_item: service.name.clone(),
                        current_value: Some("active".to_string()),
                        recommended_value: Some("Review and secure or disable".to_string()),
                        references: vec![
                            "https://www.cisecurity.org/controls/".to_string(),
                            "https://wiki.archlinux.org/title/Systemd".to_string(),
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

    /// Riskli servis pattern'ları
    fn get_risky_service_patterns(&self) -> Vec<RiskyService> {
        vec![
            RiskyService {
                name: "telnet".to_string(),
                reason: "Unencrypted remote access protocol".to_string(),
                severity: Severity::High,
                recommendation: "Use SSH instead".to_string(),
            },
            RiskyService {
                name: "ftp".to_string(),
                reason: "Unencrypted file transfer protocol".to_string(),
                severity: Severity::High,
                recommendation: "Use SFTP or FTPS".to_string(),
            },
            RiskyService {
                name: "rsh".to_string(),
                reason: "Remote shell without encryption".to_string(),
                severity: Severity::High,
                recommendation: "Use SSH instead".to_string(),
            },
            RiskyService {
                name: "rlogin".to_string(),
                reason: "Remote login without encryption".to_string(),
                severity: Severity::High,
                recommendation: "Use SSH instead".to_string(),
            },
            RiskyService {
                name: "fingerd".to_string(),
                reason: "Information disclosure service".to_string(),
                severity: Severity::Medium,
                recommendation: "Disable if not needed".to_string(),
            },
            RiskyService {
                name: "tftpd".to_string(),
                reason: "Trivial FTP without authentication".to_string(),
                severity: Severity::Medium,
                recommendation: "Secure or disable".to_string(),
            },
            RiskyService {
                name: "cups".to_string(),
                reason: "Printing service may have vulnerabilities".to_string(),
                severity: Severity::Low,
                recommendation: "Secure configuration and updates".to_string(),
            },
        ]
    }

    /// Check unnecessary services
    fn check_unnecessary_services(&self, services: &[SystemService], result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking unnecessary services...");
        
        let unnecessary_patterns = vec![
            "avahi-daemon", "bluetooth", "cups", "ModemManager", "wpa_supplicant"
        ];
        
        for service in services {
            for pattern in &unnecessary_patterns {
                if service.name.contains(pattern) {
                    let finding = Finding {
                        id: format!("SVC-UNNECESSARY-{}", service.name.to_uppercase().replace('-', "_")),
                        title: format!("Potentially unnecessary service: {}", service.name),
                        description: format!(
                            "Service '{}' is running but may not be needed on a server environment. Consider disabling if not required.",
                            service.name
                        ),
                        severity: Severity::Low,
                        category: Category::Service,
                        affected_item: service.name.clone(),
                        current_value: Some("enabled".to_string()),
                        recommended_value: Some("Review and disable if not needed".to_string()),
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

        Ok(())
    }

    /// SSH konfigürasyonunu kontrol et
    fn check_ssh_configuration(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking SSH configuration...");
        
        if let Ok(config_content) = std::fs::read_to_string("/etc/ssh/sshd_config") {
            self.analyze_ssh_config(&config_content, result)?;
        }

        Ok(())
    }

    /// Analyze SSH config file
    fn analyze_ssh_config(&self, config: &str, result: &mut ScanResult) -> Result<(), ScanError> {
        let mut root_login_enabled = false;
        let mut password_auth_enabled = false;
        let mut permit_empty_passwords = false;
        let mut protocol_version_1 = false;

        for line in config.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            if line.to_lowercase().starts_with("permitrootlogin") {
                if line.to_lowercase().contains("yes") {
                    root_login_enabled = true;
                }
            }
            
            if line.to_lowercase().starts_with("passwordauthentication") {
                if line.to_lowercase().contains("yes") {
                    password_auth_enabled = true;
                }
            }
            
            if line.to_lowercase().starts_with("permitemptypasswords") {
                if line.to_lowercase().contains("yes") {
                    permit_empty_passwords = true;
                }
            }
            
            if line.to_lowercase().starts_with("protocol") {
                if line.contains("1") {
                    protocol_version_1 = true;
                }
            }
        }

        // SSH güvenlik bulguları
        if root_login_enabled {
            let finding = Finding {
                id: "SSH-ROOT-LOGIN".to_string(),
                title: "SSH root login enabled".to_string(),
                description: "SSH is configured to allow direct root login, which is a security risk.".to_string(),
                severity: Severity::High,
                category: Category::Service,
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

        if password_auth_enabled {
            let finding = Finding {
                id: "SSH-PASSWORD-AUTH".to_string(),
                title: "SSH password authentication enabled".to_string(),
                description: "SSH allows password authentication, which is less secure than key-based auth.".to_string(),
                severity: Severity::Medium,
                category: Category::Service,
                affected_item: "SSH Configuration".to_string(),
                current_value: Some("PasswordAuthentication yes".to_string()),
                recommended_value: Some("PasswordAuthentication no".to_string()),
                references: vec![
                    "https://www.ssh.com/academy/ssh/sshd_config".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        if permit_empty_passwords {
            let finding = Finding {
                id: "SSH-EMPTY-PASSWORDS".to_string(),
                title: "SSH allows empty passwords".to_string(),
                description: "SSH is configured to allow empty passwords, which is extremely dangerous.".to_string(),
                severity: Severity::Critical,
                category: Category::Service,
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

        if protocol_version_1 {
            let finding = Finding {
                id: "SSH-PROTOCOL-V1".to_string(),
                title: "SSH Protocol version 1 enabled".to_string(),
                description: "SSH Protocol version 1 is deprecated and insecure.".to_string(),
                severity: Severity::High,
                category: Category::Service,
                affected_item: "SSH Configuration".to_string(),
                current_value: Some("Protocol 1".to_string()),
                recommended_value: Some("Protocol 2".to_string()),
                references: vec![
                    "https://www.ssh.com/academy/ssh/sshd_config".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        Ok(())
    }

    /// Network servislerini kontrol et
    fn check_network_services(&self, services: &[SystemService], result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking network services...");
        
        let network_services = vec![
            "apache2", "nginx", "httpd", "mysql", "mariadb", "postgresql", 
            "redis", "mongodb", "elasticsearch", "ssh", "sshd"
        ];
        
        for service in services {
            for net_service in &network_services {
                if service.name.contains(net_service) {
                    // Bu servisler için network binding kontrol et
                    let finding = Finding {
                        id: format!("SVC-NETWORK-{}", service.name.to_uppercase().replace('-', "_")),
                        title: format!("Network service detected: {}", service.name),
                        description: format!(
                            "Network service '{}' is running. Ensure it's properly secured and configured.",
                            service.name
                        ),
                        severity: Severity::Medium,
                        category: Category::Service,
                        affected_item: service.name.clone(),
                        current_value: Some("running".to_string()),
                        recommended_value: Some("Review configuration and security".to_string()),
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

        Ok(())
    }
}