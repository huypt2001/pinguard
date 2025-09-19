use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::process::Command;
use std::time::Instant;

pub struct ServiceAudit;

#[derive(Debug, Serialize, Deserialize)]
struct SystemService {
    name: String,
    enabled: bool,
    active: bool,
    state: String,
    description: String,
    unit_file_state: Option<String>,
    load_state: Option<String>,
    sub_state: Option<String>,
    main_pid: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RiskyService {
    name: String,
    reason: String,
    severity: Severity,
    recommendation: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct ServiceHardening {
    service_name: String,
    user: Option<String>,
    group: Option<String>,
    private_tmp: bool,
    protect_system: bool,
    protect_home: bool,
    no_new_privileges: bool,
    restrict_address_families: bool,
    system_call_filter: Option<String>,
    capability_bounding_set: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct NetworkBinding {
    service: String,
    port: u16,
    protocol: String,
    bind_address: String,
    process_name: String,
    pid: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct ServiceConfiguration {
    name: String,
    config_files: Vec<String>,
    security_settings: HashMap<String, String>,
    hardening_features: Vec<String>,
    exposed_ports: Vec<u16>,
}

impl Scanner for ServiceAudit {
    fn name(&self) -> &'static str {
        "service_audit"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"service_audit".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Enhanced Service Audit".to_string());

        tracing::info!("Starting enhanced service audit scan...");

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

        // Service hardening analizi
        self.analyze_service_hardening(&services, &mut result)?;

        // Port binding analizi
        self.analyze_port_bindings(&mut result)?;

        // Service configuration güvenlik analizi
        self.analyze_service_configurations(&services, &mut result)?;

        // Process monitoring
        self.analyze_running_processes(&mut result)?;

        // Systemd security features analizi
        self.analyze_systemd_security_features(&services, &mut result)?;

        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;

        tracing::info!("Enhanced service audit tamamlandı: {} bulgu", result.findings.len());

        Ok(result)
    }
}

impl ServiceAudit {
    /// List active services
    fn get_active_services(&self) -> Result<Vec<SystemService>, ScanError> {
        let output = Command::new("systemctl")
            .args([
                "list-units",
                "--type=service",
                "--state=active",
                "--no-pager",
                "--plain",
            ])
            .output()
            .map_err(|e| ScanError::CommandError(format!("systemctl failed: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError(
                "systemctl command failed".to_string(),
            ));
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
                        unit_file_state: None,
                        load_state: None,
                        sub_state: None,
                        main_pid: None,
                    });
                }
            }
        }

        Ok(services)
    }

    /// Bilinen riskli servisleri kontrol et
    fn check_risky_services(
        &self,
        services: &[SystemService],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
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
    fn check_unnecessary_services(
        &self,
        services: &[SystemService],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        tracing::info!("Checking unnecessary services...");

        let unnecessary_patterns = vec![
            "avahi-daemon",
            "bluetooth",
            "cups",
            "ModemManager",
            "wpa_supplicant",
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

            if line.to_lowercase().starts_with("permitrootlogin")
                && line.to_lowercase().contains("yes")
            {
                root_login_enabled = true;
            }

            if line.to_lowercase().starts_with("passwordauthentication")
                && line.to_lowercase().contains("yes")
            {
                password_auth_enabled = true;
            }

            if line.to_lowercase().starts_with("permitemptypasswords")
                && line.to_lowercase().contains("yes")
            {
                permit_empty_passwords = true;
            }

            if line.to_lowercase().starts_with("protocol") && line.contains("1") {
                protocol_version_1 = true;
            }
        }

        // SSH güvenlik bulguları
        if root_login_enabled {
            let finding = Finding {
                id: "SSH-ROOT-LOGIN".to_string(),
                title: "SSH root login enabled".to_string(),
                description:
                    "SSH is configured to allow direct root login, which is a security risk."
                        .to_string(),
                severity: Severity::High,
                category: Category::Service,
                affected_item: "SSH Configuration".to_string(),
                current_value: Some("PermitRootLogin yes".to_string()),
                recommended_value: Some("PermitRootLogin no".to_string()),
                references: vec!["https://www.ssh.com/academy/ssh/sshd_config".to_string()],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        if password_auth_enabled {
            let finding = Finding {
                id: "SSH-PASSWORD-AUTH".to_string(),
                title: "SSH password authentication enabled".to_string(),
                description:
                    "SSH allows password authentication, which is less secure than key-based auth."
                        .to_string(),
                severity: Severity::Medium,
                category: Category::Service,
                affected_item: "SSH Configuration".to_string(),
                current_value: Some("PasswordAuthentication yes".to_string()),
                recommended_value: Some("PasswordAuthentication no".to_string()),
                references: vec!["https://www.ssh.com/academy/ssh/sshd_config".to_string()],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        if permit_empty_passwords {
            let finding = Finding {
                id: "SSH-EMPTY-PASSWORDS".to_string(),
                title: "SSH allows empty passwords".to_string(),
                description:
                    "SSH is configured to allow empty passwords, which is extremely dangerous."
                        .to_string(),
                severity: Severity::Critical,
                category: Category::Service,
                affected_item: "SSH Configuration".to_string(),
                current_value: Some("PermitEmptyPasswords yes".to_string()),
                recommended_value: Some("PermitEmptyPasswords no".to_string()),
                references: vec!["https://www.ssh.com/academy/ssh/sshd_config".to_string()],
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
                references: vec!["https://www.ssh.com/academy/ssh/sshd_config".to_string()],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        Ok(())
    }

    /// Network servislerini kontrol et
    fn check_network_services(
        &self,
        services: &[SystemService],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        tracing::info!("Checking network services...");

        let network_services = vec![
            "apache2",
            "nginx",
            "httpd",
            "mysql",
            "mariadb",
            "postgresql",
            "redis",
            "mongodb",
            "elasticsearch",
            "ssh",
            "sshd",
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

    /// Analyze service hardening features
    fn analyze_service_hardening(&self, services: &[SystemService], result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing service hardening features...");

        for service in services.iter().take(20) { // Limit to first 20 services for performance
            if let Ok(output) = Command::new("systemctl")
                .args(&["show", &format!("{}.service", service.name), "--property=User,Group,PrivateTmp,ProtectSystem,ProtectHome,NoNewPrivileges"])
                .output() {
                
                let properties = String::from_utf8_lossy(&output.stdout);
                let mut user_set = false;
                let mut private_tmp = false;
                let mut protect_system = false;

                for line in properties.lines() {
                    if line.starts_with("User=") && !line.ends_with("=") && !line.ends_with("root") {
                        user_set = true;
                    }
                    if line.starts_with("PrivateTmp=yes") {
                        private_tmp = true;
                    }
                    if line.starts_with("ProtectSystem=") && (line.contains("strict") || line.contains("full")) {
                        protect_system = true;
                    }
                }

                // Check for missing hardening features
                if !user_set && self.should_have_dedicated_user(&service.name) {
                    let finding = Finding {
                        id: format!("SVC-HARDENING-USER-{}", service.name.to_uppercase().replace('-', "_")),
                        title: format!("Service running as root: {}", service.name),
                        description: format!(
                            "Service '{}' is running as root user. Consider using a dedicated service user for better security isolation.",
                            service.name
                        ),
                        severity: Severity::Medium,
                        category: Category::Service,
                        affected_item: service.name.clone(),
                        current_value: Some("User=root".to_string()),
                        recommended_value: Some("Use dedicated service user".to_string()),
                        references: vec![
                            "https://www.freedesktop.org/software/systemd/man/systemd.exec.html".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }

                if !private_tmp && self.should_have_private_tmp(&service.name) {
                    let finding = Finding {
                        id: format!("SVC-HARDENING-TMP-{}", service.name.to_uppercase().replace('-', "_")),
                        title: format!("Service lacks PrivateTmp: {}", service.name),
                        description: format!(
                            "Service '{}' does not use PrivateTmp. This feature provides a private /tmp directory for better security isolation.",
                            service.name
                        ),
                        severity: Severity::Low,
                        category: Category::Service,
                        affected_item: service.name.clone(),
                        current_value: Some("PrivateTmp=no".to_string()),
                        recommended_value: Some("PrivateTmp=yes".to_string()),
                        references: vec![
                            "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateTmp=".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }

                if !protect_system {
                    let finding = Finding {
                        id: format!("SVC-HARDENING-PROTECT-{}", service.name.to_uppercase().replace('-', "_")),
                        title: format!("Service lacks ProtectSystem: {}", service.name),
                        description: format!(
                            "Service '{}' does not use ProtectSystem. This feature makes /usr, /boot, and /etc read-only for the service.",
                            service.name
                        ),
                        severity: Severity::Low,
                        category: Category::Service,
                        affected_item: service.name.clone(),
                        current_value: Some("ProtectSystem=no".to_string()),
                        recommended_value: Some("ProtectSystem=strict".to_string()),
                        references: vec![
                            "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=".to_string(),
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

    /// Analyze port bindings and network services
    fn analyze_port_bindings(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing port bindings...");

        if let Ok(output) = Command::new("ss")
            .args(&["-tulpn"])
            .output() {
            
            let netstat_output = String::from_utf8_lossy(&output.stdout);
            let mut suspicious_bindings = 0;

            for line in netstat_output.lines() {
                if line.contains("LISTEN") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let local_address = parts[4];
                        
                        // Check for potentially risky bindings
                        if local_address.starts_with("0.0.0.0:") || local_address.starts_with(":::") {
                            suspicious_bindings += 1;
                            
                            if suspicious_bindings <= 10 { // Limit findings to avoid spam
                                let finding = Finding {
                                    id: format!("SVC-PORT-BIND-{}", suspicious_bindings),
                                    title: "Service listening on all interfaces".to_string(),
                                    description: format!(
                                        "Service is listening on all network interfaces ({}). Consider binding to specific interfaces if not needed.",
                                        local_address
                                    ),
                                    severity: Severity::Medium,
                                    category: Category::Service,
                                    affected_item: local_address.to_string(),
                                    current_value: Some("Listening on all interfaces".to_string()),
                                    recommended_value: Some("Bind to specific interface".to_string()),
                                    references: vec![
                                        "https://www.cisecurity.org/controls/".to_string(),
                                    ],
                                    cve_ids: vec![],
                                    fix_available: true,
                                };
                                result.add_finding(finding);
                            }
                        }

                        // Check for services on dangerous ports
                        if local_address.contains(":23") || local_address.contains(":21") || local_address.contains(":513") {
                            let finding = Finding {
                                id: format!("SVC-DANGEROUS-PORT-{}", local_address.replace(':', "-").replace('.', "-")),
                                title: "Service on dangerous port".to_string(),
                                description: format!(
                                    "Service is listening on a potentially dangerous port ({}). These ports are associated with insecure protocols.",
                                    local_address
                                ),
                                severity: Severity::High,
                                category: Category::Service,
                                affected_item: local_address.to_string(),
                                current_value: Some("Active".to_string()),
                                recommended_value: Some("Use secure alternatives".to_string()),
                                references: vec![
                                    "https://www.iana.org/assignments/service-names-port-numbers/".to_string(),
                                ],
                                cve_ids: vec![],
                                fix_available: true,
                            };
                            result.add_finding(finding);
                        }
                    }
                }
            }

            if suspicious_bindings > 10 {
                let finding = Finding {
                    id: "SVC-MANY-BINDINGS".to_string(),
                    title: format!("Many services listening on all interfaces ({})", suspicious_bindings),
                    description: format!(
                        "Found {} services listening on all network interfaces. Review network service configurations for security.",
                        suspicious_bindings
                    ),
                    severity: Severity::Medium,
                    category: Category::Service,
                    affected_item: "Network Services".to_string(),
                    current_value: Some(suspicious_bindings.to_string()),
                    recommended_value: Some("Review and secure network bindings".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: false,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Analyze service configurations
    fn analyze_service_configurations(&self, _services: &[SystemService], result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing service configurations...");

        // Check for common configuration issues
        let config_paths = vec![
            "/etc/apache2/apache2.conf",
            "/etc/nginx/nginx.conf", 
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "/etc/redis/redis.conf",
        ];

        for config_path in config_paths {
            if let Ok(content) = fs::read_to_string(config_path) {
                self.analyze_config_security(&content, config_path, result)?;
            }
        }

        Ok(())
    }

    /// Analyze running processes for security issues
    fn analyze_running_processes(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing running processes...");

        if let Ok(output) = Command::new("ps")
            .args(&["aux", "--no-headers"])
            .output() {
            
            let ps_output = String::from_utf8_lossy(&output.stdout);
            let mut root_processes = 0;
            let mut suspicious_processes = 0;

            for line in ps_output.lines().take(100) { // Limit to avoid performance issues
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 11 {
                    let user = parts[0];
                    let command = parts.get(10..).unwrap_or(&[]).join(" ");

                    if user == "root" {
                        root_processes += 1;
                    }

                    // Check for suspicious processes
                    if self.is_suspicious_process(&command) {
                        suspicious_processes += 1;
                        if suspicious_processes <= 5 { // Limit findings
                            let finding = Finding {
                                id: format!("SVC-SUSPICIOUS-PROC-{}", suspicious_processes),
                                title: "Suspicious process detected".to_string(),
                                description: format!(
                                    "Potentially suspicious process running: {}. Review if this process is expected.",
                                    command.chars().take(100).collect::<String>()
                                ),
                                severity: Severity::Medium,
                                category: Category::Service,
                                affected_item: command.chars().take(50).collect::<String>(),
                                current_value: Some("Running".to_string()),
                                recommended_value: Some("Review and validate".to_string()),
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
            }

            if root_processes > 50 {
                let finding = Finding {
                    id: "SVC-MANY-ROOT-PROCS".to_string(),
                    title: format!("Many processes running as root ({})", root_processes),
                    description: format!(
                        "Found {} processes running as root. Consider running services with dedicated users where possible.",
                        root_processes
                    ),
                    severity: Severity::Low,
                    category: Category::Service,
                    affected_item: "Root Processes".to_string(),
                    current_value: Some(root_processes.to_string()),
                    recommended_value: Some("Use dedicated service users".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: false,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Analyze systemd security features
    fn analyze_systemd_security_features(&self, services: &[SystemService], result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing systemd security features...");

        let important_services = vec!["ssh", "apache2", "nginx", "mysql", "postgresql", "redis"];

        for service_name in important_services {
            if services.iter().any(|s| s.name.contains(service_name)) {
                if let Ok(output) = Command::new("systemctl")
                    .args(&["show", &format!("{}.service", service_name), 
                           "--property=CapabilityBoundingSet,SystemCallFilter,RestrictAddressFamilies"])
                    .output() {
                    
                    let properties = String::from_utf8_lossy(&output.stdout);
                    let mut has_capability_restrictions = false;
                    let mut has_syscall_filter = false;

                    for line in properties.lines() {
                        if line.starts_with("CapabilityBoundingSet=") && !line.ends_with("=") {
                            has_capability_restrictions = true;
                        }
                        if line.starts_with("SystemCallFilter=") && !line.ends_with("=") {
                            has_syscall_filter = true;
                        }
                    }

                    if !has_capability_restrictions {
                        let finding = Finding {
                            id: format!("SVC-SYSTEMD-CAP-{}", service_name.to_uppercase().replace('-', "_")),
                            title: format!("Service lacks capability restrictions: {}", service_name),
                            description: format!(
                                "Service '{}' does not have capability restrictions. Consider using CapabilityBoundingSet to limit privileges.",
                                service_name
                            ),
                            severity: Severity::Medium,
                            category: Category::Service,
                            affected_item: service_name.to_string(),
                            current_value: Some("No capability restrictions".to_string()),
                            recommended_value: Some("Set CapabilityBoundingSet".to_string()),
                            references: vec![
                                "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=".to_string(),
                            ],
                            cve_ids: vec![],
                            fix_available: true,
                        };
                        result.add_finding(finding);
                    }

                    if !has_syscall_filter {
                        let finding = Finding {
                            id: format!("SVC-SYSTEMD-SYSCALL-{}", service_name.to_uppercase().replace('-', "_")),
                            title: format!("Service lacks syscall filtering: {}", service_name),
                            description: format!(
                                "Service '{}' does not use system call filtering. Consider using SystemCallFilter for additional security.",
                                service_name
                            ),
                            severity: Severity::Low,
                            category: Category::Service,
                            affected_item: service_name.to_string(),
                            current_value: Some("No syscall filtering".to_string()),
                            recommended_value: Some("Set SystemCallFilter".to_string()),
                            references: vec![
                                "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=".to_string(),
                            ],
                            cve_ids: vec![],
                            fix_available: true,
                        };
                        result.add_finding(finding);
                    }
                }
            }
        }

        Ok(())
    }

    /// Helper methods
    fn should_have_dedicated_user(&self, service_name: &str) -> bool {
        let services_needing_users = vec![
            "apache2", "nginx", "mysql", "postgresql", "redis", "mongodb", 
            "elasticsearch", "memcached", "rabbitmq", "prometheus"
        ];
        services_needing_users.iter().any(|&s| service_name.contains(s))
    }

    fn should_have_private_tmp(&self, service_name: &str) -> bool {
        let services_needing_private_tmp = vec![
            "apache2", "nginx", "mysql", "postgresql", "redis", "php-fpm"
        ];
        services_needing_private_tmp.iter().any(|&s| service_name.contains(s))
    }

    fn analyze_config_security(&self, content: &str, config_path: &str, result: &mut ScanResult) -> Result<(), ScanError> {
        // Basic security checks for configuration files
        if config_path.contains("nginx") {
            if !content.contains("server_tokens off") {
                let finding = Finding {
                    id: "SVC-NGINX-SERVER-TOKENS".to_string(),
                    title: "Nginx server tokens enabled".to_string(),
                    description: "Nginx is configured to show server version information which may aid attackers.".to_string(),
                    severity: Severity::Low,
                    category: Category::Service,
                    affected_item: config_path.to_string(),
                    current_value: Some("server_tokens on (default)".to_string()),
                    recommended_value: Some("server_tokens off".to_string()),
                    references: vec![
                        "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        if config_path.contains("apache") {
            if !content.contains("ServerTokens Prod") {
                let finding = Finding {
                    id: "SVC-APACHE-SERVER-TOKENS".to_string(),
                    title: "Apache server tokens not minimized".to_string(),
                    description: "Apache is not configured to minimize server token information disclosure.".to_string(),
                    severity: Severity::Low,
                    category: Category::Service,
                    affected_item: config_path.to_string(),
                    current_value: Some("ServerTokens default".to_string()),
                    recommended_value: Some("ServerTokens Prod".to_string()),
                    references: vec![
                        "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    fn is_suspicious_process(&self, command: &str) -> bool {
        let suspicious_patterns = vec![
            "nc -l", "netcat", "/tmp/", "wget http://", "curl http://", 
            "base64 -d", "python -c", "perl -e", "ruby -e"
        ];
        suspicious_patterns.iter().any(|&pattern| command.contains(pattern))
    }
}
