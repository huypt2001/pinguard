use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::Instant;

pub struct NetworkAudit;

#[derive(Debug, Serialize, Deserialize)]
struct NetworkConnection {
    protocol: String,
    local_address: String,
    local_port: u16,
    remote_address: String,
    remote_port: u16,
    state: String,
    process: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenPort {
    port: u16,
    protocol: String,
    service: Option<String>,
    binding: String, // 0.0.0.0, 127.0.0.1, etc.
}

impl Scanner for NetworkAudit {
    fn name(&self) -> &'static str {
        "Network Audit"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"network_audit".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Network Audit".to_string());

        tracing::info!("Starting network audit scan...");

        // Açık portları listele
        let open_ports = self.get_open_ports()?;
        result.set_items_scanned(open_ports.len() as u32);

        tracing::info!("{} açık port tespit edildi", open_ports.len());

        // Riskli portları kontrol et
        self.check_risky_ports(&open_ports, &mut result)?;

        // Network bağlantılarını kontrol et
        self.check_network_connections(&mut result)?;

        // Firewall durumunu kontrol et
        self.check_firewall_status(&mut result)?;

        // Network servisleri güvenlik kontrolü
        self.check_network_service_security(&open_ports, &mut result)?;

        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;

        tracing::info!(
            "Network audit completed: {} findings",
            result.findings.len()
        );

        Ok(result)
    }
}

impl NetworkAudit {
    /// List open ports
    fn get_open_ports(&self) -> Result<Vec<OpenPort>, ScanError> {
        let output = Command::new("ss")
            .args(&["-tuln", "--no-header"])
            .output()
            .or_else(|_| {
                // Fallback: netstat kullan
                Command::new("netstat")
                    .args(&["-tuln", "--numeric-ports"])
                    .output()
            })
            .map_err(|e| ScanError::CommandError(format!("Network command failed: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError(
                "Network listing command failed".to_string(),
            ));
        }

        let output_text = String::from_utf8_lossy(&output.stdout);
        let mut ports = Vec::new();

        for line in output_text.lines() {
            if line.trim().is_empty() || line.starts_with("Proto") || line.starts_with("Active") {
                continue;
            }

            if let Some(port) = self.parse_network_line(line) {
                ports.push(port);
            }
        }

        Ok(ports)
    }

    /// Network satırını parse et
    fn parse_network_line(&self, line: &str) -> Option<OpenPort> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        let protocol = parts[0].to_lowercase();
        let local_addr = parts[3]; // ss format: address:port

        if let Some(colon_pos) = local_addr.rfind(':') {
            let address_part = &local_addr[..colon_pos];
            let port_part = &local_addr[colon_pos + 1..];

            if let Ok(port) = port_part.parse::<u16>() {
                return Some(OpenPort {
                    port,
                    protocol: if protocol.starts_with("tcp") {
                        "tcp".to_string()
                    } else {
                        "udp".to_string()
                    },
                    service: self.identify_service(port),
                    binding: address_part.to_string(),
                });
            }
        }

        None
    }

    /// Porttan servisi tanımla
    fn identify_service(&self, port: u16) -> Option<String> {
        match port {
            21 => Some("FTP".to_string()),
            22 => Some("SSH".to_string()),
            23 => Some("Telnet".to_string()),
            25 => Some("SMTP".to_string()),
            53 => Some("DNS".to_string()),
            80 => Some("HTTP".to_string()),
            110 => Some("POP3".to_string()),
            143 => Some("IMAP".to_string()),
            443 => Some("HTTPS".to_string()),
            993 => Some("IMAPS".to_string()),
            995 => Some("POP3S".to_string()),
            3306 => Some("MySQL".to_string()),
            5432 => Some("PostgreSQL".to_string()),
            6379 => Some("Redis".to_string()),
            27017 => Some("MongoDB".to_string()),
            _ => None,
        }
    }

    /// Check risky ports
    fn check_risky_ports(
        &self,
        ports: &[OpenPort],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        tracing::info!("Checking risky ports...");

        let risky_ports = vec![
            (21, "FTP", Severity::High, "Unencrypted file transfer"),
            (23, "Telnet", Severity::High, "Unencrypted remote access"),
            (25, "SMTP", Severity::Medium, "Mail server"),
            (110, "POP3", Severity::Medium, "Unencrypted mail"),
            (143, "IMAP", Severity::Medium, "Unencrypted mail"),
            (512, "rexec", Severity::High, "Remote execution"),
            (513, "rlogin", Severity::High, "Remote login"),
            (514, "rsh", Severity::High, "Remote shell"),
            (1433, "MSSQL", Severity::Medium, "Database server"),
            (3389, "RDP", Severity::Medium, "Remote desktop"),
            (5900, "VNC", Severity::Medium, "Remote desktop"),
            (6000, "X11", Severity::Medium, "X Windows"),
        ];

        for port in ports {
            for (risky_port, service, severity, description) in &risky_ports {
                if port.port == *risky_port {
                    let is_public = port.binding == "0.0.0.0" || port.binding == "::";
                    let severity = if is_public {
                        severity.clone()
                    } else {
                        match severity {
                            Severity::High => Severity::Medium,
                            Severity::Medium => Severity::Low,
                            other => other.clone(),
                        }
                    };

                    let finding = Finding {
                        id: format!("NET-RISKY-PORT-{}", risky_port),
                        title: format!("Risky service on port {}: {}", risky_port, service),
                        description: format!(
                            "Potentially risky service '{}' is listening on port {} ({}). {}. Binding: {}",
                            service, risky_port, port.protocol.to_uppercase(), description, port.binding
                        ),
                        severity,
                        category: Category::Network,
                        affected_item: format!("Port {}/{}", risky_port, port.protocol),
                        current_value: Some(format!("listening on {}", port.binding)),
                        recommended_value: Some("Review necessity and secure".to_string()),
                        references: vec![
                            "https://www.cisecurity.org/controls/".to_string(),
                            "https://nvd.nist.gov/".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }
            }
        }

        // Yaygın olmayan yüksek portları kontrol et
        for port in ports {
            if port.port > 1024 && port.port < 65535 && port.binding == "0.0.0.0" {
                if !self.is_common_port(port.port) {
                    let finding = Finding {
                        id: format!("NET-UNUSUAL-PORT-{}", port.port),
                        title: format!("Unusual service on public port: {}", port.port),
                        description: format!(
                            "Service listening on unusual port {} is publicly accessible. This might be intentional but should be reviewed.",
                            port.port
                        ),
                        severity: Severity::Low,
                        category: Category::Network,
                        affected_item: format!("Port {}/{}", port.port, port.protocol),
                        current_value: Some("publicly accessible".to_string()),
                        recommended_value: Some("Review and secure if needed".to_string()),
                        references: vec![
                            "https://www.iana.org/assignments/service-names-port-numbers/".to_string(),
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

    /// Yaygın port kontrolü
    fn is_common_port(&self, port: u16) -> bool {
        let common_ports = vec![
            22, 80, 443, 8080, 8443, 8000, 3000, 9000, 9090, 3306, 5432, 6379, 27017, 5000, 5001,
            8888, 9999,
        ];
        common_ports.contains(&port)
    }

    /// Check network connections
    fn check_network_connections(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking network connections...");

        let output = Command::new("ss")
            .args(&["-tuln", "--no-header"])
            .output()
            .or_else(|_| Command::new("netstat").args(&["-tuln"]).output());

        if let Ok(output) = output {
            if output.status.success() {
                let output_text = String::from_utf8_lossy(&output.stdout);
                let mut public_services = 0;

                for line in output_text.lines() {
                    if line.contains("0.0.0.0:") || line.contains(":::") {
                        public_services += 1;
                    }
                }

                if public_services > 5 {
                    let finding = Finding {
                        id: "NET-MANY-PUBLIC-SERVICES".to_string(),
                        title: "Many services listening publicly".to_string(),
                        description: format!(
                            "Found {} services listening on public interfaces. This may increase attack surface.",
                            public_services
                        ),
                        severity: Severity::Medium,
                        category: Category::Network,
                        affected_item: "Network Services".to_string(),
                        current_value: Some(format!("{} public services", public_services)),
                        recommended_value: Some("Review and minimize public services".to_string()),
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

    /// Check firewall status
    fn check_firewall_status(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking firewall status...");

        // UFW kontrolü
        let ufw_output = Command::new("ufw").arg("status").output();

        if let Ok(output) = ufw_output {
            let output_text = String::from_utf8_lossy(&output.stdout);
            if output_text.contains("Status: inactive") {
                let finding = Finding {
                    id: "NET-UFW-DISABLED".to_string(),
                    title: "UFW firewall is disabled".to_string(),
                    description: "UFW (Uncomplicated Firewall) is disabled. A firewall helps protect against unauthorized network access.".to_string(),
                    severity: Severity::Medium,
                    category: Category::Network,
                    affected_item: "UFW Firewall".to_string(),
                    current_value: Some("inactive".to_string()),
                    recommended_value: Some("active".to_string()),
                    references: vec![
                        "https://help.ubuntu.com/community/UFW".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        // iptables kontrolü
        let iptables_output = Command::new("iptables").args(&["-L", "-n"]).output();

        if let Ok(output) = iptables_output {
            let output_text = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_text.lines().collect();

            // Çok basit bir iptables kontrolü
            let mut has_rules = false;
            for line in &lines {
                if line.contains("ACCEPT") || line.contains("DROP") || line.contains("REJECT") {
                    if !line.contains("Chain") && !line.trim().is_empty() {
                        has_rules = true;
                        break;
                    }
                }
            }

            if !has_rules {
                let finding = Finding {
                    id: "NET-NO-IPTABLES-RULES".to_string(),
                    title: "No iptables firewall rules detected".to_string(),
                    description: "No custom iptables rules detected. Consider implementing firewall rules for better security.".to_string(),
                    severity: Severity::Low,
                    category: Category::Network,
                    affected_item: "iptables".to_string(),
                    current_value: Some("no custom rules".to_string()),
                    recommended_value: Some("implement firewall rules".to_string()),
                    references: vec![
                        "https://netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Network servisleri güvenlik kontrolü
    fn check_network_service_security(
        &self,
        ports: &[OpenPort],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        tracing::info!("Network servisleri güvenlik kontrolü...");

        // HTTP vs HTTPS kontrolü
        let mut has_http = false;
        let mut has_https = false;

        for port in ports {
            if port.port == 80 {
                has_http = true;
            }
            if port.port == 443 {
                has_https = true;
            }
        }

        if has_http && !has_https {
            let finding = Finding {
                id: "NET-HTTP-NO-HTTPS".to_string(),
                title: "HTTP service without HTTPS".to_string(),
                description: "HTTP service is running on port 80 but no HTTPS service detected on port 443. Consider implementing HTTPS for secure communication.".to_string(),
                severity: Severity::Medium,
                category: Category::Network,
                affected_item: "HTTP Service".to_string(),
                current_value: Some("HTTP only".to_string()),
                recommended_value: Some("Implement HTTPS".to_string()),
                references: vec![
                    "https://letsencrypt.org/".to_string(),
                    "https://www.ssllabs.com/projects/best-practices/".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        // SSH port kontrolü
        for port in ports {
            if port.port == 22 && port.binding == "0.0.0.0" {
                let finding = Finding {
                    id: "NET-SSH-DEFAULT-PORT".to_string(),
                    title: "SSH running on default port 22".to_string(),
                    description: "SSH service is running on the default port 22 and is publicly accessible. Consider changing to a non-standard port to reduce automated attacks.".to_string(),
                    severity: Severity::Low,
                    category: Category::Network,
                    affected_item: "SSH Service".to_string(),
                    current_value: Some("port 22".to_string()),
                    recommended_value: Some("non-standard port".to_string()),
                    references: vec![
                        "https://www.ssh.com/academy/ssh/port".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }
}
