use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::Instant;
use std::collections::{HashMap, HashSet};
use std::fs;

pub struct NetworkAudit;

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
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

#[derive(Debug, Serialize, Deserialize)]
struct FirewallRule {
    chain: String,
    target: String,
    source: Option<String>,
    destination: Option<String>,
    port: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SSLConfiguration {
    service: String,
    port: u16,
    certificate_valid: bool,
    protocols: Vec<String>,
    cipher_strength: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NetworkInterface {
    name: String,
    ip_addresses: Vec<String>,
    mac_address: Option<String>,
    mtu: Option<u32>,
    is_up: bool,
}

impl Scanner for NetworkAudit {
    fn name(&self) -> &'static str {
        "network_audit"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"network_audit".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Enhanced Network Security Audit".to_string());

        tracing::info!("Starting enhanced network audit scan...");

        // Açık portları listele
        let open_ports = self.get_open_ports()?;
        result.set_items_scanned(open_ports.len() as u32);

        tracing::info!("{} açık port tespit edildi", open_ports.len());

        // Temel güvenlik kontrolleri
        self.check_risky_ports(&open_ports, &mut result)?;
        self.check_network_connections(&mut result)?;
        self.check_firewall_status(&mut result)?;
        self.check_network_service_security(&open_ports, &mut result)?;

        // Gelişmiş güvenlik analizleri
        self.analyze_firewall_rules(&mut result)?;
        self.check_network_interfaces(&mut result)?;
        self.analyze_ssl_configurations(&open_ports, &mut result)?;
        self.check_dns_security(&mut result)?;
        self.analyze_network_traffic_patterns(&mut result)?;

        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;

        tracing::info!(
            "Enhanced network audit completed: {} findings",
            result.findings.len()
        );

        Ok(result)
    }
}

impl NetworkAudit {
    /// List open ports
    fn get_open_ports(&self) -> Result<Vec<OpenPort>, ScanError> {
        let output = Command::new("ss")
            .args(["-tuln", "--no-header"])
            .output()
            .or_else(|_| {
                // Fallback: netstat kullan
                Command::new("netstat")
                    .args(["-tuln", "--numeric-ports"])
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
            if port.port > 1024
                && port.port < 65535
                && port.binding == "0.0.0.0"
                && !self.is_common_port(port.port)
            {
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

        Ok(())
    }

    /// Yaygın port kontrolü
    fn is_common_port(&self, port: u16) -> bool {
        let common_ports = [
            22, 80, 443, 8080, 8443, 8000, 3000, 9000, 9090, 3306, 5432, 6379, 27017, 5000, 5001,
            8888, 9999,
        ];
        common_ports.contains(&port)
    }

    /// Check network connections
    fn check_network_connections(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking network connections...");

        let output = Command::new("ss")
            .args(["-tuln", "--no-header"])
            .output()
            .or_else(|_| Command::new("netstat").args(["-tuln"]).output());

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
        let iptables_output = Command::new("iptables").args(["-L", "-n"]).output();

        if let Ok(output) = iptables_output {
            let output_text = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_text.lines().collect();

            // Çok basit bir iptables kontrolü
            let mut has_rules = false;
            for line in &lines {
                if (line.contains("ACCEPT") || line.contains("DROP") || line.contains("REJECT"))
                    && !line.contains("Chain")
                    && !line.trim().is_empty()
                {
                    has_rules = true;
                    break;
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

    /// Analyze firewall rules in detail
    fn analyze_firewall_rules(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing firewall rules in detail...");

        // Check iptables rules
        if let Ok(output) = Command::new("iptables").args(&["-L", "-n", "-v"]).output() {
            let rules_output = String::from_utf8_lossy(&output.stdout);
            self.analyze_iptables_rules(&rules_output, result)?;
        }

        // Check UFW status if available
        if let Ok(output) = Command::new("ufw").args(&["status", "verbose"]).output() {
            let ufw_output = String::from_utf8_lossy(&output.stdout);
            self.analyze_ufw_configuration(&ufw_output, result)?;
        }

        // Check firewalld if available
        if let Ok(output) = Command::new("firewall-cmd").args(&["--list-all"]).output() {
            let firewalld_output = String::from_utf8_lossy(&output.stdout);
            self.analyze_firewalld_configuration(&firewalld_output, result)?;
        }

        Ok(())
    }

    /// Check network interfaces for security issues
    fn check_network_interfaces(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking network interfaces...");

        if let Ok(output) = Command::new("ip").args(&["addr", "show"]).output() {
            let interfaces_output = String::from_utf8_lossy(&output.stdout);
            let interfaces = self.parse_network_interfaces(&interfaces_output);

            for interface in interfaces {
                // Check for promiscuous mode
                if let Ok(flags_output) = Command::new("ip")
                    .args(&["link", "show", &interface.name])
                    .output() 
                {
                    let flags = String::from_utf8_lossy(&flags_output.stdout);
                    if flags.contains("PROMISC") {
                        let finding = Finding {
                            id: format!("NET-PROMISC-{}", interface.name.to_uppercase()),
                            title: format!("Interface in promiscuous mode: {}", interface.name),
                            description: format!(
                                "Network interface '{}' is in promiscuous mode, which allows it to capture all network traffic. This could be a security risk.",
                                interface.name
                            ),
                            severity: Severity::Medium,
                            category: Category::Network,
                            affected_item: interface.name.clone(),
                            current_value: Some("Promiscuous mode enabled".to_string()),
                            recommended_value: Some("Disable promiscuous mode if not needed".to_string()),
                            references: vec![
                                "https://en.wikipedia.org/wiki/Promiscuous_mode".to_string(),
                            ],
                            cve_ids: vec![],
                            fix_available: true,
                        };
                        result.add_finding(finding);
                    }
                }

                // Check for unusual IP addresses or configurations
                for ip in &interface.ip_addresses {
                    if ip.starts_with("169.254.") {
                        let finding = Finding {
                            id: format!("NET-APIPA-{}", interface.name.to_uppercase()),
                            title: format!("APIPA address detected: {}", interface.name),
                            description: format!(
                                "Interface '{}' has an APIPA address ({}), indicating potential DHCP issues.",
                                interface.name, ip
                            ),
                            severity: Severity::Low,
                            category: Category::Network,
                            affected_item: format!("{}:{}", interface.name, ip),
                            current_value: Some(ip.clone()),
                            recommended_value: Some("Configure proper IP addressing".to_string()),
                            references: vec![
                                "https://en.wikipedia.org/wiki/Link-local_address".to_string(),
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

    /// Analyze SSL/TLS configurations
    fn analyze_ssl_configurations(&self, ports: &[OpenPort], result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing SSL/TLS configurations...");

        let ssl_ports = vec![443, 993, 995, 8443, 9443];
        
        for port in ports {
            if ssl_ports.contains(&port.port) {
                self.check_ssl_service(port, result)?;
            }
        }

        // Check for SSL certificate files
        let cert_paths = vec![
            "/etc/ssl/certs/",
            "/etc/nginx/ssl/",
            "/etc/apache2/ssl/",
            "/opt/*/ssl/",
        ];

        for cert_path in cert_paths {
            if let Ok(entries) = fs::read_dir(cert_path) {
                let mut cert_count = 0;
                let mut expired_certs = 0;

                for entry in entries.flatten() {
                    if let Some(filename) = entry.file_name().to_str() {
                        if filename.ends_with(".crt") || filename.ends_with(".pem") {
                            cert_count += 1;
                            
                            // Check certificate expiration (basic check)
                            if let Ok(output) = Command::new("openssl")
                                .args(&["x509", "-in", &entry.path().to_string_lossy(), "-noout", "-enddate"])
                                .output() 
                            {
                                let cert_info = String::from_utf8_lossy(&output.stdout);
                                if cert_info.contains("notAfter=") {
                                    // Simple check - would need proper date parsing for production
                                    if self.is_certificate_near_expiry(&cert_info) {
                                        expired_certs += 1;
                                    }
                                }
                            }
                        }
                    }
                }

                if expired_certs > 0 {
                    let finding = Finding {
                        id: format!("NET-SSL-EXPIRED-{}", cert_path.replace('/', "-")),
                        title: "SSL certificates near expiry".to_string(),
                        description: format!(
                            "Found {} SSL certificates in '{}' that are near expiry or expired.",
                            expired_certs, cert_path
                        ),
                        severity: Severity::High,
                        category: Category::Network,
                        affected_item: cert_path.to_string(),
                        current_value: Some(format!("{} expired", expired_certs)),
                        recommended_value: Some("Renew certificates".to_string()),
                        references: vec![
                            "https://letsencrypt.org/docs/".to_string(),
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

    /// Check DNS security configurations
    fn check_dns_security(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking DNS security...");

        // Check DNS resolvers
        if let Ok(resolv_content) = fs::read_to_string("/etc/resolv.conf") {
            let mut has_secure_dns = false;
            let mut dns_servers = Vec::new();

            for line in resolv_content.lines() {
                if line.starts_with("nameserver") {
                    if let Some(dns_ip) = line.split_whitespace().nth(1) {
                        dns_servers.push(dns_ip.to_string());
                        
                        // Check for secure DNS providers
                        if dns_ip == "1.1.1.1" || dns_ip == "8.8.8.8" || dns_ip == "9.9.9.9" {
                            has_secure_dns = true;
                        }
                    }
                }
            }

            if !has_secure_dns && !dns_servers.is_empty() {
                let finding = Finding {
                    id: "NET-DNS-INSECURE".to_string(),
                    title: "Using potentially insecure DNS servers".to_string(),
                    description: format!(
                        "System is using DNS servers that may not provide security features: {}. Consider using secure DNS providers.",
                        dns_servers.join(", ")
                    ),
                    severity: Severity::Medium,
                    category: Category::Network,
                    affected_item: "DNS Configuration".to_string(),
                    current_value: Some(dns_servers.join(", ")),
                    recommended_value: Some("Use secure DNS (1.1.1.1, 8.8.8.8, 9.9.9.9)".to_string()),
                    references: vec![
                        "https://developers.cloudflare.com/1.1.1.1/".to_string(),
                        "https://dns.google/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        // Check for DNS over HTTPS configuration
        let doh_configs = vec![
            "/etc/systemd/resolved.conf",
            "/etc/dnsmasq.conf",
        ];

        for config_path in doh_configs {
            if let Ok(config_content) = fs::read_to_string(config_path) {
                if !config_content.contains("DNS-over-HTTPS") && !config_content.contains("DoH") {
                    let finding = Finding {
                        id: format!("NET-NO-DOH-{}", config_path.replace('/', "-")),
                        title: "DNS over HTTPS not configured".to_string(),
                        description: format!(
                            "DNS configuration in '{}' does not include DNS over HTTPS (DoH) which provides encrypted DNS queries.",
                            config_path
                        ),
                        severity: Severity::Low,
                        category: Category::Network,
                        affected_item: config_path.to_string(),
                        current_value: Some("No DoH configuration".to_string()),
                        recommended_value: Some("Configure DNS over HTTPS".to_string()),
                        references: vec![
                            "https://en.wikipedia.org/wiki/DNS_over_HTTPS".to_string(),
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

    /// Analyze network traffic patterns
    fn analyze_network_traffic_patterns(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Analyzing network traffic patterns...");

        // Check for suspicious network connections
        if let Ok(output) = Command::new("netstat").args(&["-an"]).output() {
            let connections = String::from_utf8_lossy(&output.stdout);
            let mut suspicious_connections = 0;
            let mut foreign_connections = HashSet::new();

            for line in connections.lines() {
                if line.contains("ESTABLISHED") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let foreign_addr = parts[4];
                        if let Some(ip) = foreign_addr.split(':').next() {
                            if !ip.starts_with("127.") && !ip.starts_with("192.168.") && 
                               !ip.starts_with("10.") && !ip.starts_with("172.") {
                                foreign_connections.insert(ip.to_string());
                                suspicious_connections += 1;
                            }
                        }
                    }
                }
            }

            if suspicious_connections > 20 {
                let finding = Finding {
                    id: "NET-MANY-EXTERNAL-CONN".to_string(),
                    title: format!("Many external connections detected ({})", suspicious_connections),
                    description: format!(
                        "System has {} active connections to external IP addresses. This could indicate normal activity or potential security issues.",
                        suspicious_connections
                    ),
                    severity: Severity::Low,
                    category: Category::Network,
                    affected_item: "Network Connections".to_string(),
                    current_value: Some(suspicious_connections.to_string()),
                    recommended_value: Some("Review network connections".to_string()),
                    references: vec![
                        "https://www.cisecurity.org/controls/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: false,
                };
                result.add_finding(finding);
            }
        }

        // Check network interface statistics for anomalies
        if let Ok(output) = Command::new("cat").args(&["/proc/net/dev"]).output() {
            let net_stats = String::from_utf8_lossy(&output.stdout);
            
            for line in net_stats.lines().skip(2) { // Skip header lines
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 17 {
                    let interface = parts[0].trim_end_matches(':');
                    if interface != "lo" { // Skip loopback
                        let rx_errors = parts[3].parse::<u64>().unwrap_or(0);
                        let tx_errors = parts[11].parse::<u64>().unwrap_or(0);
                        
                        if rx_errors > 1000 || tx_errors > 1000 {
                            let finding = Finding {
                                id: format!("NET-INTERFACE-ERRORS-{}", interface.to_uppercase()),
                                title: format!("High error rate on interface: {}", interface),
                                description: format!(
                                    "Network interface '{}' has high error rates (RX: {}, TX: {}). This could indicate hardware issues or network problems.",
                                    interface, rx_errors, tx_errors
                                ),
                                severity: Severity::Medium,
                                category: Category::Network,
                                affected_item: interface.to_string(),
                                current_value: Some(format!("RX: {}, TX: {}", rx_errors, tx_errors)),
                                recommended_value: Some("Investigate network issues".to_string()),
                                references: vec![
                                    "https://www.kernel.org/doc/Documentation/networking/".to_string(),
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

        Ok(())
    }

    // Helper methods for new features
    fn analyze_iptables_rules(&self, rules_output: &str, result: &mut ScanResult) -> Result<(), ScanError> {
        let mut default_policies = HashMap::new();
        let mut rule_count = 0;

        for line in rules_output.lines() {
            if line.contains("Chain") && line.contains("policy") {
                if let Some(policy_start) = line.find("policy") {
                    let policy_part = &line[policy_start + 6..];
                    if let Some(policy_end) = policy_part.find(' ') {
                        let policy = &policy_part[..policy_end].trim();
                        let chain_name = line.split_whitespace().nth(1).unwrap_or("");
                        default_policies.insert(chain_name.to_string(), policy.to_string());
                    }
                }
            }
            if !line.is_empty() && !line.starts_with("Chain") && !line.contains("target") {
                rule_count += 1;
            }
        }

        // Check for permissive default policies
        for (chain, policy) in default_policies {
            if chain == "INPUT" && policy == "ACCEPT" {
                let finding = Finding {
                    id: "NET-IPTABLES-INPUT-ACCEPT".to_string(),
                    title: "Permissive INPUT chain default policy".to_string(),
                    description: "The INPUT chain has a default ACCEPT policy, which allows all incoming traffic by default. This is a security risk.".to_string(),
                    severity: Severity::High,
                    category: Category::Network,
                    affected_item: "iptables INPUT chain".to_string(),
                    current_value: Some("ACCEPT".to_string()),
                    recommended_value: Some("DROP".to_string()),
                    references: vec![
                        "https://netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO.html".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        if rule_count == 0 {
            let finding = Finding {
                id: "NET-NO-IPTABLES-RULES".to_string(),
                title: "No iptables rules configured".to_string(),
                description: "No custom iptables rules are configured. The system may be vulnerable to network attacks.".to_string(),
                severity: Severity::High,
                category: Category::Network,
                affected_item: "iptables configuration".to_string(),
                current_value: Some("No rules".to_string()),
                recommended_value: Some("Configure firewall rules".to_string()),
                references: vec![
                    "https://netfilter.org/documentation/".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        Ok(())
    }

    fn analyze_ufw_configuration(&self, ufw_output: &str, result: &mut ScanResult) -> Result<(), ScanError> {
        if ufw_output.contains("Status: inactive") {
            let finding = Finding {
                id: "NET-UFW-INACTIVE".to_string(),
                title: "UFW firewall is inactive".to_string(),
                description: "UFW (Uncomplicated Firewall) is installed but not active. This leaves the system without firewall protection.".to_string(),
                severity: Severity::High,
                category: Category::Network,
                affected_item: "UFW".to_string(),
                current_value: Some("inactive".to_string()),
                recommended_value: Some("Enable UFW".to_string()),
                references: vec![
                    "https://help.ubuntu.com/community/UFW".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            };
            result.add_finding(finding);
        }

        Ok(())
    }

    fn analyze_firewalld_configuration(&self, firewalld_output: &str, _result: &mut ScanResult) -> Result<(), ScanError> {
        // Basic firewalld analysis - could be expanded
        tracing::debug!("Firewalld configuration: {}", firewalld_output);
        Ok(())
    }

    fn parse_network_interfaces(&self, interfaces_output: &str) -> Vec<NetworkInterface> {
        let mut interfaces = Vec::new();
        let mut current_interface: Option<NetworkInterface> = None;

        for line in interfaces_output.lines() {
            if line.chars().next().map_or(false, |c| !c.is_whitespace()) {
                // New interface
                if let Some(interface) = current_interface.take() {
                    interfaces.push(interface);
                }

                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim().split_whitespace().next().unwrap_or("").to_string();
                    current_interface = Some(NetworkInterface {
                        name,
                        ip_addresses: Vec::new(),
                        mac_address: None,
                        mtu: None,
                        is_up: line.contains("UP"),
                    });
                }
            } else if let Some(ref mut interface) = current_interface {
                if line.trim().starts_with("inet ") {
                    if let Some(ip) = line.trim().split_whitespace().nth(1) {
                        if let Some(ip_only) = ip.split('/').next() {
                            interface.ip_addresses.push(ip_only.to_string());
                        }
                    }
                }
            }
        }

        if let Some(interface) = current_interface {
            interfaces.push(interface);
        }

        interfaces
    }

    fn check_ssl_service(&self, port: &OpenPort, result: &mut ScanResult) -> Result<(), ScanError> {
        // Basic SSL check using openssl s_client
        if let Ok(output) = Command::new("timeout")
            .args(&["5", "openssl", "s_client", "-connect", 
                   &format!("localhost:{}", port.port), "-brief"])
            .output() 
        {
            let ssl_output = String::from_utf8_lossy(&output.stderr);
            
            if ssl_output.contains("SSL3_GET_SERVER_CERTIFICATE") || ssl_output.contains("certificate verify failed") {
                let finding = Finding {
                    id: format!("NET-SSL-CERT-ISSUE-{}", port.port),
                    title: format!("SSL certificate issue on port {}", port.port),
                    description: format!(
                        "SSL service on port {} has certificate issues. This could affect secure communications.",
                        port.port
                    ),
                    severity: Severity::Medium,
                    category: Category::Network,
                    affected_item: format!("SSL service on port {}", port.port),
                    current_value: Some("Certificate issues detected".to_string()),
                    recommended_value: Some("Fix SSL certificate".to_string()),
                    references: vec![
                        "https://www.ssllabs.com/projects/best-practices/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    fn is_certificate_near_expiry(&self, cert_info: &str) -> bool {
        // Simple check - in production, would parse actual dates
        cert_info.contains("Dec 202") && cert_info.contains("2024") 
    }
}
