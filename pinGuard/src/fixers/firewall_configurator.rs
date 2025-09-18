use super::{Fixer, FixResult, FixError, FixPlan, FixStatus, RiskLevel, execute_command};
use crate::scanners::Finding;
use std::time::{Duration, Instant};
use std::fs;

pub struct FirewallConfigurator;

impl Fixer for FirewallConfigurator {
    fn name(&self) -> &'static str {
        "Firewall Configurator"
    }

    fn can_fix(&self, finding: &Finding) -> bool {
        // Can fix findings related to network and firewall
        finding.id.starts_with("NET-") ||
        finding.affected_item.contains("firewall") ||
        finding.affected_item.contains("ufw") ||
        finding.affected_item.contains("iptables") ||
        finding.title.contains("firewall") ||
        finding.title.contains("port") ||
        finding.title.contains("UFW")
    }

    fn fix(&self, finding: &Finding, _config: &crate::core::config::Config) -> Result<FixResult, FixError> {
        let start_time = Instant::now();
        let mut result = FixResult::new(finding.id.clone(), self.name().to_string());

        tracing::info!("Firewall configuration starting: {}", finding.title);

        // Choose appropriate fix method based on finding type
        if finding.id.starts_with("NET-UFW-DISABLED") {
            self.enable_ufw_firewall(&mut result)?;
        } else if finding.id.starts_with("NET-NO-IPTABLES-RULES") {
            self.configure_basic_iptables(&mut result)?;
        } else if finding.id.starts_with("NET-RISKY-PORT") {
            self.block_risky_port(finding, &mut result)?;
        } else if finding.id.starts_with("NET-UNUSUAL-PORT") {
            self.review_unusual_port(finding, &mut result)?;
        } else if finding.id.starts_with("NET-SSH-DEFAULT-PORT") {
            self.configure_ssh_port_security(finding, &mut result)?;
        } else if finding.id.starts_with("NET-HTTP-NO-HTTPS") {
            self.configure_web_security(&mut result)?;
        } else {
            return Err(FixError::UnsupportedFix(format!("Unsupported firewall fix: {}", finding.id)));
        }

        result = result.set_duration(start_time);
        tracing::info!("Firewall configuration completed: {}", result.message);
        
        Ok(result)
    }

    fn dry_run(&self, finding: &Finding) -> Result<FixPlan, FixError> {
        let mut plan = FixPlan::new(
            finding.id.clone(),
            self.name().to_string(),
            format!("Configure firewall for: {}", finding.title)
        );

        if finding.id.starts_with("NET-UFW-DISABLED") {
            plan = plan
                .add_command("ufw --force enable".to_string())
                .add_command("ufw default deny incoming".to_string())
                .add_command("ufw default allow outgoing".to_string())
                .set_risk(RiskLevel::Medium)
                .set_duration(Duration::from_secs(120));
        } else if finding.id.starts_with("NET-NO-IPTABLES-RULES") {
            plan = plan
                .requires_backup()
                .add_file("/etc/iptables/rules.v4".to_string())
                .add_command("iptables-save".to_string())
                .set_risk(RiskLevel::High)
                .set_duration(Duration::from_secs(300));
        } else if finding.id.starts_with("NET-RISKY-PORT") {
            let port = self.extract_port_from_finding(finding)?;
            plan = plan
                .add_command(format!("ufw deny {}", port))
                .set_risk(RiskLevel::Medium)
                .set_duration(Duration::from_secs(60));
        }

        Ok(plan)
    }
}

impl FirewallConfigurator {
    /// Enable UFW firewall and set basic rules
    fn enable_ufw_firewall(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Enabling UFW firewall...");

        // Check if UFW is installed
        let ufw_check = execute_command("which", &["ufw"]);
        if ufw_check.is_err() {
            return Err(FixError::CommandError("UFW is not installed".to_string()));
        }

        // Set default policies
        let _output = execute_command("ufw", &["--force", "default", "deny", "incoming"])?;
        result.commands_executed.push("ufw default deny incoming".to_string());

        let _output = execute_command("ufw", &["--force", "default", "allow", "outgoing"])?;
        result.commands_executed.push("ufw default allow outgoing".to_string());

        // Allow essential services
        self.configure_essential_services(result)?;

        // Enable UFW
        let _output = execute_command("ufw", &["--force", "enable"])?;
        result.commands_executed.push("ufw --force enable".to_string());

        // Check UFW status
        let status_output = execute_command("ufw", &["status"])?;
        if status_output.contains("Status: active") {
            result.status = FixStatus::Success;
            result.message = "UFW firewall enabled with secure default rules".to_string();
        } else {
            result.status = FixStatus::Failed;
            result.message = "Failed to enable UFW firewall".to_string();
        }

        Ok(())
    }

    /// Configure essential services
    fn configure_essential_services(&self, result: &mut FixResult) -> Result<(), FixError> {
        // Allow SSH (default port)
        let _output = execute_command("ufw", &["allow", "ssh"])?;
        result.commands_executed.push("ufw allow ssh".to_string());

        // Allow HTTP and HTTPS (if web server exists)
        let _output = execute_command("ufw", &["allow", "80/tcp"])?;
        result.commands_executed.push("ufw allow 80/tcp".to_string());

        let _output = execute_command("ufw", &["allow", "443/tcp"])?;
        result.commands_executed.push("ufw allow 443/tcp".to_string());

        // Allow DNS
        let _output = execute_command("ufw", &["allow", "53"])?;
        result.commands_executed.push("ufw allow 53".to_string());

        Ok(())
    }

    /// Configure basic iptables rules
    fn configure_basic_iptables(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Configuring basic iptables rules...");

        // Backup current rules
        let backup_output = execute_command("iptables-save", &[])?;
        let backup_path = "/tmp/iptables_backup.rules";
        fs::write(backup_path, backup_output)
            .map_err(|e| FixError::FileError(format!("Cannot create iptables backup: {}", e)))?;
        result.backup_created = Some(backup_path.to_string());

        // Basic iptables rules
        let rules = vec![
            // Allow loopback traffic
            ("iptables", vec!["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"]),
            ("iptables", vec!["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]),
            
            // Allow existing connections
            ("iptables", vec!["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
            
            // Allow SSH
            ("iptables", vec!["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]),
            
            // Allow HTTP/HTTPS
            ("iptables", vec!["-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"]),
            ("iptables", vec!["-A", "INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"]),
            
            // Allow DNS
            ("iptables", vec!["-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"]),
            ("iptables", vec!["-A", "INPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"]),
            
            // Reject remaining traffic
            ("iptables", vec!["-A", "INPUT", "-j", "DROP"]),
            ("iptables", vec!["-A", "FORWARD", "-j", "DROP"]),
        ];

        for (command, args) in rules {
            let _output = execute_command(command, &args)?;
            result.commands_executed.push(format!("{} {}", command, args.join(" ")));
        }

        // Make rules persistent
        self.save_iptables_rules(result)?;

        result.status = FixStatus::Success;
        result.message = "Basic iptables rules configured".to_string();

        Ok(())
    }

    /// Make iptables rules persistent
    fn save_iptables_rules(&self, result: &mut FixResult) -> Result<(), FixError> {
        // For Debian/Ubuntu
        let debian_save = execute_command("iptables-save", &["-t", "filter"]);
        if let Ok(rules) = debian_save {
            let rules_path = "/etc/iptables/rules.v4";
            
            // Create directory
            let _mkdir = execute_command("mkdir", &["-p", "/etc/iptables"]);
            
            fs::write(rules_path, rules)
                .map_err(|e| FixError::FileError(format!("Cannot save iptables rules: {}", e)))?;
            
            result.files_modified.push(rules_path.to_string());
            result.commands_executed.push("iptables-save > /etc/iptables/rules.v4".to_string());
        }

        // Enable iptables-persistent service
        let _enable = execute_command("systemctl", &["enable", "netfilter-persistent"]);

        Ok(())
    }

    /// Block risky port
    fn block_risky_port(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let port = self.extract_port_from_finding(finding)?;
        
        tracing::info!("Blocking risky port: {}", port);

        // Block port with UFW
        let ufw_result = execute_command("ufw", &["deny", &port.to_string()]);
        if ufw_result.is_ok() {
            result.commands_executed.push(format!("ufw deny {}", port));
        } else {
            // Block with iptables
            let _output = execute_command("iptables", &["-A", "INPUT", "-p", "tcp", "--dport", &port.to_string(), "-j", "DROP"])?;
            result.commands_executed.push(format!("iptables -A INPUT -p tcp --dport {} -j DROP", port));
        }

        result.status = FixStatus::Success;
        result.message = format!("Risky port {} blocked", port);

        Ok(())
    }

    /// Review unusual port
    fn review_unusual_port(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        let port = self.extract_port_from_finding(finding)?;
        
        tracing::info!("Reviewing unusual port: {}", port);

        // Get port information
        let netstat_output = execute_command("netstat", &["-tulnp"]);
        if let Ok(output) = netstat_output {
            if output.contains(&format!(":{}", port)) {
                result.status = FixStatus::RequiresUserAction;
                result.message = format!("Unusual port {} detected. Review if this service is necessary. Use 'ufw deny {}' to block if not needed.", port, port);
            }
        }

        Ok(())
    }

    /// Configure SSH port security
    fn configure_ssh_port_security(&self, _finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Configuring SSH port security...");

        // SSH bruteforce protection
        let ssh_protection_rules = vec![
            // SSH connection rate limiting
            ("iptables", vec!["-A", "INPUT", "-p", "tcp", "--dport", "22", "-m", "state", "--state", "NEW", "-m", "recent", "--set"]),
            ("iptables", vec!["-A", "INPUT", "-p", "tcp", "--dport", "22", "-m", "state", "--state", "NEW", "-m", "recent", "--update", "--seconds", "60", "--hitcount", "4", "-j", "DROP"]),
        ];

        for (command, args) in ssh_protection_rules {
            let rule_result = execute_command(command, &args);
            if rule_result.is_ok() {
                result.commands_executed.push(format!("{} {}", command, args.join(" ")));
            }
        }

        result.status = FixStatus::Success;
        result.message = "SSH port security configured with rate limiting".to_string();

        Ok(())
    }

    /// Configure web security
    fn configure_web_security(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Configuring web security...");

        // Redirect HTTP traffic to HTTPS
        result.status = FixStatus::RequiresUserAction;
        result.message = "Configure HTTPS redirect and SSL certificates. Consider using Let's Encrypt for free SSL certificates.".to_string();

        Ok(())
    }

    /// Extract port number from finding
    fn extract_port_from_finding(&self, finding: &Finding) -> Result<u16, FixError> {
        // Extract port number from "Port 22/tcp" format
        if finding.affected_item.starts_with("Port ") {
            let port_part = finding.affected_item.replace("Port ", "").split('/').next().unwrap_or("").to_string();
            return port_part.parse::<u16>()
                .map_err(|_| FixError::ConfigError(format!("Invalid port number: {}", port_part)));
        }

        // Extract port number from title
        if let Some(port_str) = self.extract_number_from_text(&finding.title) {
            return port_str.parse::<u16>()
                .map_err(|_| FixError::ConfigError(format!("Invalid port number: {}", port_str)));
        }

        Err(FixError::ConfigError(format!("Cannot extract port from finding: {}", finding.id)))
    }

    /// Extract number from text
    fn extract_number_from_text(&self, text: &str) -> Option<String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        for word in words {
            if word.chars().all(|c| c.is_ascii_digit()) {
                return Some(word.to_string());
            }
        }
        None
    }

    /// Comprehensive firewall configuration for entire system
    pub fn configure_comprehensive_firewall(&self) -> Result<Vec<FixResult>, FixError> {
        let mut results = Vec::new();

        // Enable UFW
        let mut ufw_result = FixResult::new("NET-UFW-COMPREHENSIVE".to_string(), self.name().to_string());
        if let Err(e) = self.enable_ufw_firewall(&mut ufw_result) {
            tracing::error!("Failed to enable UFW: {}", e);
        }
        results.push(ufw_result);

        // Block risky services
        let risky_ports = vec![21, 23, 25, 135, 139, 445, 1433, 3389, 5900];
        for port in risky_ports {
            let mut port_result = FixResult::new(
                format!("NET-RISKY-PORT-BLOCK-{}", port),
                self.name().to_string()
            );
            
            if let Err(e) = self.block_specific_port(port, &mut port_result) {
                tracing::warn!("Failed to block risky port {}: {}", port, e);
            }
            results.push(port_result);
        }

        // Add DDoS protection
        let mut ddos_result = FixResult::new("NET-DDOS-PROTECTION".to_string(), self.name().to_string());
        if let Err(e) = self.configure_ddos_protection(&mut ddos_result) {
            tracing::error!("Failed to configure DDoS protection: {}", e);
        }
        results.push(ddos_result);

        Ok(results)
    }

    /// Block specific port
    fn block_specific_port(&self, port: u16, result: &mut FixResult) -> Result<(), FixError> {
        let _output = execute_command("ufw", &["deny", &port.to_string()])?;
        result.commands_executed.push(format!("ufw deny {}", port));
        result.status = FixStatus::Success;
        result.message = format!("Port {} blocked", port);
        Ok(())
    }

    /// Configure DDoS protection
    fn configure_ddos_protection(&self, result: &mut FixResult) -> Result<(), FixError> {
        let ddos_rules = vec![
            // SYN flood protection
            ("iptables", vec!["-A", "INPUT", "-p", "tcp", "--syn", "-m", "limit", "--limit", "1/s", "--limit-burst", "3", "-j", "ACCEPT"]),
            
            // Ping flood protection
            ("iptables", vec!["-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-m", "limit", "--limit", "1/s", "-j", "ACCEPT"]),
            
            // Port scan protection
            ("iptables", vec!["-A", "INPUT", "-m", "recent", "--name", "portscan", "--rcheck", "--seconds", "86400", "-j", "DROP"]),
            ("iptables", vec!["-A", "INPUT", "-m", "recent", "--name", "portscan", "--remove"]),
        ];

        for (command, args) in ddos_rules {
            let rule_result = execute_command(command, &args);
            if rule_result.is_ok() {
                result.commands_executed.push(format!("{} {}", command, args.join(" ")));
            }
        }

        result.status = FixStatus::Success;
        result.message = "DDoS protection configured".to_string();

        Ok(())
    }

    /// Check firewall status and report
    pub fn audit_firewall_status(&self) -> Result<FixResult, FixError> {
        let mut result = FixResult::new("NET-FIREWALL-AUDIT".to_string(), self.name().to_string());

        // UFW status
        let ufw_status = execute_command("ufw", &["status"]);
        let mut status_info = Vec::new();

        if let Ok(output) = ufw_status {
            if output.contains("Status: active") {
                status_info.push("UFW: Active".to_string());
            } else {
                status_info.push("UFW: Inactive".to_string());
            }
        }

        // iptables rules
        let iptables_rules = execute_command("iptables", &["-L", "-n"]);
        if let Ok(output) = iptables_rules {
            let rule_count = output.lines().count();
            status_info.push(format!("iptables rules: {} lines", rule_count));
        }

        result.status = FixStatus::Success;
        result.message = format!("Firewall audit completed: {}", status_info.join(", "));

        Ok(result)
    }
}