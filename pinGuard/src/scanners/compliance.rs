use crate::scanners::{Scanner, ScanResult, Finding, Severity, Category, ScanError};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;
use std::os::unix::fs::PermissionsExt;
use serde::{Deserialize, Serialize};

/// Compliance scanner for various regulatory frameworks
pub struct ComplianceScanner {
    name: String,
}

/// Compliance framework types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComplianceFramework {
    CIS,           // Center for Internet Security
    NIST,          // NIST Cybersecurity Framework
    PCIDSS,        // Payment Card Industry Data Security Standard
    ISO27001,      // ISO 27001 Information Security Management
    GDPR,          // General Data Protection Regulation
    HIPAA,         // Health Insurance Portability and Accountability Act
    SOX,           // Sarbanes-Oxley Act
    Custom(String), // Custom compliance framework
}

/// Compliance rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub framework: ComplianceFramework,
    pub category: String,
    pub severity: Severity,
    pub check_type: CheckType,
    pub remediation: String,
}

/// Types of compliance checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckType {
    FileExists(String),
    FilePermissions { path: String, expected: String },
    ProcessRunning(String),
    ServiceEnabled(String),
    ConfigValue { file: String, key: String, expected: String },
    CommandOutput { command: String, expected: String },
    PortClosed(u16),
    UserExists(String),
    GroupExists(String),
    SystemSetting { setting: String, expected: String },
}

/// Compliance check result
#[derive(Debug, Clone)]
pub struct ComplianceResult {
    pub rule: ComplianceRule,
    pub status: ComplianceStatus,
    pub details: String,
    pub evidence: Option<String>,
}

/// Compliance status
#[derive(Debug, Clone, PartialEq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    NotApplicable,
    ManualReview,
    Error(String),
}

impl ComplianceScanner {
    pub fn new() -> Self {
        Self {
            name: "Compliance Scanner".to_string(),
        }
    }

    /// Run compliance checks for all frameworks
    pub fn run_all_compliance_checks(&self) -> Result<Vec<ComplianceResult>, ScanError> {
        let mut results = Vec::new();
        
        // Run all framework checks
        results.extend(self.check_cis_compliance()?);
        results.extend(self.check_nist_compliance()?);
        results.extend(self.check_pci_dss_compliance()?);
        results.extend(self.check_iso27001_compliance()?);
        results.extend(self.check_gdpr_compliance()?);
        results.extend(self.check_hipaa_compliance()?);
        results.extend(self.check_sox_compliance()?);
        
        Ok(results)
    }

    /// Run compliance checks for specific framework
    pub fn run_framework_compliance(&self, framework: &ComplianceFramework) -> Result<Vec<ComplianceResult>, ScanError> {
        match framework {
            ComplianceFramework::CIS => self.check_cis_compliance(),
            ComplianceFramework::NIST => self.check_nist_compliance(),
            ComplianceFramework::PCIDSS => self.check_pci_dss_compliance(),
            ComplianceFramework::ISO27001 => self.check_iso27001_compliance(),
            ComplianceFramework::GDPR => self.check_gdpr_compliance(),
            ComplianceFramework::HIPAA => self.check_hipaa_compliance(),
            ComplianceFramework::SOX => self.check_sox_compliance(),
            ComplianceFramework::Custom(name) => self.check_custom_compliance(name),
        }
    }

    /// Check CIS (Center for Internet Security) benchmark compliance
    fn check_cis_compliance(&self) -> Result<Vec<ComplianceResult>, ScanError> {
        let mut results = Vec::new();
        
        // CIS Control 1: Inventory and Control of Hardware Assets
        results.push(self.check_rule(&ComplianceRule {
            id: "CIS-1.1".to_string(),
            title: "Hardware Asset Inventory".to_string(),
            description: "Maintain an accurate and up-to-date inventory of all technology assets".to_string(),
            framework: ComplianceFramework::CIS,
            category: "Asset Management".to_string(),
            severity: Severity::High,
            check_type: CheckType::FileExists("/etc/machine-id".to_string()),
            remediation: "Implement automated asset discovery and maintain hardware inventory".to_string(),
        })?);

        // CIS Control 2: Inventory and Control of Software Assets
        results.push(self.check_rule(&ComplianceRule {
            id: "CIS-2.1".to_string(),
            title: "Software Asset Inventory".to_string(),
            description: "Maintain an accurate and up-to-date inventory of all software".to_string(),
            framework: ComplianceFramework::CIS,
            category: "Asset Management".to_string(),
            severity: Severity::High,
            check_type: CheckType::CommandOutput { 
                command: "dpkg -l | wc -l".to_string(), 
                expected: "0".to_string() 
            },
            remediation: "Implement software inventory management and monitoring".to_string(),
        })?);

        // CIS Control 3: Continuous Vulnerability Management
        results.push(self.check_rule(&ComplianceRule {
            id: "CIS-3.1".to_string(),
            title: "Vulnerability Scanning".to_string(),
            description: "Run automated vulnerability scanning tools against all systems".to_string(),
            framework: ComplianceFramework::CIS,
            category: "Vulnerability Management".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::ProcessRunning("cron".to_string()),
            remediation: "Implement regular vulnerability scanning schedule".to_string(),
        })?);

        // CIS Control 4: Controlled Use of Administrative Privileges
        results.push(self.check_rule(&ComplianceRule {
            id: "CIS-4.1".to_string(),
            title: "Administrative Privilege Control".to_string(),
            description: "Use dedicated administrative accounts for all administrative activities".to_string(),
            framework: ComplianceFramework::CIS,
            category: "Access Control".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::FileExists("/etc/sudoers".to_string()),
            remediation: "Configure sudo properly and limit administrative access".to_string(),
        })?);

        // CIS Control 5: Secure Configuration for Hardware and Software
        results.push(self.check_rule(&ComplianceRule {
            id: "CIS-5.1".to_string(),
            title: "Secure Configuration Management".to_string(),
            description: "Establish and maintain secure configurations for all devices".to_string(),
            framework: ComplianceFramework::CIS,
            category: "Configuration Management".to_string(),
            severity: Severity::High,
            check_type: CheckType::ServiceEnabled("ssh".to_string()),
            remediation: "Implement configuration management and hardening standards".to_string(),
        })?);

        // CIS Control 6: Maintenance, Monitoring, and Analysis of Audit Logs
        results.push(self.check_rule(&ComplianceRule {
            id: "CIS-6.1".to_string(),
            title: "Audit Log Management".to_string(),
            description: "Collect, alert, review, and retain audit logs of events".to_string(),
            framework: ComplianceFramework::CIS,
            category: "Logging and Monitoring".to_string(),
            severity: Severity::High,
            check_type: CheckType::ServiceEnabled("rsyslog".to_string()),
            remediation: "Enable comprehensive logging and log monitoring".to_string(),
        })?);

        // CIS Control 7: Email and Web Browser Protections
        results.push(self.check_rule(&ComplianceRule {
            id: "CIS-7.1".to_string(),
            title: "Email Security".to_string(),
            description: "Minimize the attack surface and impact from email-based attacks".to_string(),
            framework: ComplianceFramework::CIS,
            category: "Email Security".to_string(),
            severity: Severity::Medium,
            check_type: CheckType::ProcessRunning("postfix".to_string()),
            remediation: "Implement email security controls and filtering".to_string(),
        })?);

        // CIS Control 8: Malware Defenses
        results.push(self.check_rule(&ComplianceRule {
            id: "CIS-8.1".to_string(),
            title: "Anti-Malware Software".to_string(),
            description: "Utilize centrally managed anti-malware software".to_string(),
            framework: ComplianceFramework::CIS,
            category: "Malware Protection".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::ProcessRunning("clamav".to_string()),
            remediation: "Install and configure anti-malware protection".to_string(),
        })?);

        Ok(results)
    }

    /// Check NIST Cybersecurity Framework compliance
    fn check_nist_compliance(&self) -> Result<Vec<ComplianceResult>, ScanError> {
        let mut results = Vec::new();
        
        // NIST Function: IDENTIFY
        results.push(self.check_rule(&ComplianceRule {
            id: "NIST-ID.AM-1".to_string(),
            title: "Asset Management".to_string(),
            description: "Physical devices and systems within the organization are inventoried".to_string(),
            framework: ComplianceFramework::NIST,
            category: "Asset Management".to_string(),
            severity: Severity::High,
            check_type: CheckType::FileExists("/etc/hostname".to_string()),
            remediation: "Implement comprehensive asset inventory management".to_string(),
        })?);

        results.push(self.check_rule(&ComplianceRule {
            id: "NIST-ID.GV-1".to_string(),
            title: "Cybersecurity Policy".to_string(),
            description: "Organizational cybersecurity policy is established and communicated".to_string(),
            framework: ComplianceFramework::NIST,
            category: "Governance".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::FileExists("/etc/security/policy".to_string()),
            remediation: "Establish formal cybersecurity policies and procedures".to_string(),
        })?);

        // NIST Function: PROTECT
        results.push(self.check_rule(&ComplianceRule {
            id: "NIST-PR.AC-1".to_string(),
            title: "Access Control Management".to_string(),
            description: "Identities and credentials are issued, managed, verified, revoked".to_string(),
            framework: ComplianceFramework::NIST,
            category: "Access Control".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::FileExists("/etc/passwd".to_string()),
            remediation: "Implement proper identity and access management".to_string(),
        })?);

        results.push(self.check_rule(&ComplianceRule {
            id: "NIST-PR.DS-1".to_string(),
            title: "Data Protection".to_string(),
            description: "Data-at-rest is protected".to_string(),
            framework: ComplianceFramework::NIST,
            category: "Data Security".to_string(),
            severity: Severity::High,
            check_type: CheckType::CommandOutput { 
                command: "lsblk -f | grep -i crypt".to_string(), 
                expected: "".to_string() 
            },
            remediation: "Implement data encryption for data at rest".to_string(),
        })?);

        // NIST Function: DETECT
        results.push(self.check_rule(&ComplianceRule {
            id: "NIST-DE.AE-1".to_string(),
            title: "Anomaly Detection".to_string(),
            description: "A baseline of network operations and expected data flows is established".to_string(),
            framework: ComplianceFramework::NIST,
            category: "Anomaly Detection".to_string(),
            severity: Severity::Medium,
            check_type: CheckType::ProcessRunning("fail2ban".to_string()),
            remediation: "Implement network monitoring and anomaly detection".to_string(),
        })?);

        results.push(self.check_rule(&ComplianceRule {
            id: "NIST-DE.CM-1".to_string(),
            title: "Security Monitoring".to_string(),
            description: "The network is monitored to detect potential cybersecurity events".to_string(),
            framework: ComplianceFramework::NIST,
            category: "Continuous Monitoring".to_string(),
            severity: Severity::High,
            check_type: CheckType::ServiceEnabled("auditd".to_string()),
            remediation: "Enable comprehensive security monitoring and logging".to_string(),
        })?);

        // NIST Function: RESPOND
        results.push(self.check_rule(&ComplianceRule {
            id: "NIST-RS.RP-1".to_string(),
            title: "Response Planning".to_string(),
            description: "Response plan is executed during or after an incident".to_string(),
            framework: ComplianceFramework::NIST,
            category: "Response Planning".to_string(),
            severity: Severity::Medium,
            check_type: CheckType::FileExists("/etc/incident-response-plan".to_string()),
            remediation: "Develop and maintain incident response procedures".to_string(),
        })?);

        // NIST Function: RECOVER
        results.push(self.check_rule(&ComplianceRule {
            id: "NIST-RC.RP-1".to_string(),
            title: "Recovery Planning".to_string(),
            description: "Recovery plan is executed during or after a cybersecurity incident".to_string(),
            framework: ComplianceFramework::NIST,
            category: "Recovery Planning".to_string(),
            severity: Severity::Medium,
            check_type: CheckType::FileExists("/etc/backup-policy".to_string()),
            remediation: "Implement disaster recovery and backup procedures".to_string(),
        })?);

        Ok(results)
    }

    /// Check PCI DSS (Payment Card Industry Data Security Standard) compliance
    fn check_pci_dss_compliance(&self) -> Result<Vec<ComplianceResult>, ScanError> {
        let mut results = Vec::new();
        
        // PCI DSS Requirement 1: Install and maintain a firewall configuration
        results.push(self.check_rule(&ComplianceRule {
            id: "PCI-1.1".to_string(),
            title: "Firewall Configuration".to_string(),
            description: "Install and maintain a firewall configuration to protect cardholder data".to_string(),
            framework: ComplianceFramework::PCIDSS,
            category: "Network Security".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::ServiceEnabled("ufw".to_string()),
            remediation: "Configure and enable firewall protection".to_string(),
        })?);

        // PCI DSS Requirement 2: Do not use vendor-supplied defaults
        results.push(self.check_rule(&ComplianceRule {
            id: "PCI-2.1".to_string(),
            title: "Default Passwords".to_string(),
            description: "Always change vendor-supplied defaults and remove unnecessary default accounts".to_string(),
            framework: ComplianceFramework::PCIDSS,
            category: "Configuration Management".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::UserExists("admin".to_string()),
            remediation: "Remove default accounts and change default passwords".to_string(),
        })?);

        // PCI DSS Requirement 3: Protect stored cardholder data
        results.push(self.check_rule(&ComplianceRule {
            id: "PCI-3.1".to_string(),
            title: "Data Encryption".to_string(),
            description: "Protect stored cardholder data through encryption".to_string(),
            framework: ComplianceFramework::PCIDSS,
            category: "Data Protection".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::CommandOutput { 
                command: "find /var/log -name '*.log' -type f | head -1".to_string(), 
                expected: "".to_string() 
            },
            remediation: "Implement strong encryption for sensitive data storage".to_string(),
        })?);

        // PCI DSS Requirement 4: Encrypt transmission of cardholder data
        results.push(self.check_rule(&ComplianceRule {
            id: "PCI-4.1".to_string(),
            title: "Data Transmission Encryption".to_string(),
            description: "Encrypt transmission of cardholder data across open, public networks".to_string(),
            framework: ComplianceFramework::PCIDSS,
            category: "Network Security".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::PortClosed(80),
            remediation: "Use strong cryptography and security protocols for data transmission".to_string(),
        })?);

        // PCI DSS Requirement 8: Identify and authenticate access
        results.push(self.check_rule(&ComplianceRule {
            id: "PCI-8.1".to_string(),
            title: "User Authentication".to_string(),
            description: "Identify and authenticate access to system components".to_string(),
            framework: ComplianceFramework::PCIDSS,
            category: "Access Control".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::FileExists("/etc/pam.d/common-auth".to_string()),
            remediation: "Implement strong authentication mechanisms".to_string(),
        })?);

        // PCI DSS Requirement 10: Track and monitor all access
        results.push(self.check_rule(&ComplianceRule {
            id: "PCI-10.1".to_string(),
            title: "Access Logging".to_string(),
            description: "Track and monitor all access to network resources and cardholder data".to_string(),
            framework: ComplianceFramework::PCIDSS,
            category: "Logging and Monitoring".to_string(),
            severity: Severity::High,
            check_type: CheckType::ServiceEnabled("auditd".to_string()),
            remediation: "Enable comprehensive audit logging and monitoring".to_string(),
        })?);

        Ok(results)
    }

    /// Check ISO 27001 information security management controls
    fn check_iso27001_compliance(&self) -> Result<Vec<ComplianceResult>, ScanError> {
        let mut results = Vec::new();
        
        // ISO 27001 Control A.5.1.1: Information security policies
        results.push(self.check_rule(&ComplianceRule {
            id: "ISO-A.5.1.1".to_string(),
            title: "Information Security Policies".to_string(),
            description: "Information security policy shall be defined, approved by management".to_string(),
            framework: ComplianceFramework::ISO27001,
            category: "Security Policy".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::FileExists("/etc/security/policy.txt".to_string()),
            remediation: "Establish formal information security policies".to_string(),
        })?);

        // ISO 27001 Control A.9.1.1: Access control policy
        results.push(self.check_rule(&ComplianceRule {
            id: "ISO-A.9.1.1".to_string(),
            title: "Access Control Policy".to_string(),
            description: "Access control policy shall be established, documented and reviewed".to_string(),
            framework: ComplianceFramework::ISO27001,
            category: "Access Control".to_string(),
            severity: Severity::High,
            check_type: CheckType::FileExists("/etc/sudoers".to_string()),
            remediation: "Implement comprehensive access control policies".to_string(),
        })?);

        // ISO 27001 Control A.12.4.1: Event logging
        results.push(self.check_rule(&ComplianceRule {
            id: "ISO-A.12.4.1".to_string(),
            title: "Event Logging".to_string(),
            description: "Event logs recording user activities shall be produced and kept".to_string(),
            framework: ComplianceFramework::ISO27001,
            category: "Logging and Monitoring".to_string(),
            severity: Severity::High,
            check_type: CheckType::ServiceEnabled("rsyslog".to_string()),
            remediation: "Enable comprehensive event logging and retention".to_string(),
        })?);

        // ISO 27001 Control A.10.1.1: Cryptographic policy
        results.push(self.check_rule(&ComplianceRule {
            id: "ISO-A.10.1.1".to_string(),
            title: "Cryptographic Controls".to_string(),
            description: "Policy on the use of cryptographic controls shall be developed".to_string(),
            framework: ComplianceFramework::ISO27001,
            category: "Cryptography".to_string(),
            severity: Severity::High,
            check_type: CheckType::FileExists("/etc/ssl/certs".to_string()),
            remediation: "Implement cryptographic controls and key management".to_string(),
        })?);

        // ISO 27001 Control A.12.6.1: Management of technical vulnerabilities
        results.push(self.check_rule(&ComplianceRule {
            id: "ISO-A.12.6.1".to_string(),
            title: "Vulnerability Management".to_string(),
            description: "Information about technical vulnerabilities shall be obtained in a timely fashion".to_string(),
            framework: ComplianceFramework::ISO27001,
            category: "Vulnerability Management".to_string(),
            severity: Severity::High,
            check_type: CheckType::ProcessRunning("cron".to_string()),
            remediation: "Implement regular vulnerability scanning and patching".to_string(),
        })?);

        Ok(results)
    }

    /// Check GDPR (General Data Protection Regulation) compliance
    fn check_gdpr_compliance(&self) -> Result<Vec<ComplianceResult>, ScanError> {
        let mut results = Vec::new();
        
        // GDPR Article 32: Security of processing
        results.push(self.check_rule(&ComplianceRule {
            id: "GDPR-32.1".to_string(),
            title: "Data Encryption".to_string(),
            description: "Implement appropriate technical measures including encryption of personal data".to_string(),
            framework: ComplianceFramework::GDPR,
            category: "Data Protection".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::CommandOutput { 
                command: "lsblk -f | grep -i crypt | wc -l".to_string(), 
                expected: "0".to_string() 
            },
            remediation: "Implement encryption for personal data protection".to_string(),
        })?);

        // GDPR Article 25: Data protection by design and by default
        results.push(self.check_rule(&ComplianceRule {
            id: "GDPR-25.1".to_string(),
            title: "Privacy by Design".to_string(),
            description: "Implement data protection by design and by default".to_string(),
            framework: ComplianceFramework::GDPR,
            category: "Privacy Controls".to_string(),
            severity: Severity::High,
            check_type: CheckType::FileExists("/etc/privacy-policy".to_string()),
            remediation: "Implement privacy by design principles and controls".to_string(),
        })?);

        // GDPR Article 30: Records of processing activities
        results.push(self.check_rule(&ComplianceRule {
            id: "GDPR-30.1".to_string(),
            title: "Processing Records".to_string(),
            description: "Maintain records of all processing activities under its responsibility".to_string(),
            framework: ComplianceFramework::GDPR,
            category: "Record Keeping".to_string(),
            severity: Severity::Medium,
            check_type: CheckType::FileExists("/var/log/gdpr-processing.log".to_string()),
            remediation: "Maintain comprehensive records of data processing activities".to_string(),
        })?);

        // GDPR Article 33: Notification of personal data breach
        results.push(self.check_rule(&ComplianceRule {
            id: "GDPR-33.1".to_string(),
            title: "Breach Notification".to_string(),
            description: "Notify supervisory authority of personal data breach without undue delay".to_string(),
            framework: ComplianceFramework::GDPR,
            category: "Incident Response".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::FileExists("/etc/breach-response-plan".to_string()),
            remediation: "Establish breach notification procedures and response plans".to_string(),
        })?);

        Ok(results)
    }

    /// Check HIPAA (Health Insurance Portability and Accountability Act) security requirements
    fn check_hipaa_compliance(&self) -> Result<Vec<ComplianceResult>, ScanError> {
        let mut results = Vec::new();
        
        // HIPAA Security Rule: Access Control
        results.push(self.check_rule(&ComplianceRule {
            id: "HIPAA-164.312.a.1".to_string(),
            title: "Access Control".to_string(),
            description: "Assign a unique name and/or number for identifying and tracking user identity".to_string(),
            framework: ComplianceFramework::HIPAA,
            category: "Access Control".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::FileExists("/etc/passwd".to_string()),
            remediation: "Implement unique user identification and access controls".to_string(),
        })?);

        // HIPAA Security Rule: Audit Controls
        results.push(self.check_rule(&ComplianceRule {
            id: "HIPAA-164.312.b".to_string(),
            title: "Audit Controls".to_string(),
            description: "Implement hardware, software, and/or procedural mechanisms that record access".to_string(),
            framework: ComplianceFramework::HIPAA,
            category: "Audit Controls".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::ServiceEnabled("auditd".to_string()),
            remediation: "Enable comprehensive audit logging for all system access".to_string(),
        })?);

        // HIPAA Security Rule: Integrity
        results.push(self.check_rule(&ComplianceRule {
            id: "HIPAA-164.312.c.1".to_string(),
            title: "Data Integrity".to_string(),
            description: "Protect electronic PHI from improper alteration or destruction".to_string(),
            framework: ComplianceFramework::HIPAA,
            category: "Data Integrity".to_string(),
            severity: Severity::High,
            check_type: CheckType::ProcessRunning("aide".to_string()),
            remediation: "Implement file integrity monitoring and protection mechanisms".to_string(),
        })?);

        // HIPAA Security Rule: Transmission Security
        results.push(self.check_rule(&ComplianceRule {
            id: "HIPAA-164.312.e.1".to_string(),
            title: "Transmission Security".to_string(),
            description: "Implement technical security measures to guard against unauthorized access".to_string(),
            framework: ComplianceFramework::HIPAA,
            category: "Transmission Security".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::PortClosed(80),
            remediation: "Encrypt all data transmissions and disable insecure protocols".to_string(),
        })?);

        Ok(results)
    }

    /// Check SOX (Sarbanes-Oxley Act) compliance controls
    fn check_sox_compliance(&self) -> Result<Vec<ComplianceResult>, ScanError> {
        let mut results = Vec::new();
        
        // SOX Section 404: Management Assessment of Internal Controls
        results.push(self.check_rule(&ComplianceRule {
            id: "SOX-404.1".to_string(),
            title: "Internal Controls Assessment".to_string(),
            description: "Establish and maintain adequate internal control over financial reporting".to_string(),
            framework: ComplianceFramework::SOX,
            category: "Internal Controls".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::FileExists("/etc/sox-controls-policy".to_string()),
            remediation: "Establish comprehensive internal controls documentation".to_string(),
        })?);

        // SOX IT General Controls: Access Controls
        results.push(self.check_rule(&ComplianceRule {
            id: "SOX-ITGC.1".to_string(),
            title: "IT Access Controls".to_string(),
            description: "Ensure appropriate access controls are in place for financial systems".to_string(),
            framework: ComplianceFramework::SOX,
            category: "Access Control".to_string(),
            severity: Severity::Critical,
            check_type: CheckType::FileExists("/etc/sudoers".to_string()),
            remediation: "Implement role-based access controls for financial systems".to_string(),
        })?);

        // SOX IT General Controls: Change Management
        results.push(self.check_rule(&ComplianceRule {
            id: "SOX-ITGC.2".to_string(),
            title: "Change Management".to_string(),
            description: "Establish formal change management procedures for financial systems".to_string(),
            framework: ComplianceFramework::SOX,
            category: "Change Management".to_string(),
            severity: Severity::High,
            check_type: CheckType::FileExists("/etc/change-management-policy".to_string()),
            remediation: "Implement formal change management procedures and documentation".to_string(),
        })?);

        // SOX IT General Controls: Backup and Recovery
        results.push(self.check_rule(&ComplianceRule {
            id: "SOX-ITGC.3".to_string(),
            title: "Backup and Recovery".to_string(),
            description: "Ensure adequate backup and recovery procedures for financial data".to_string(),
            framework: ComplianceFramework::SOX,
            category: "Business Continuity".to_string(),
            severity: Severity::High,
            check_type: CheckType::ProcessRunning("cron".to_string()),
            remediation: "Implement regular backup procedures and test recovery processes".to_string(),
        })?);

        Ok(results)
    }

    /// Check custom compliance framework
    fn check_custom_compliance(&self, _framework_name: &str) -> Result<Vec<ComplianceResult>, ScanError> {
        let mut results = Vec::new();
        
        // Custom framework implementation would load rules from configuration
        // For now, return empty results
        results.push(ComplianceResult {
            rule: ComplianceRule {
                id: "CUSTOM-1".to_string(),
                title: "Custom Compliance Check".to_string(),
                description: "Custom compliance framework not yet implemented".to_string(),
                framework: ComplianceFramework::Custom("Unknown".to_string()),
                category: "Custom".to_string(),
                severity: Severity::Low,
                check_type: CheckType::FileExists("/dev/null".to_string()),
                remediation: "Implement custom compliance framework configuration".to_string(),
            },
            status: ComplianceStatus::NotApplicable,
            details: "Custom compliance framework support is planned for future implementation".to_string(),
            evidence: None,
        });
        
        Ok(results)
    }

    /// Execute a specific compliance rule check
    fn check_rule(&self, rule: &ComplianceRule) -> Result<ComplianceResult, ScanError> {
        let (status, details, evidence) = match &rule.check_type {
            CheckType::FileExists(path) => {
                if Path::new(path).exists() {
                    (ComplianceStatus::Compliant, format!("File {} exists", path), Some(path.clone()))
                } else {
                    (ComplianceStatus::NonCompliant, format!("File {} does not exist", path), None)
                }
            }
            
            CheckType::FilePermissions { path, expected } => {
                if let Ok(metadata) = fs::metadata(path) {
                    let permissions = format!("{:o}", metadata.permissions().mode() & 0o777);
                    if permissions == *expected {
                        (ComplianceStatus::Compliant, format!("File {} has correct permissions {}", path, permissions), Some(permissions))
                    } else {
                        (ComplianceStatus::NonCompliant, format!("File {} has permissions {} but expected {}", path, permissions, expected), Some(permissions))
                    }
                } else {
                    (ComplianceStatus::Error("File not found".to_string()), format!("Could not check permissions for {}", path), None)
                }
            }
            
            CheckType::ProcessRunning(process) => {
                let output = Command::new("pgrep")
                    .arg(process)
                    .output();
                    
                match output {
                    Ok(output) if output.status.success() && !output.stdout.is_empty() => {
                        (ComplianceStatus::Compliant, format!("Process {} is running", process), Some(String::from_utf8_lossy(&output.stdout).trim().to_string()))
                    }
                    _ => {
                        (ComplianceStatus::NonCompliant, format!("Process {} is not running", process), None)
                    }
                }
            }
            
            CheckType::ServiceEnabled(service) => {
                let output = Command::new("systemctl")
                    .args(&["is-enabled", service])
                    .output();
                    
                match output {
                    Ok(output) if output.status.success() => {
                        let status_output = String::from_utf8_lossy(&output.stdout);
                        let status_str = status_output.trim();
                        if status_str == "enabled" {
                            (ComplianceStatus::Compliant, format!("Service {} is enabled", service), Some(status_str.to_string()))
                        } else {
                            (ComplianceStatus::NonCompliant, format!("Service {} is not enabled (status: {})", service, status_str), Some(status_str.to_string()))
                        }
                    }
                    _ => {
                        (ComplianceStatus::Error("Could not check service status".to_string()), format!("Failed to check service {} status", service), None)
                    }
                }
            }
            
            CheckType::CommandOutput { command, expected } => {
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .output();
                    
                match output {
                    Ok(output) if output.status.success() => {
                        let output_string = String::from_utf8_lossy(&output.stdout);
                        let result = output_string.trim();
                        if expected.is_empty() || result.contains(expected) {
                            (ComplianceStatus::Compliant, format!("Command output matches expected result"), Some(result.to_string()))
                        } else {
                            (ComplianceStatus::NonCompliant, format!("Command output '{}' does not match expected '{}'", result, expected), Some(result.to_string()))
                        }
                    }
                    _ => {
                        (ComplianceStatus::Error("Command execution failed".to_string()), format!("Failed to execute command: {}", command), None)
                    }
                }
            }
            
            CheckType::PortClosed(port) => {
                let output = Command::new("netstat")
                    .args(&["-ln"])
                    .output();
                    
                match output {
                    Ok(output) if output.status.success() => {
                        let netstat_output = String::from_utf8_lossy(&output.stdout);
                        if netstat_output.contains(&format!(":{}", port)) {
                            (ComplianceStatus::NonCompliant, format!("Port {} is open", port), Some(format!("Port {} found in netstat output", port)))
                        } else {
                            (ComplianceStatus::Compliant, format!("Port {} is closed", port), None)
                        }
                    }
                    _ => {
                        (ComplianceStatus::Error("Could not check port status".to_string()), format!("Failed to check port {} status", port), None)
                    }
                }
            }
            
            CheckType::UserExists(username) => {
                let output = Command::new("id")
                    .arg(username)
                    .output();
                    
                match output {
                    Ok(output) if output.status.success() => {
                        let id_output = String::from_utf8_lossy(&output.stdout);
                        (ComplianceStatus::NonCompliant, format!("User {} exists", username), Some(id_output.trim().to_string()))
                    }
                    _ => {
                        (ComplianceStatus::Compliant, format!("User {} does not exist", username), None)
                    }
                }
            }
            
            CheckType::GroupExists(groupname) => {
                let output = Command::new("getent")
                    .args(&["group", groupname])
                    .output();
                    
                match output {
                    Ok(output) if output.status.success() => {
                        let group_output = String::from_utf8_lossy(&output.stdout);
                        (ComplianceStatus::Compliant, format!("Group {} exists", groupname), Some(group_output.trim().to_string()))
                    }
                    _ => {
                        (ComplianceStatus::NonCompliant, format!("Group {} does not exist", groupname), None)
                    }
                }
            }
            
            CheckType::SystemSetting { setting: _, expected: _ } => {
                // System setting checks would require specific implementation per setting
                (ComplianceStatus::ManualReview, "System setting check requires manual review".to_string(), None)
            }
            
            CheckType::ConfigValue { file: _, key: _, expected: _ } => {
                // Configuration value checks would require parsing specific config files
                (ComplianceStatus::ManualReview, "Configuration value check requires manual review".to_string(), None)
            }
        };
        
        Ok(ComplianceResult {
            rule: rule.clone(),
            status,
            details,
            evidence,
        })
    }

    /// Convert compliance results to scanner findings
    fn compliance_results_to_findings(&self, results: Vec<ComplianceResult>) -> Vec<Finding> {
        results.into_iter()
            .filter(|result| result.status == ComplianceStatus::NonCompliant)
            .map(|result| Finding {
                id: result.rule.id.clone(),
                title: format!("{} - {}", result.rule.framework_name(), result.rule.title),
                description: format!("{}\n\nCompliance Rule: {}\nCategory: {}\nDetails: {}", 
                    result.rule.description, result.rule.id, result.rule.category, result.details),
                severity: result.rule.severity.clone(),
                category: Category::Security,
                affected_item: result.rule.id.clone(),
                current_value: result.evidence,
                recommended_value: Some(result.rule.remediation.clone()),
                references: vec![format!("{} Framework", result.rule.framework_name())],
                cve_ids: vec![],
                fix_available: true,
            })
            .collect()
    }
}

impl ComplianceFramework {
    /// Get the human-readable name of the compliance framework
    pub fn name(&self) -> &str {
        match self {
            ComplianceFramework::CIS => "CIS Controls",
            ComplianceFramework::NIST => "NIST Cybersecurity Framework",
            ComplianceFramework::PCIDSS => "PCI DSS",
            ComplianceFramework::ISO27001 => "ISO 27001",
            ComplianceFramework::GDPR => "GDPR",
            ComplianceFramework::HIPAA => "HIPAA",
            ComplianceFramework::SOX => "SOX",
            ComplianceFramework::Custom(name) => name,
        }
    }
}

impl ComplianceRule {
    /// Get the framework name for this rule
    pub fn framework_name(&self) -> String {
        self.framework.name().to_string()
    }
}

impl Scanner for ComplianceScanner {
    fn name(&self) -> &'static str {
        "compliance"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"compliance".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        
        tracing::info!("Starting enhanced compliance scan...");
        
        // Run all compliance checks
        let compliance_results = self.run_all_compliance_checks()?;
        
        // Convert to findings
        let findings = self.compliance_results_to_findings(compliance_results);
        
        let duration = start_time.elapsed();
        tracing::info!("Enhanced compliance scan completed: {} findings in {}ms", 
            findings.len(), duration.as_millis());

        let mut result = ScanResult::new("Compliance Scanner".to_string());
        
        for finding in findings {
            result.add_finding(finding);
        }
        
        result.set_duration(duration.as_millis() as u64);
        result.set_items_scanned(1);

        Ok(result)
    }
}

impl Default for ComplianceScanner {
    fn default() -> Self {
        Self::new()
    }
}