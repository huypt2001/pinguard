use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Web Application Security Scanner
/// Scans for web application vulnerabilities, SSL/TLS issues, and web server misconfigurations
pub struct WebSecurityScanner {
    /// Target ports to scan for web services
    target_ports: Vec<u16>,
    /// Maximum timeout for HTTP requests
    timeout_seconds: u64,
}

/// Represents a discovered web service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebService {
    pub port: u16,
    pub protocol: String, // HTTP or HTTPS
    pub server_type: Option<String>, // Apache, Nginx, etc.
    pub version: Option<String>,
    pub is_ssl: bool,
    pub binding: String, // IP address
    pub response_headers: HashMap<String, String>,
    pub status_code: Option<u16>,
}

/// SSL/TLS certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertificate {
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub signature_algorithm: String,
    pub key_size: Option<u32>,
    pub serial_number: String,
    pub fingerprint: String,
    pub is_expired: bool,
    pub is_self_signed: bool,
    pub days_until_expiry: i64,
}

/// HTTP security headers information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaders {
    pub hsts: Option<String>,
    pub csp: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub x_xss_protection: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub content_security_policy: Option<String>,
}

/// Web server configuration details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebServerConfig {
    pub server_type: String,
    pub version: String,
    pub config_files: Vec<String>,
    pub modules: Vec<String>,
    pub security_features: HashMap<String, bool>,
}

/// OWASP vulnerability test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspVulnerability {
    pub category: String,
    pub vulnerability_type: String,
    pub risk_level: Severity,
    pub description: String,
    pub test_endpoint: String,
    pub payload_used: String,
    pub response_indicators: Vec<String>,
}

impl Default for WebSecurityScanner {
    fn default() -> Self {
        Self {
            target_ports: vec![80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 4000, 5000],
            timeout_seconds: 10,
        }
    }
}

impl WebSecurityScanner {
    /// Create new WebSecurityScanner with custom ports
    #[allow(dead_code)]
    pub fn new(target_ports: Vec<u16>, timeout_seconds: u64) -> Self {
        Self {
            target_ports,
            timeout_seconds,
        }
    }

    /// Discover web services running on the system
    fn discover_web_services(&self) -> Result<Vec<WebService>, ScanError> {
        info!("Discovering web services on ports: {:?}", self.target_ports);
        let mut services = Vec::new();

        // Check each target port
        for &port in &self.target_ports {
            if let Ok(service) = self.probe_web_service(port) {
                services.push(service);
            }
        }

        info!("Discovered {} web services", services.len());
        Ok(services)
    }

    /// Probe a specific port for web services
    fn probe_web_service(&self, port: u16) -> Result<WebService, ScanError> {
        debug!("Probing port {} for web services", port);

        // First check if port is open using netstat
        let is_open = self.is_port_open(port)?;
        if !is_open {
            return Err(ScanError::ConfigurationError(format!("Port {} is not open", port)));
        }

        // Try HTTPS first, then HTTP
        let (protocol, is_ssl) = if port == 443 || port == 8443 {
            ("https".to_string(), true)
        } else {
            ("http".to_string(), false)
        };

        let url = format!("{}://localhost:{}", protocol, port);
        let mut service = WebService {
            port,
            protocol: protocol.clone(),
            server_type: None,
            version: None,
            is_ssl,
            binding: "127.0.0.1".to_string(),
            response_headers: HashMap::new(),
            status_code: None,
        };

        // Try to get HTTP response headers using curl
        if let Ok(headers) = self.get_http_headers(&url) {
            service.response_headers = headers.clone();
            
            // Extract server information
            if let Some(server_header) = headers.get("server") {
                let (server_type, version) = self.parse_server_header(server_header);
                service.server_type = server_type;
                service.version = version;
            }
        }

        Ok(service)
    }

    /// Check if a port is open using netstat
    fn is_port_open(&self, port: u16) -> Result<bool, ScanError> {
        let output = Command::new("netstat")
            .args(&["-ln"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("netstat failed: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let port_pattern = format!(":{}", port);
        
        Ok(stdout.lines().any(|line| {
            line.contains(&port_pattern) && (line.contains("LISTEN") || line.contains("LISTENING"))
        }))
    }

    /// Get HTTP headers using curl
    fn get_http_headers(&self, url: &str) -> Result<HashMap<String, String>, ScanError> {
        let output = Command::new("curl")
            .args(&[
                "-I", // Head request only
                "-s", // Silent
                "-k", // Ignore SSL errors
                "--max-time", &self.timeout_seconds.to_string(),
                "--connect-timeout", "5",
                url,
            ])
            .output()
            .map_err(|e| ScanError::CommandError(format!("curl failed: {}", e)))?;

        let response = String::from_utf8_lossy(&output.stdout);
        let mut headers = HashMap::new();

        for line in response.lines() {
            if line.contains(':') {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim().to_lowercase();
                    let value = parts[1].trim().to_string();
                    headers.insert(key, value);
                }
            } else if line.starts_with("HTTP/") {
                // Parse status code
                if let Some(status_str) = line.split_whitespace().nth(1) {
                    if let Ok(status) = status_str.parse::<u16>() {
                        headers.insert("status_code".to_string(), status.to_string());
                    }
                }
            }
        }

        Ok(headers)
    }

    /// Parse server header to extract server type and version
    fn parse_server_header(&self, server_header: &str) -> (Option<String>, Option<String>) {
        let lower = server_header.to_lowercase();
        
        if lower.contains("apache") {
            let parts: Vec<&str> = server_header.split('/').collect();
            if parts.len() > 1 {
                (Some("Apache".to_string()), Some(parts[1].to_string()))
            } else {
                (Some("Apache".to_string()), None)
            }
        } else if lower.contains("nginx") {
            let parts: Vec<&str> = server_header.split('/').collect();
            if parts.len() > 1 {
                (Some("Nginx".to_string()), Some(parts[1].to_string()))
            } else {
                (Some("Nginx".to_string()), None)
            }
        } else if lower.contains("iis") {
            (Some("IIS".to_string()), None)
        } else if lower.contains("lighttpd") {
            (Some("Lighttpd".to_string()), None)
        } else {
            (Some(server_header.to_string()), None)
        }
    }

    /// Validate SSL/TLS certificates for HTTPS services
    fn validate_ssl_certificates(&self, services: &[WebService]) -> Result<Vec<Finding>, ScanError> {
        info!("Validating SSL/TLS certificates...");
        let mut findings = Vec::new();

        for service in services {
            if service.is_ssl {
                match self.get_ssl_certificate_info(service.port) {
                    Ok(cert) => {
                        // Check for certificate issues
                        findings.extend(self.analyze_ssl_certificate(&cert, service)?);
                    }
                    Err(e) => {
                        warn!("Failed to get SSL certificate for port {}: {}", service.port, e);
                        findings.push(Finding {
                            id: format!("SSL-CERT-ERROR-{}", service.port),
                            title: format!("SSL Certificate Error on port {}", service.port),
                            description: format!("Failed to retrieve SSL certificate information: {}", e),
                            severity: Severity::Medium,
                            category: Category::Security,
                            affected_item: format!("HTTPS service on port {}", service.port),
                            current_value: Some("SSL certificate error".to_string()),
                            recommended_value: Some("Fix SSL certificate configuration".to_string()),
                            references: vec![
                                "https://www.ssllabs.com/ssltest/".to_string(),
                                "https://letsencrypt.org/".to_string(),
                            ],
                            cve_ids: vec![],
                            fix_available: false,
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Get SSL certificate information using openssl
    fn get_ssl_certificate_info(&self, port: u16) -> Result<SslCertificate, ScanError> {
        let output = Command::new("openssl")
            .args(&[
                "s_client",
                "-connect", &format!("localhost:{}", port),
                "-servername", "localhost",
                "-showcerts",
                "-verify_return_error",
            ])
            .output()
            .map_err(|e| ScanError::CommandError(format!("openssl s_client failed: {}", e)))?;

        let cert_output = String::from_utf8_lossy(&output.stdout);
        
        // Parse certificate information (simplified)
        let mut cert = SslCertificate {
            subject: "Unknown".to_string(),
            issuer: "Unknown".to_string(),
            valid_from: "Unknown".to_string(),
            valid_to: "Unknown".to_string(),
            signature_algorithm: "Unknown".to_string(),
            key_size: None,
            serial_number: "Unknown".to_string(),
            fingerprint: "Unknown".to_string(),
            is_expired: false,
            is_self_signed: false,
            days_until_expiry: 0,
        };

        // Extract certificate details from openssl output
        for line in cert_output.lines() {
            if line.contains("subject=") {
                cert.subject = line.replace("subject=", "").trim().to_string();
            } else if line.contains("issuer=") {
                cert.issuer = line.replace("issuer=", "").trim().to_string();
            }
        }

        // Check if self-signed
        cert.is_self_signed = cert.subject == cert.issuer;

        Ok(cert)
    }

    /// Analyze SSL certificate for security issues
    fn analyze_ssl_certificate(&self, cert: &SslCertificate, service: &WebService) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Check for self-signed certificate
        if cert.is_self_signed {
            findings.push(Finding {
                id: format!("SSL-SELF-SIGNED-{}", service.port),
                title: format!("Self-signed SSL certificate on port {}", service.port),
                description: "The SSL certificate is self-signed, which may cause trust issues for users.".to_string(),
                severity: Severity::Medium,
                category: Category::Security,
                affected_item: format!("SSL certificate on port {}", service.port),
                current_value: Some("Self-signed certificate".to_string()),
                recommended_value: Some("Use CA-signed certificate".to_string()),
                references: vec![
                    "https://letsencrypt.org/".to_string(),
                    "https://www.ssllabs.com/projects/best-practices/".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            });
        }

        // Check for certificate expiration
        if cert.is_expired {
            findings.push(Finding {
                id: format!("SSL-EXPIRED-{}", service.port),
                title: format!("Expired SSL certificate on port {}", service.port),
                description: "The SSL certificate has expired and needs to be renewed.".to_string(),
                severity: Severity::High,
                category: Category::Security,
                affected_item: format!("SSL certificate on port {}", service.port),
                current_value: Some("Expired certificate".to_string()),
                recommended_value: Some("Renew SSL certificate".to_string()),
                references: vec![
                    "https://letsencrypt.org/".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            });
        }

        // Check for soon-to-expire certificate (within 30 days)
        if cert.days_until_expiry > 0 && cert.days_until_expiry <= 30 {
            findings.push(Finding {
                id: format!("SSL-EXPIRING-{}", service.port),
                title: format!("SSL certificate expiring soon on port {}", service.port),
                description: format!("The SSL certificate will expire in {} days.", cert.days_until_expiry),
                severity: Severity::Medium,
                category: Category::Security,
                affected_item: format!("SSL certificate on port {}", service.port),
                current_value: Some(format!("{} days until expiry", cert.days_until_expiry)),
                recommended_value: Some("Renew SSL certificate".to_string()),
                references: vec![
                    "https://letsencrypt.org/".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            });
        }

        Ok(findings)
    }

    /// Analyze HTTP security headers
    fn analyze_security_headers(&self, services: &[WebService]) -> Result<Vec<Finding>, ScanError> {
        info!("Analyzing HTTP security headers...");
        let mut findings = Vec::new();

        for service in services {
            let headers = &service.response_headers;
            
            // Check for missing security headers
            findings.extend(self.check_missing_security_headers(headers, service)?);
            
            // Check for weak security headers
            findings.extend(self.check_weak_security_headers(headers, service)?);
        }

        Ok(findings)
    }

    /// Check for missing security headers
    fn check_missing_security_headers(&self, headers: &HashMap<String, String>, service: &WebService) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        let required_headers = vec![
            ("strict-transport-security", "HSTS", "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            ("x-frame-options", "X-Frame-Options", "X-Frame-Options: DENY"),
            ("x-content-type-options", "X-Content-Type-Options", "X-Content-Type-Options: nosniff"),
            ("content-security-policy", "Content Security Policy", "Content-Security-Policy: default-src 'self'"),
            ("x-xss-protection", "XSS Protection", "X-XSS-Protection: 1; mode=block"),
            ("referrer-policy", "Referrer Policy", "Referrer-Policy: strict-origin-when-cross-origin"),
        ];

        for (header_name, friendly_name, recommended_value) in required_headers {
            if !headers.contains_key(header_name) {
                let severity = match header_name {
                    "strict-transport-security" if service.is_ssl => Severity::High,
                    "content-security-policy" => Severity::High,
                    "x-frame-options" => Severity::Medium,
                    _ => Severity::Low,
                };

                findings.push(Finding {
                    id: format!("HTTP-MISSING-{}-{}", header_name.to_uppercase().replace('-', "_"), service.port),
                    title: format!("Missing {} header on port {}", friendly_name, service.port),
                    description: format!("The {} security header is missing, which could expose the application to security risks.", friendly_name),
                    severity,
                    category: Category::Security,
                    affected_item: format!("HTTP service on port {}", service.port),
                    current_value: Some("Header not present".to_string()),
                    recommended_value: Some(recommended_value.to_string()),
                    references: vec![
                        "https://owasp.org/www-project-secure-headers/".to_string(),
                        "https://securityheaders.com/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }
        }

        Ok(findings)
    }

    /// Check for weak security headers
    fn check_weak_security_headers(&self, headers: &HashMap<String, String>, service: &WebService) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Check X-Frame-Options
        if let Some(xfo) = headers.get("x-frame-options") {
            if xfo.to_lowercase() == "allowall" {
                findings.push(Finding {
                    id: format!("HTTP-WEAK-XFO-{}", service.port),
                    title: format!("Weak X-Frame-Options on port {}", service.port),
                    description: "X-Frame-Options is set to ALLOWALL, which allows framing from any origin.".to_string(),
                    severity: Severity::Medium,
                    category: Category::Security,
                    affected_item: format!("HTTP service on port {}", service.port),
                    current_value: Some(xfo.clone()),
                    recommended_value: Some("X-Frame-Options: DENY or SAMEORIGIN".to_string()),
                    references: vec![
                        "https://owasp.org/www-project-secure-headers/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }
        }

        // Check Content-Security-Policy
        if let Some(csp) = headers.get("content-security-policy") {
            if csp.contains("'unsafe-inline'") || csp.contains("'unsafe-eval'") {
                findings.push(Finding {
                    id: format!("HTTP-WEAK-CSP-{}", service.port),
                    title: format!("Weak Content Security Policy on port {}", service.port),
                    description: "Content Security Policy contains 'unsafe-inline' or 'unsafe-eval' directives.".to_string(),
                    severity: Severity::Medium,
                    category: Category::Security,
                    affected_item: format!("HTTP service on port {}", service.port),
                    current_value: Some(csp.clone()),
                    recommended_value: Some("Remove 'unsafe-inline' and 'unsafe-eval' from CSP".to_string()),
                    references: vec![
                        "https://content-security-policy.com/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }
        }

        Ok(findings)
    }

    /// Analyze web server configurations
    fn analyze_web_server_configs(&self, services: &[WebService]) -> Result<Vec<Finding>, ScanError> {
        info!("Analyzing web server configurations...");
        let mut findings = Vec::new();

        for service in services {
            if let Some(server_type) = &service.server_type {
                match server_type.to_lowercase().as_str() {
                    "apache" => findings.extend(self.analyze_apache_config(service)?),
                    "nginx" => findings.extend(self.analyze_nginx_config(service)?),
                    _ => {
                        debug!("Unknown server type: {}", server_type);
                    }
                }
            }

            // Check for server information disclosure
            if let Some(server_header) = service.response_headers.get("server") {
                if !server_header.is_empty() {
                    findings.push(Finding {
                        id: format!("HTTP-SERVER-DISCLOSURE-{}", service.port),
                        title: format!("Server information disclosure on port {}", service.port),
                        description: "The server header reveals detailed information about the web server.".to_string(),
                        severity: Severity::Low,
                        category: Category::Configuration,
                        affected_item: format!("HTTP service on port {}", service.port),
                        current_value: Some(server_header.clone()),
                        recommended_value: Some("Hide or minimize server information".to_string()),
                        references: vec![
                            "https://owasp.org/www-project-web-security-testing-guide/".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Analyze Apache configuration
    fn analyze_apache_config(&self, service: &WebService) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Check if Apache version is outdated (simplified check)
        if let Some(version) = &service.version {
            if version.starts_with("2.2") {
                findings.push(Finding {
                    id: format!("APACHE-OUTDATED-{}", service.port),
                    title: format!("Outdated Apache version on port {}", service.port),
                    description: format!("Apache version {} is outdated and may contain security vulnerabilities.", version),
                    severity: Severity::Medium,
                    category: Category::Service,
                    affected_item: format!("Apache server on port {}", service.port),
                    current_value: Some(version.clone()),
                    recommended_value: Some("Upgrade to Apache 2.4 or later".to_string()),
                    references: vec![
                        "https://httpd.apache.org/security/vulnerabilities_24.html".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }
        }

        Ok(findings)
    }

    /// Analyze Nginx configuration
    fn analyze_nginx_config(&self, service: &WebService) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Check common Nginx security issues
        if let Some(version) = &service.version {
            // Check for old Nginx versions (simplified)
            if version.starts_with("1.1") || version.starts_with("1.0") {
                findings.push(Finding {
                    id: format!("NGINX-OUTDATED-{}", service.port),
                    title: format!("Outdated Nginx version on port {}", service.port),
                    description: format!("Nginx version {} is outdated and may contain security vulnerabilities.", version),
                    severity: Severity::Medium,
                    category: Category::Service,
                    affected_item: format!("Nginx server on port {}", service.port),
                    current_value: Some(version.clone()),
                    recommended_value: Some("Upgrade to latest stable Nginx version".to_string()),
                    references: vec![
                        "https://nginx.org/en/security_advisories.html".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }
        }

        Ok(findings)
    }

    /// Basic OWASP Top 10 vulnerability detection
    fn detect_owasp_vulnerabilities(&self, services: &[WebService]) -> Result<Vec<Finding>, ScanError> {
        info!("Detecting OWASP Top 10 vulnerabilities...");
        let mut findings = Vec::new();

        for service in services {
            // Basic checks for common vulnerabilities
            findings.extend(self.check_sql_injection_indicators(service)?);
            findings.extend(self.check_xss_protection(service)?);
            findings.extend(self.check_csrf_protection(service)?);
            findings.extend(self.check_directory_traversal(service)?);
        }

        Ok(findings)
    }

    /// Check for SQL injection indicators
    fn check_sql_injection_indicators(&self, service: &WebService) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // This is a basic check - in practice, you'd want more sophisticated testing
        let test_endpoints = vec![
            "/", 
            "/login", 
            "/search", 
            "/index.php", 
            "/admin"
        ];

        for endpoint in test_endpoints {
            let url = format!("{}://localhost:{}{}", service.protocol, service.port, endpoint);
            
            // Test with basic SQL injection payload
            let test_url = format!("{}?id=1'", url);
            
            if let Ok(response) = self.test_endpoint(&test_url) {
                if response.contains("SQL") || response.contains("mysql") || response.contains("ORA-") {
                    findings.push(Finding {
                        id: format!("OWASP-SQLI-{}-{}", service.port, endpoint.replace('/', "_")),
                        title: format!("Potential SQL injection vulnerability on port {}", service.port),
                        description: format!("Endpoint {} may be vulnerable to SQL injection attacks.", endpoint),
                        severity: Severity::High,
                        category: Category::Security,
                        affected_item: format!("Web endpoint: {}", endpoint),
                        current_value: Some("Potential SQL injection vulnerability".to_string()),
                        recommended_value: Some("Use parameterized queries and input validation".to_string()),
                        references: vec![
                            "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Check XSS protection
    fn check_xss_protection(&self, service: &WebService) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Check if XSS protection header is missing or disabled
        if let Some(xss_protection) = service.response_headers.get("x-xss-protection") {
            if xss_protection == "0" {
                findings.push(Finding {
                    id: format!("OWASP-XSS-DISABLED-{}", service.port),
                    title: format!("XSS protection disabled on port {}", service.port),
                    description: "X-XSS-Protection header is set to 0, disabling browser XSS protection.".to_string(),
                    severity: Severity::Medium,
                    category: Category::Security,
                    affected_item: format!("HTTP service on port {}", service.port),
                    current_value: Some("X-XSS-Protection: 0".to_string()),
                    recommended_value: Some("X-XSS-Protection: 1; mode=block".to_string()),
                    references: vec![
                        "https://owasp.org/www-community/attacks/xss/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }
        }

        Ok(findings)
    }

    /// Check CSRF protection
    fn check_csrf_protection(&self, service: &WebService) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Check for CSRF protection indicators
        let csrf_headers = vec![
            "x-csrf-token",
            "x-xsrf-token", 
            "csrf-token",
            "x-requested-with"
        ];

        let has_csrf_protection = csrf_headers.iter()
            .any(|header| service.response_headers.contains_key(*header));

        if !has_csrf_protection {
            findings.push(Finding {
                id: format!("OWASP-CSRF-{}", service.port),
                title: format!("No CSRF protection detected on port {}", service.port),
                description: "No CSRF protection headers or tokens detected in the response.".to_string(),
                severity: Severity::Medium,
                category: Category::Security,
                affected_item: format!("HTTP service on port {}", service.port),
                current_value: Some("No CSRF protection detected".to_string()),
                recommended_value: Some("Implement CSRF tokens and validation".to_string()),
                references: vec![
                    "https://owasp.org/www-community/attacks/csrf".to_string(),
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html".to_string(),
                ],
                cve_ids: vec![],
                fix_available: true,
            });
        }

        Ok(findings)
    }

    /// Check for directory traversal vulnerabilities
    fn check_directory_traversal(&self, service: &WebService) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        let test_paths = vec![
            "/../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
        ];

        for path in test_paths {
            let url = format!("{}://localhost:{}{}", service.protocol, service.port, path);
            
            if let Ok(response) = self.test_endpoint(&url) {
                if response.contains("root:") || response.contains("localhost") {
                    findings.push(Finding {
                        id: format!("OWASP-DIR-TRAVERSAL-{}", service.port),
                        title: format!("Potential directory traversal vulnerability on port {}", service.port),
                        description: "The web application may be vulnerable to directory traversal attacks.".to_string(),
                        severity: Severity::High,
                        category: Category::Security,
                        affected_item: format!("Web application on port {}", service.port),
                        current_value: Some("Directory traversal vulnerability detected".to_string()),
                        recommended_value: Some("Implement proper input validation and path sanitization".to_string()),
                        references: vec![
                            "https://owasp.org/www-community/attacks/Path_Traversal".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    });
                    break; // Don't test other paths if one is found
                }
            }
        }

        Ok(findings)
    }

    /// Test an endpoint and return response body
    fn test_endpoint(&self, url: &str) -> Result<String, ScanError> {
        let output = Command::new("curl")
            .args(&[
                "-s", // Silent
                "-k", // Ignore SSL errors
                "--max-time", &self.timeout_seconds.to_string(),
                "--connect-timeout", "5",
                url,
            ])
            .output()
            .map_err(|e| ScanError::CommandError(format!("curl failed: {}", e)))?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Scanner for WebSecurityScanner {
    fn name(&self) -> &'static str {
        "web_security"
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Web Application Security".to_string());

        info!("Starting web application security scan...");

        // Discover web services
        let services = match self.discover_web_services() {
            Ok(services) => {
                info!("Discovered {} web services", services.len());
                result.set_items_scanned(services.len() as u32);
                services
            }
            Err(e) => {
                warn!("Failed to discover web services: {}", e);
                result.status = ScanStatus::Warning;
                vec![]
            }
        };

        if services.is_empty() {
            info!("No web services found");
            result.status = ScanStatus::Skipped("No web services found".to_string());
            result.set_duration(start_time.elapsed().as_millis() as u64);
            return Ok(result);
        }

        let mut all_findings = Vec::new();

        // SSL/TLS Certificate validation
        match self.validate_ssl_certificates(&services) {
            Ok(mut findings) => {
                info!("SSL/TLS certificate validation found {} issues", findings.len());
                all_findings.append(&mut findings);
            }
            Err(e) => {
                warn!("SSL/TLS certificate validation failed: {}", e);
                result.status = ScanStatus::Warning;
            }
        }

        // HTTP security headers analysis
        match self.analyze_security_headers(&services) {
            Ok(mut findings) => {
                info!("Security headers analysis found {} issues", findings.len());
                all_findings.append(&mut findings);
            }
            Err(e) => {
                warn!("Security headers analysis failed: {}", e);
                result.status = ScanStatus::Warning;
            }
        }

        // Web server configuration analysis
        match self.analyze_web_server_configs(&services) {
            Ok(mut findings) => {
                info!("Web server config analysis found {} issues", findings.len());
                all_findings.append(&mut findings);
            }
            Err(e) => {
                warn!("Web server config analysis failed: {}", e);
                result.status = ScanStatus::Warning;
            }
        }

        // OWASP Top 10 vulnerability detection
        match self.detect_owasp_vulnerabilities(&services) {
            Ok(mut findings) => {
                info!("OWASP vulnerability detection found {} issues", findings.len());
                all_findings.append(&mut findings);
            }
            Err(e) => {
                warn!("OWASP vulnerability detection failed: {}", e);
                result.status = ScanStatus::Warning;
            }
        }

        // Update result with findings
        for finding in all_findings {
            result.add_finding(finding);
        }

        let duration = start_time.elapsed();
        result.set_duration(duration.as_millis() as u64);
        result.metadata.scanner_version = "0.1.0".to_string();

        info!(
            "Web application security scan completed in {}ms with {} findings",
            duration.as_millis(),
            result.findings.len()
        );

        Ok(result)
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config.scanner.enabled_modules.contains(&"web_security".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_server_header() {
        let scanner = WebSecurityScanner::default();
        
        let (server, version) = scanner.parse_server_header("Apache/2.4.41 (Ubuntu)");
        assert_eq!(server, Some("Apache".to_string()));
        assert_eq!(version, Some("2.4.41 (Ubuntu)".to_string()));

        let (server, version) = scanner.parse_server_header("nginx/1.18.0");
        assert_eq!(server, Some("Nginx".to_string()));
        assert_eq!(version, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_web_security_scanner_creation() {
        let scanner = WebSecurityScanner::default();
        assert_eq!(scanner.name(), "Web Application Security");
        assert!(!scanner.target_ports.is_empty());
    }
}