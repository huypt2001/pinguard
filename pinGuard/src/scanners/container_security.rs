use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::Instant;
use tracing::{debug, info, warn};

use crate::cve::cve_manager::CveManager;
use crate::database::cve_cache::{CveData, CveSeverity};

pub struct ContainerSecurityScanner {
    cve_manager: Option<CveManager>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DockerContainer {
    id: String,
    name: String,
    image: String,
    status: String,
    ports: Vec<String>,
    mounts: Vec<String>,
    privileged: bool,
    security_opts: Vec<String>,
    network_mode: String,
    vulnerabilities: Vec<String>,
    cve_details: Vec<CveData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DockerImage {
    id: String,
    repository: String,
    tag: String,
    size: u64,
    created: String,
    base_os: Option<String>,
    layers: Vec<String>,
    vulnerabilities: Vec<String>,
    cve_details: Vec<CveData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DockerDaemonConfig {
    version: String,
    root_dir: String,
    logging_driver: String,
    storage_driver: String,
    security_options: Vec<String>,
    insecure_registries: Vec<String>,
    registry_mirrors: Vec<String>,
    live_restore: bool,
    userland_proxy: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct KubernetesCluster {
    version: String,
    nodes: Vec<KubernetesNode>,
    namespaces: Vec<String>,
    security_policies: Vec<String>,
    rbac_enabled: bool,
    network_policies: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KubernetesNode {
    name: String,
    status: String,
    version: String,
    container_runtime: String,
    os_image: String,
    kernel_version: String,
}

impl Default for ContainerSecurityScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerSecurityScanner {
    pub fn new() -> Self {
        Self { cve_manager: None }
    }

    pub fn with_cve_manager(mut self, cve_manager: CveManager) -> Self {
        self.cve_manager = Some(cve_manager);
        self
    }

    /// Check if Docker is installed and running
    fn is_docker_available(&self) -> bool {
        match Command::new("docker").arg("--version").output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    /// Check if kubectl is available for Kubernetes scanning
    fn is_kubectl_available(&self) -> bool {
        match Command::new("kubectl").arg("version").arg("--client").output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    /// Scan Docker containers for vulnerabilities
    fn scan_docker_containers(&self) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        if !self.is_docker_available() {
            return Ok(findings);
        }

        info!("Scanning Docker containers for security issues...");

        let containers = self.get_running_containers()?;
        for container in containers {
            // Check for privileged containers
            if container.privileged {
                findings.push(Finding {
                    id: format!("CONTAINER_PRIVILEGED_{}", container.id[..12].to_string()),
                    title: "Privileged Container Detected".to_string(),
                    description: format!(
                        "Container '{}' is running in privileged mode, which grants all capabilities to the container",
                        container.name
                    ),
                    severity: Severity::High,
                    category: Category::Security,
                    affected_item: format!("Container: {}", container.name),
                    current_value: Some("privileged: true".to_string()),
                    recommended_value: Some("privileged: false".to_string()),
                    references: vec![
                        "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities".to_string()
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }

            // Check for containers running as root
            if self.is_container_running_as_root(&container.id)? {
                findings.push(Finding {
                    id: format!("CONTAINER_ROOT_USER_{}", container.id[..12].to_string()),
                    title: "Container Running as Root".to_string(),
                    description: format!(
                        "Container '{}' is running as root user, which poses security risks",
                        container.name
                    ),
                    severity: Severity::Medium,
                    category: Category::Security,
                    affected_item: format!("Container: {}", container.name),
                    current_value: Some("user: root".to_string()),
                    recommended_value: Some("user: non-root user".to_string()),
                    references: vec![
                        "https://docs.docker.com/develop/dev-best-practices/#use-non-root-user".to_string()
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }

            // Check for exposed sensitive ports
            for port in &container.ports {
                if self.is_sensitive_port(port) {
                    findings.push(Finding {
                        id: format!("CONTAINER_SENSITIVE_PORT_{}_{}", container.id[..12].to_string(), port),
                        title: "Sensitive Port Exposed".to_string(),
                        description: format!(
                            "Container '{}' exposes sensitive port '{}'",
                            container.name, port
                        ),
                        severity: Severity::Medium,
                        category: Category::Network,
                        affected_item: format!("Container: {} Port: {}", container.name, port),
                        current_value: Some(format!("exposed port: {}", port)),
                        recommended_value: Some("Restrict access or use internal networking".to_string()),
                        references: vec![
                            "https://docs.docker.com/network/".to_string()
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    });
                }
            }

            // Check for secrets in environment variables
            let secrets = self.scan_container_secrets(&container.id)?;
            for secret in secrets {
                findings.push(Finding {
                    id: format!("CONTAINER_SECRET_{}_{}", container.id[..12].to_string(), secret),
                    title: "Potential Secret in Environment".to_string(),
                    description: format!(
                        "Container '{}' may contain secrets in environment variables",
                        container.name
                    ),
                    severity: Severity::High,
                    category: Category::Security,
                    affected_item: format!("Container: {} Environment: {}", container.name, secret),
                    current_value: Some(format!("env var: {}", secret)),
                    recommended_value: Some("Use Docker secrets or external secret management".to_string()),
                    references: vec![
                        "https://docs.docker.com/engine/swarm/secrets/".to_string()
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }
        }

        Ok(findings)
    }

    /// Scan Docker images for vulnerabilities
    fn scan_docker_images(&self) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        if !self.is_docker_available() {
            return Ok(findings);
        }

        info!("Scanning Docker images for security issues...");

        let images = self.get_docker_images()?;
        for image in images {
            // Check for images using 'latest' tag
            if image.tag == "latest" {
                findings.push(Finding {
                    id: format!("IMAGE_LATEST_TAG_{}", image.id[..12].to_string()),
                    title: "Image Using 'latest' Tag".to_string(),
                    description: format!(
                        "Image '{}:{}' uses the 'latest' tag, which can lead to unpredictable deployments",
                        image.repository, image.tag
                    ),
                    severity: Severity::Low,
                    category: Category::Configuration,
                    affected_item: format!("Image: {}:{}", image.repository, image.tag),
                    current_value: Some("tag: latest".to_string()),
                    recommended_value: Some("Use specific version tags".to_string()),
                    references: vec![
                        "https://docs.docker.com/develop/dev-best-practices/#tag-images-appropriately".to_string()
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }

            // Check for large images
            if image.size > 1_000_000_000 { // 1GB
                findings.push(Finding {
                    id: format!("IMAGE_LARGE_SIZE_{}", image.id[..12].to_string()),
                    title: "Large Docker Image".to_string(),
                    description: format!(
                        "Image '{}:{}' is large ({} MB), which increases attack surface and deployment time",
                        image.repository, image.tag, image.size / 1_000_000
                    ),
                    severity: Severity::Low,
                    category: Category::Configuration,
                    affected_item: format!("Image: {}:{}", image.repository, image.tag),
                    current_value: Some(format!("size: {} MB", image.size / 1_000_000)),
                    recommended_value: Some("Use multi-stage builds and minimal base images".to_string()),
                    references: vec![
                        "https://docs.docker.com/develop/dev-best-practices/#use-multi-stage-builds".to_string()
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                });
            }

            // Scan for CVEs in image if CVE manager is available
            if let Some(ref cve_manager) = self.cve_manager {
                let cves = self.scan_image_vulnerabilities(&image, cve_manager)?;
                for cve in cves {
                    let severity = match cve.severity {
                        CveSeverity::Critical => Severity::Critical,
                        CveSeverity::High => Severity::High,
                        CveSeverity::Medium => Severity::Medium,
                        CveSeverity::Low => Severity::Low,
                        CveSeverity::None => Severity::Info,
                        CveSeverity::Unknown => Severity::Info,
                    };

                    findings.push(Finding {
                        id: format!("IMAGE_CVE_{}_{}", cve.cve_id, image.id[..12].to_string()),
                        title: format!("CVE Found in Image: {}", cve.cve_id),
                        description: cve.description.clone(),
                        severity,
                        category: Category::Security,
                        affected_item: format!("Image: {}:{}", image.repository, image.tag),
                        current_value: Some(format!("vulnerable image: {}:{}", image.repository, image.tag)),
                        recommended_value: Some("Update to patched image version".to_string()),
                        references: vec![
                            format!("https://nvd.nist.gov/vuln/detail/{}", cve.cve_id)
                        ],
                        cve_ids: vec![cve.cve_id.clone()],
                        fix_available: true,
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Audit Docker daemon configuration
    fn audit_docker_daemon(&self) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        if !self.is_docker_available() {
            return Ok(findings);
        }

        info!("Auditing Docker daemon configuration...");

        let daemon_config = self.get_docker_daemon_config()?;

        // Check for insecure registries
        if !daemon_config.insecure_registries.is_empty() {
            findings.push(Finding {
                id: "DOCKER_INSECURE_REGISTRIES".to_string(),
                title: "Insecure Docker Registries Configured".to_string(),
                description: "Docker daemon is configured to use insecure registries".to_string(),
                severity: Severity::Medium,
                category: Category::Configuration,
                affected_item: "Docker daemon".to_string(),
                current_value: Some(format!("insecure-registries: {:?}", daemon_config.insecure_registries)),
                recommended_value: Some("Use only secure registries with TLS".to_string()),
                references: vec![
                    "https://docs.docker.com/registry/insecure/".to_string()
                ],
                cve_ids: vec![],
                fix_available: true,
            });
        }

        // Check for live restore
        if !daemon_config.live_restore {
            findings.push(Finding {
                id: "DOCKER_LIVE_RESTORE_DISABLED".to_string(),
                title: "Docker Live Restore Disabled".to_string(),
                description: "Docker daemon live restore is disabled, containers will stop during daemon restart".to_string(),
                severity: Severity::Low,
                category: Category::Configuration,
                affected_item: "Docker daemon".to_string(),
                current_value: Some("live-restore: false".to_string()),
                recommended_value: Some("live-restore: true".to_string()),
                references: vec![
                    "https://docs.docker.com/config/containers/live-restore/".to_string()
                ],
                cve_ids: vec![],
                fix_available: true,
            });
        }

        Ok(findings)
    }

    /// Basic Kubernetes cluster security audit
    fn audit_kubernetes_cluster(&self) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        if !self.is_kubectl_available() {
            return Ok(findings);
        }

        info!("Auditing Kubernetes cluster security...");

        // Check if cluster is accessible
        match self.get_kubernetes_cluster_info() {
            Ok(cluster) => {
                // Check RBAC
                if !cluster.rbac_enabled {
                    findings.push(Finding {
                        id: "K8S_RBAC_DISABLED".to_string(),
                        title: "Kubernetes RBAC Disabled".to_string(),
                        description: "Role-Based Access Control (RBAC) is not enabled in the cluster".to_string(),
                        severity: Severity::High,
                        category: Category::Security,
                        affected_item: "Kubernetes cluster".to_string(),
                        current_value: Some("RBAC: disabled".to_string()),
                        recommended_value: Some("Enable RBAC".to_string()),
                        references: vec![
                            "https://kubernetes.io/docs/reference/access-authn-authz/rbac/".to_string()
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    });
                }

                // Check for default namespace usage
                if cluster.namespaces.contains(&"default".to_string()) {
                    findings.push(Finding {
                        id: "K8S_DEFAULT_NAMESPACE".to_string(),
                        title: "Default Namespace in Use".to_string(),
                        description: "Resources are running in the default namespace".to_string(),
                        severity: Severity::Low,
                        category: Category::Configuration,
                        affected_item: "Kubernetes namespaces".to_string(),
                        current_value: Some("using default namespace".to_string()),
                        recommended_value: Some("Use dedicated namespaces for applications".to_string()),
                        references: vec![
                            "https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/".to_string()
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    });
                }

                // Check network policies
                if cluster.network_policies.is_empty() {
                    findings.push(Finding {
                        id: "K8S_NO_NETWORK_POLICIES".to_string(),
                        title: "No Network Policies Configured".to_string(),
                        description: "No network policies are configured, allowing unrestricted pod-to-pod communication".to_string(),
                        severity: Severity::Medium,
                        category: Category::Network,
                        affected_item: "Kubernetes network policies".to_string(),
                        current_value: Some("network policies: none".to_string()),
                        recommended_value: Some("Implement network policies for pod isolation".to_string()),
                        references: vec![
                            "https://kubernetes.io/docs/concepts/services-networking/network-policies/".to_string()
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    });
                }
            }
            Err(e) => {
                debug!("Could not access Kubernetes cluster: {}", e);
            }
        }

        Ok(findings)
    }

    /// Get running Docker containers
    fn get_running_containers(&self) -> Result<Vec<DockerContainer>, ScanError> {
        let output = Command::new("docker")
            .args(["ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("Failed to run docker ps: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError(
                "Docker ps command failed".to_string(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut containers = Vec::new();

        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 5 {
                let container_id = parts[0].to_string();
                
                // Get detailed info for this container
                let inspect_info = self.inspect_container(&container_id)?;
                
                containers.push(DockerContainer {
                    id: container_id,
                    name: parts[1].to_string(),
                    image: parts[2].to_string(),
                    status: parts[3].to_string(),
                    ports: parts[4].split(',').map(|s| s.trim().to_string()).collect(),
                    mounts: inspect_info.0,
                    privileged: inspect_info.1,
                    security_opts: inspect_info.2,
                    network_mode: inspect_info.3,
                    vulnerabilities: vec![],
                    cve_details: vec![],
                });
            }
        }

        Ok(containers)
    }

    /// Inspect a specific container for detailed security information
    fn inspect_container(&self, container_id: &str) -> Result<(Vec<String>, bool, Vec<String>, String), ScanError> {
        let output = Command::new("docker")
            .args(["inspect", container_id])
            .output()
            .map_err(|e| ScanError::CommandError(format!("Failed to inspect container: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError(
                "Docker inspect command failed".to_string(),
            ));
        }

        // Parse JSON output (simplified - in real implementation, use proper JSON parsing)
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Extract key security information
        let mounts = vec![]; // TODO: Parse mounts from JSON
        let privileged = stdout.contains("\"Privileged\": true");
        let security_opts = vec![]; // TODO: Parse security options from JSON
        let network_mode = "default".to_string(); // TODO: Parse network mode from JSON

        Ok((mounts, privileged, security_opts, network_mode))
    }

    /// Check if container is running as root
    fn is_container_running_as_root(&self, container_id: &str) -> Result<bool, ScanError> {
        let output = Command::new("docker")
            .args(["exec", container_id, "id", "-u"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("Failed to check user in container: {}", e)))?;

        if !output.status.success() {
            return Ok(false); // Assume not root if we can't check
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim() == "0")
    }

    /// Check if a port is considered sensitive
    fn is_sensitive_port(&self, port: &str) -> bool {
        let sensitive_ports = [
            "22", "23", "3389", "5432", "3306", "1433", "5984", "6379", "11211", "9200", "27017"
        ];
        
        for &sensitive in &sensitive_ports {
            if port.contains(sensitive) {
                return true;
            }
        }
        false
    }

    /// Scan container for potential secrets in environment variables
    fn scan_container_secrets(&self, container_id: &str) -> Result<Vec<String>, ScanError> {
        let output = Command::new("docker")
            .args(["exec", container_id, "env"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("Failed to get container env: {}", e)))?;

        if !output.status.success() {
            return Ok(vec![]); // No environment variables or access denied
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut secrets = Vec::new();

        for line in stdout.lines() {
            let env_var = line.to_lowercase();
            if env_var.contains("password") || env_var.contains("secret") || 
               env_var.contains("token") || env_var.contains("key") ||
               env_var.contains("api_key") || env_var.contains("auth") {
                secrets.push(line.split('=').next().unwrap_or(line).to_string());
            }
        }

        Ok(secrets)
    }

    /// Get Docker images
    fn get_docker_images(&self) -> Result<Vec<DockerImage>, ScanError> {
        let output = Command::new("docker")
            .args(["images", "--format", "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("Failed to run docker images: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError(
                "Docker images command failed".to_string(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut images = Vec::new();

        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 5 {
                images.push(DockerImage {
                    id: parts[0].to_string(),
                    repository: parts[1].to_string(),
                    tag: parts[2].to_string(),
                    size: self.parse_size(parts[3]).unwrap_or(0),
                    created: parts[4].to_string(),
                    base_os: None,
                    layers: vec![],
                    vulnerabilities: vec![],
                    cve_details: vec![],
                });
            }
        }

        Ok(images)
    }

    /// Parse size string to bytes
    fn parse_size(&self, size_str: &str) -> Result<u64, ScanError> {
        let size_str = size_str.to_lowercase();
        let size_str = size_str.replace(' ', "");
        
        if let Some(pos) = size_str.find("gb") {
            let num_str = &size_str[..pos];
            if let Ok(num) = num_str.parse::<f64>() {
                return Ok((num * 1_000_000_000.0) as u64);
            }
        } else if let Some(pos) = size_str.find("mb") {
            let num_str = &size_str[..pos];
            if let Ok(num) = num_str.parse::<f64>() {
                return Ok((num * 1_000_000.0) as u64);
            }
        } else if let Some(pos) = size_str.find("kb") {
            let num_str = &size_str[..pos];
            if let Ok(num) = num_str.parse::<f64>() {
                return Ok((num * 1_000.0) as u64);
            }
        }
        
        Ok(0)
    }

    /// Scan image for vulnerabilities using CVE manager
    fn scan_image_vulnerabilities(&self, _image: &DockerImage, _cve_manager: &CveManager) -> Result<Vec<CveData>, ScanError> {
        // This is a simplified implementation
        // In a real implementation, you would:
        // 1. Extract package information from the image
        // 2. Query CVE database for each package
        // 3. Return matching CVEs
        
        debug!("Scanning image {}:{} for vulnerabilities", _image.repository, _image.tag);
        
        // For now, return empty list
        // TODO: Implement actual image vulnerability scanning
        Ok(vec![])
    }

    /// Get Docker daemon configuration
    fn get_docker_daemon_config(&self) -> Result<DockerDaemonConfig, ScanError> {
        let output = Command::new("docker")
            .args(["system", "info", "--format", "{{json .}}"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("Failed to get docker info: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError(
                "Docker system info command failed".to_string(),
            ));
        }

        // Simplified parsing - in real implementation, use proper JSON parsing
        let _stdout = String::from_utf8_lossy(&output.stdout);
        
        Ok(DockerDaemonConfig {
            version: "unknown".to_string(), // TODO: Parse from JSON
            root_dir: "/var/lib/docker".to_string(), // TODO: Parse from JSON
            logging_driver: "json-file".to_string(), // TODO: Parse from JSON
            storage_driver: "overlay2".to_string(), // TODO: Parse from JSON
            security_options: vec![], // TODO: Parse from JSON
            insecure_registries: vec![], // TODO: Parse from JSON
            registry_mirrors: vec![], // TODO: Parse from JSON
            live_restore: false, // TODO: Parse from JSON
            userland_proxy: true, // TODO: Parse from JSON
        })
    }

    /// Get Kubernetes cluster information
    fn get_kubernetes_cluster_info(&self) -> Result<KubernetesCluster, ScanError> {
        let output = Command::new("kubectl")
            .args(["cluster-info"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("Failed to get cluster info: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError(
                "kubectl cluster-info command failed".to_string(),
            ));
        }

        // Simplified implementation
        Ok(KubernetesCluster {
            version: "unknown".to_string(),
            nodes: vec![],
            namespaces: vec!["default".to_string()], // TODO: Get actual namespaces
            security_policies: vec![],
            rbac_enabled: true, // TODO: Check actual RBAC status
            network_policies: vec![], // TODO: Get actual network policies
        })
    }
}

impl Scanner for ContainerSecurityScanner {
    fn name(&self) -> &'static str {
        "container_security"
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Container Security Scanner".to_string());
        let mut all_findings = Vec::new();

        info!("Starting container security scan...");

        // Scan Docker containers
        match self.scan_docker_containers() {
            Ok(mut findings) => {
                info!("Found {} container security issues", findings.len());
                all_findings.append(&mut findings);
            }
            Err(e) => {
                warn!("Failed to scan Docker containers: {}", e);
                result.status = ScanStatus::Warning;
            }
        }

        // Scan Docker images
        match self.scan_docker_images() {
            Ok(mut findings) => {
                info!("Found {} image security issues", findings.len());
                all_findings.append(&mut findings);
            }
            Err(e) => {
                warn!("Failed to scan Docker images: {}", e);
                result.status = ScanStatus::Warning;
            }
        }

        // Audit Docker daemon
        match self.audit_docker_daemon() {
            Ok(mut findings) => {
                info!("Found {} Docker daemon configuration issues", findings.len());
                all_findings.append(&mut findings);
            }
            Err(e) => {
                warn!("Failed to audit Docker daemon: {}", e);
                result.status = ScanStatus::Warning;
            }
        }

        // Audit Kubernetes cluster
        match self.audit_kubernetes_cluster() {
            Ok(mut findings) => {
                info!("Found {} Kubernetes security issues", findings.len());
                all_findings.append(&mut findings);
            }
            Err(e) => {
                debug!("Kubernetes scan skipped: {}", e);
                // Don't set warning status for K8s issues as it's optional
            }
        }

        // Update result with findings
        for finding in all_findings {
            result.add_finding(finding);
        }

        let duration = start_time.elapsed();
        result.set_duration(duration.as_millis() as u64);
        result.metadata.scanner_version = "0.1.1".to_string();

        info!(
            "Container security scan completed in {}ms with {} findings",
            duration.as_millis(),
            result.findings.len()
        );

        Ok(result)
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"container_security".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_scanner_creation() {
        let scanner = ContainerSecurityScanner::new();
        assert_eq!(scanner.name(), "container_security");
    }

    #[test]
    fn test_docker_availability_check() {
        let scanner = ContainerSecurityScanner::new();
        // This will fail in test environment without Docker, which is expected
        let _is_available = scanner.is_docker_available();
    }

    #[test]
    fn test_sensitive_port_detection() {
        let scanner = ContainerSecurityScanner::new();
        assert!(scanner.is_sensitive_port("22/tcp"));
        assert!(scanner.is_sensitive_port("0.0.0.0:3306->3306/tcp"));
        assert!(!scanner.is_sensitive_port("80/tcp"));
        assert!(!scanner.is_sensitive_port("8080/tcp"));
    }

    #[test]
    fn test_size_parsing() {
        let scanner = ContainerSecurityScanner::new();
        assert_eq!(scanner.parse_size("1.5GB").unwrap(), 1_500_000_000);
        assert_eq!(scanner.parse_size("500MB").unwrap(), 500_000_000);
        assert_eq!(scanner.parse_size("1.2 KB").unwrap(), 1_200);
    }
}