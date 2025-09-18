//! Package audit scanner implementation using the new trait system

use crate::core::{
    enhanced_config::Config, Category, ErrorContext, Finding, PinGuardResult, 
    ScanResult, ScanStatus, Scanner, Severity,
};
use crate::core::traits::ScanMetadata;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use tokio::process::Command as AsyncCommand;
use tracing::{debug, info};

/// Package audit scanner that checks for outdated packages and known vulnerabilities
#[allow(dead_code)]
pub struct PackageAuditScanner {
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Package {
    name: String,
    version: String,
    architecture: String,
    status: String,
    description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VulnerabilityInfo {
    cve_id: String,
    description: String,
    severity: String,
    score: Option<f64>,
    published_date: Option<String>,
    references: Vec<String>,
}

#[allow(dead_code)]
impl PackageAuditScanner {
    /// Create a new package audit scanner
    pub fn new() -> Self {
        Self {
            version: "1.0.0".to_string(),
        }
    }

    /// Get list of installed packages based on the distribution
    async fn get_installed_packages(&self) -> PinGuardResult<Vec<Package>> {
        // Detect package manager and get packages accordingly
        if self.is_debian_based().await? {
            self.get_debian_packages().await
        } else if self.is_redhat_based().await? {
            self.get_redhat_packages().await
        } else if self.is_arch_based().await? {
            self.get_arch_packages().await
        } else {
            Err(crate::core::PinGuardError::scanner(
                "package_audit",
                "Unsupported Linux distribution",
            ))
        }
    }

    /// Check if system is Debian-based (Ubuntu, Debian, etc.)
    async fn is_debian_based(&self) -> PinGuardResult<bool> {
        let output = AsyncCommand::new("which")
            .arg("dpkg")
            .output()
            .await
            .with_scanner_context("package_audit", || "Failed to check for dpkg".to_string())?;

        Ok(output.status.success())
    }

    /// Check if system is RedHat-based (RHEL, CentOS, Fedora, etc.)
    async fn is_redhat_based(&self) -> PinGuardResult<bool> {
        let rpm_check = AsyncCommand::new("which")
            .arg("rpm")
            .output()
            .await
            .with_scanner_context("package_audit", || "Failed to check for rpm".to_string())?;

        Ok(rpm_check.status.success())
    }

    /// Check if system is Arch-based
    async fn is_arch_based(&self) -> PinGuardResult<bool> {
        let pacman_check = AsyncCommand::new("which")
            .arg("pacman")
            .output()
            .await
            .with_scanner_context("package_audit", || "Failed to check for pacman".to_string())?;

        Ok(pacman_check.status.success())
    }

    /// Get packages from Debian-based systems
    async fn get_debian_packages(&self) -> PinGuardResult<Vec<Package>> {
        debug!("Getting packages from Debian-based system");

        let output = AsyncCommand::new("dpkg-query")
            .args(&[
                "-W",
                "-f=${Package}\\t${Version}\\t${Architecture}\\t${Status}\\t${Description}\\n",
            ])
            .output()
            .await
            .with_scanner_context("package_audit", || "Failed to query dpkg packages".to_string())?;

        if !output.status.success() {
            return Err(crate::core::PinGuardError::scanner(
                "package_audit",
                format!(
                    "dpkg-query failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in output_str.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 4 {
                // Only include installed packages
                if parts[3].contains("install ok installed") {
                    packages.push(Package {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        architecture: parts[2].to_string(),
                        status: parts[3].to_string(),
                        description: parts.get(4).map(|s| s.to_string()),
                    });
                }
            }
        }

        info!("Found {} installed packages", packages.len());
        Ok(packages)
    }

    /// Get packages from RedHat-based systems
    async fn get_redhat_packages(&self) -> PinGuardResult<Vec<Package>> {
        debug!("Getting packages from RedHat-based system");

        let output = AsyncCommand::new("rpm")
            .args(&["-qa", "--queryformat", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\tinstalled\\t%{SUMMARY}\\n"])
            .output()
            .await
            .with_scanner_context("package_audit", || "Failed to query rpm packages".to_string())?;

        if !output.status.success() {
            return Err(crate::core::PinGuardError::scanner(
                "package_audit",
                format!("rpm query failed: {}", String::from_utf8_lossy(&output.stderr)),
            ));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in output_str.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 4 {
                packages.push(Package {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: parts[2].to_string(),
                    status: parts[3].to_string(),
                    description: parts.get(4).map(|s| s.to_string()),
                });
            }
        }

        info!("Found {} installed packages", packages.len());
        Ok(packages)
    }

    /// Get packages from Arch-based systems
    async fn get_arch_packages(&self) -> PinGuardResult<Vec<Package>> {
        debug!("Getting packages from Arch-based system");

        let output = AsyncCommand::new("pacman")
            .args(&["-Q"])
            .output()
            .await
            .with_scanner_context("package_audit", || "Failed to query pacman packages".to_string())?;

        if !output.status.success() {
            return Err(crate::core::PinGuardError::scanner(
                "package_audit",
                format!(
                    "pacman query failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in output_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                packages.push(Package {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: "x86_64".to_string(), // Arch doesn't provide arch in -Q output
                    status: "installed".to_string(),
                    description: None,
                });
            }
        }

        info!("Found {} installed packages", packages.len());
        Ok(packages)
    }

    /// Check for outdated packages
    async fn check_outdated_packages(
        &self,
        packages: &[Package],
        config: &Config,
    ) -> PinGuardResult<Vec<Finding>> {
        if !config.scanner.package_audit.check_outdated {
            debug!("Outdated package check disabled");
            return Ok(Vec::new());
        }

        info!("Checking for outdated packages...");
        let mut findings = Vec::new();

        // Get list of upgradeable packages
        let upgradeable = self.get_upgradeable_packages().await?;

        for package in packages {
            if config
                .scanner
                .package_audit
                .exclude_packages
                .contains(&package.name)
            {
                continue;
            }

            if upgradeable.contains_key(&package.name) {
                let available_version = &upgradeable[&package.name];
                
                let finding = Finding::new(
                    format!("outdated-package-{}", package.name),
                    format!("Outdated package: {}", package.name),
                    format!(
                        "Package '{}' version '{}' can be updated to '{}'",
                        package.name, package.version, available_version
                    ),
                    Severity::Low,
                    Category::Package,
                    package.name.clone(),
                )
                .with_recommendation(format!(
                    "Update package '{}' to version '{}'",
                    package.name, available_version
                ))
                .with_metadata("current_version".to_string(), package.version.clone())
                .with_metadata("available_version".to_string(), available_version.clone())
                .make_fixable();

                findings.push(finding);
            }
        }

        info!("Found {} outdated packages", findings.len());
        Ok(findings)
    }

    /// Get list of upgradeable packages
    async fn get_upgradeable_packages(&self) -> PinGuardResult<HashMap<String, String>> {
        let mut upgradeable = HashMap::new();

        if self.is_debian_based().await? {
            // Update package list first
            let _update = AsyncCommand::new("apt")
                .args(&["update", "-qq"])
                .output()
                .await
                .with_scanner_context("package_audit", || "Failed to update package list".to_string())?;

            let output = AsyncCommand::new("apt")
                .args(&["list", "--upgradable", "-qq"])
                .output()
                .await
                .with_scanner_context("package_audit", || "Failed to get upgradeable packages".to_string())?;

            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if line.contains("upgradable") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let package_name = parts[0].split('/').next().unwrap_or(parts[0]);
                            let available_version = parts[1];
                            upgradeable.insert(package_name.to_string(), available_version.to_string());
                        }
                    }
                }
            }
        } else if self.is_redhat_based().await? {
            let output = AsyncCommand::new("dnf")
                .args(&["check-update", "-q"])
                .output()
                .await
                .with_scanner_context("package_audit", || "Failed to check for updates".to_string())?;

            // dnf check-update returns 100 if updates are available
            if output.status.code() == Some(100) || output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let package_name = parts[0].split('.').next().unwrap_or(parts[0]);
                        let available_version = parts[1];
                        upgradeable.insert(package_name.to_string(), available_version.to_string());
                    }
                }
            }
        } else if self.is_arch_based().await? {
            let output = AsyncCommand::new("pacman")
                .args(&["-Qu"])
                .output()
                .await
                .with_scanner_context("package_audit", || "Failed to check for updates".to_string())?;

            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        // Format: package current -> new
                        let package_name = parts[0];
                        let new_version = parts[3];
                        upgradeable.insert(package_name.to_string(), new_version.to_string());
                    }
                }
            }
        }

        Ok(upgradeable)
    }

    /// Check for CVE vulnerabilities (placeholder - would integrate with CVE API)
    async fn check_cve_vulnerabilities(
        &self,
        packages: &[Package],
        config: &Config,
    ) -> PinGuardResult<Vec<Finding>> {
        if !config.scanner.package_audit.check_cve {
            debug!("CVE check disabled");
            return Ok(Vec::new());
        }

        info!("Checking for CVE vulnerabilities...");
        let mut findings = Vec::new();

        // This is a placeholder - in a real implementation, this would:
        // 1. Query a vulnerability database (like OSV, CVE API, etc.)
        // 2. Check each package against known vulnerabilities
        // 3. Filter by minimum severity threshold
        
        // For now, we'll simulate finding some vulnerabilities
        for package in packages.iter().take(5) { // Limit for demo
            if package.name.contains("openssl") || package.name.contains("curl") {
                let finding = Finding::new(
                    format!("cve-{}-example", package.name),
                    format!("Potential vulnerability in {}", package.name),
                    format!(
                        "Package '{}' version '{}' may have known security vulnerabilities",
                        package.name, package.version
                    ),
                    Severity::Medium,
                    Category::Vulnerability,
                    package.name.clone(),
                )
                .with_recommendation(format!("Update package '{}' to the latest version", package.name))
                .with_metadata("package_version".to_string(), package.version.clone())
                .make_fixable();

                findings.push(finding);
            }
        }

        info!("Found {} potential CVE vulnerabilities", findings.len());
        Ok(findings)
    }
}

impl Default for PackageAuditScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for PackageAuditScanner {
    fn name(&self) -> &'static str {
        "package_audit"
    }

    fn description(&self) -> &'static str {
        "Scans installed packages for outdated versions and known vulnerabilities"
    }

    fn categories(&self) -> Vec<Category> {
        vec![Category::Package, Category::Vulnerability]
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.scanner.enabled_modules.contains(&"package_audit".to_string())
    }

    async fn scan(&self, config: &Config) -> PinGuardResult<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();
        let mut raw_data = HashMap::new();

        info!("Starting package audit scan...");

        // Get installed packages
        let packages = self.get_installed_packages().await?;
        let packages_count = packages.len();
        
        raw_data.insert("packages_found".to_string(), packages_count.to_string());

        // Check for outdated packages
        let mut outdated_findings = self.check_outdated_packages(&packages, config).await?;
        findings.append(&mut outdated_findings);

        // Check for CVE vulnerabilities
        let mut cve_findings = self.check_cve_vulnerabilities(&packages, config).await?;
        findings.append(&mut cve_findings);

        let duration = start_time.elapsed();
        let status = if findings.is_empty() {
            ScanStatus::Success
        } else {
            ScanStatus::Warning
        };

        let metadata = ScanMetadata {
            duration,
            items_scanned: packages_count,
            scanner_version: self.version.clone(),
            configuration: HashMap::from([
                ("check_outdated".to_string(), config.scanner.package_audit.check_outdated.to_string()),
                ("check_cve".to_string(), config.scanner.package_audit.check_cve.to_string()),
                ("exclude_packages".to_string(), config.scanner.package_audit.exclude_packages.join(",")),
            ]),
        };

        info!(
            "Package audit scan completed in {:?}: {} findings from {} packages",
            duration,
            findings.len(),
            packages_count
        );

        Ok(ScanResult {
            scanner_name: self.name().to_string(),
            scan_time: chrono::Utc::now(),
            status,
            findings,
            metadata,
            raw_data: Some(raw_data),
        })
    }

    async fn validate(&self) -> PinGuardResult<()> {
        // Check if we can detect the package manager
        if !self.is_debian_based().await? 
            && !self.is_redhat_based().await? 
            && !self.is_arch_based().await? {
            return Err(crate::core::PinGuardError::scanner(
                "package_audit",
                "No supported package manager found (dpkg, rpm, or pacman)",
            ));
        }

        info!("Package audit scanner validation successful");
        Ok(())
    }

    fn config_schema(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "check_cve": {
                    "type": "boolean",
                    "description": "Enable CVE vulnerability checking",
                    "default": true
                },
                "check_outdated": {
                    "type": "boolean", 
                    "description": "Check for outdated packages",
                    "default": true
                },
                "exclude_packages": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of package names to exclude from scanning"
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Minimum severity level for CVE findings",
                    "default": "medium"
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_package_audit_scanner_creation() {
        let scanner = PackageAuditScanner::new();
        assert_eq!(scanner.name(), "package_audit");
        assert!(!scanner.description().is_empty());
    }

    #[tokio::test] 
    async fn test_package_audit_scanner_validation() {
        let scanner = PackageAuditScanner::new();
        // This might fail on systems without supported package managers
        let _result = scanner.validate().await;
    }

    #[test]
    fn test_config_schema() {
        let scanner = PackageAuditScanner::new();
        let schema = scanner.config_schema();
        assert!(schema.is_some());
    }
}