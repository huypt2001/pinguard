use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::process::Command;
use std::time::Instant;
use tracing::{debug, error, info, warn};

use crate::cve::cve_manager::CveManager;
use crate::database::cve_cache::{CveData, CveSeverity};

pub struct PackageAudit {
    cve_manager: Option<CveManager>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Package {
    name: String,
    version: String,
    architecture: String,
    status: String,
    vulnerabilities: Vec<String>, // CVE IDs
    cve_details: Vec<CveData>,    // Enriched CVE data
    dependencies: Vec<String>,    // Package dependencies
    size: u64,                    // Package size in bytes
    source: String,               // Source package
    essential: bool,              // Essential system package
}

#[derive(Debug, Serialize, Deserialize)]
struct VulnerabilityStats {
    total_packages: usize,
    vulnerable_packages: usize,
    critical_cves: usize,
    high_cves: usize,
    medium_cves: usize,
    low_cves: usize,
    outdated_packages: usize,
    unverified_packages: usize,
    risky_packages: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct CveInfo {
    id: String,
    description: String,
    severity: String,
    score: f32,
    published_date: String,
}

impl Default for PackageAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageAudit {
    pub fn new() -> Self {
        Self { cve_manager: None }
    }

    /// CVE manager ile paketi oluştur
    #[allow(dead_code)]
    pub fn with_cve_manager(mut self, cve_manager: CveManager) -> Self {
        self.cve_manager = Some(cve_manager);
        self
    }
}

impl Scanner for PackageAudit {
    fn name(&self) -> &'static str {
        "package_audit"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"package_audit".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Enhanced Package Audit".to_string());

        info!("Starting enhanced package audit scan...");

        // Paket listesini al
        let mut packages = self.get_installed_packages()?;
        result.set_items_scanned(packages.len() as u32);

        info!("{} paket tespit edildi", packages.len());

        // Enhanced dependency analysis (sample only for performance)
        if packages.len() > 100 {
            info!("Large package count detected, analyzing sample for dependencies...");
            let sample_size = 50; // Analyze only first 50 packages
            if let Err(e) = self.analyze_package_dependencies(&mut packages[0..sample_size]) {
                warn!("Dependency analysis failed: {}", e);
            }
        } else if let Err(e) = self.analyze_package_dependencies(&mut packages) {
            warn!("Dependency analysis failed: {}", e);
        }

        // Risky package detection
        self.check_risky_packages(&packages, &mut result)?;

        // Eski paketleri bul
        self.check_outdated_packages(&packages, &mut result)?;

        // CVE kontrolü
        if self.cve_manager.is_some() {
            match self.check_cve_vulnerabilities(&packages, &mut result) {
                Ok(_) => {
                    info!("CVE check completed");
                }
                Err(e) => {
                    warn!("CVE check error: {}", e);
                    // Continue with scan, don't fail
                }
            }
        } else {
            info!("CVE manager not available, skipping CVE check");
        }

        // Generate comprehensive statistics
        let stats = self.generate_vulnerability_stats(&result);
        info!(
            "📊 Package Security Summary: {}/{} packages have vulnerabilities, {} outdated, {} from unverified sources",
            stats.vulnerable_packages, stats.total_packages, stats.outdated_packages, stats.unverified_packages
        );

        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;

        info!(
            "Enhanced package audit completed: {} findings",
            result.findings.len()
        );

        Ok(result)
    }
}

impl PackageAudit {
    /// Kurulu paketleri listele
    fn get_installed_packages(&self) -> Result<Vec<Package>, ScanError> {
        let output = Command::new("dpkg-query")
            .args([
                "-W",
                "--showformat=${Package}|${Version}|${Architecture}|${Status}\n",
            ])
            .output()
            .map_err(|e| ScanError::CommandError(format!("dpkg-query failed: {}", e)))?;

        if !output.status.success() {
            // Fallback: RPM-based sistemler için
            return self.get_rpm_packages();
        }

        let packages_text = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in packages_text.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 4 {
                packages.push(Package {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: parts[2].to_string(),
                    status: parts[3].to_string(),
                    vulnerabilities: Vec::new(),
                    cve_details: Vec::new(),
                    dependencies: Vec::new(),
                    size: 0,
                    source: parts[0].to_string(), // Default to package name
                    essential: false,
                });
            }
        }

        Ok(packages)
    }

    /// RPM-based sistemler için paket listesi
    fn get_rpm_packages(&self) -> Result<Vec<Package>, ScanError> {
        let output = Command::new("rpm")
            .args([
                "-qa",
                "--queryformat",
                "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|installed\n",
            ])
            .output()
            .map_err(|e| ScanError::CommandError(format!("rpm query failed: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError(
                "Neither dpkg nor rpm available".to_string(),
            ));
        }

        let packages_text = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in packages_text.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 4 {
                packages.push(Package {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: parts[2].to_string(),
                    status: parts[3].to_string(),
                    vulnerabilities: Vec::new(),
                    cve_details: Vec::new(),
                    dependencies: Vec::new(),
                    size: 0,
                    source: parts[0].to_string(), // Default to package name
                    essential: false,
                });
            }
        }

        Ok(packages)
    }

    /// Enhanced package dependency analysis
    fn analyze_package_dependencies(&self, packages: &mut [Package]) -> Result<(), ScanError> {
        info!("Analyzing package dependencies...");
        
        for package in packages.iter_mut() {
            // Get dependencies for each package
            match self.get_package_dependencies(&package.name) {
                Ok(deps) => package.dependencies = deps,
                Err(_) => continue, // Skip on error
            }
            
            // Get package size and source info
            if let Ok(info) = self.get_package_info(&package.name) {
                package.size = info.0;
                package.source = info.1;
                package.essential = info.2;
            }
        }
        
        Ok(())
    }
    
    /// Get package dependencies
    fn get_package_dependencies(&self, package_name: &str) -> Result<Vec<String>, ScanError> {
        let output = Command::new("apt-cache")
            .args(["depends", package_name])
            .output()
            .map_err(|e| ScanError::CommandError(format!("apt-cache depends failed: {}", e)))?;
            
        if !output.status.success() {
            return Ok(Vec::new());
        }
        
        let text = String::from_utf8_lossy(&output.stdout);
        let mut dependencies = Vec::new();
        
        for line in text.lines() {
            if line.trim().starts_with("Depends:") {
                if let Some(dep) = line.split("Depends:").nth(1) {
                    dependencies.push(dep.trim().to_string());
                }
            }
        }
        
        Ok(dependencies)
    }
    
    /// Get package size, source and essential status
    fn get_package_info(&self, package_name: &str) -> Result<(u64, String, bool), ScanError> {
        let output = Command::new("dpkg-query")
            .args(["-W", "--showformat=${Installed-Size}|${Source}|${Essential}\n", package_name])
            .output()
            .map_err(|e| ScanError::CommandError(format!("dpkg-query info failed: {}", e)))?;
            
        if !output.status.success() {
            return Ok((0, package_name.to_string(), false));
        }
        
        let text = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = text.trim().split('|').collect();
        
        let size = parts.get(0).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) * 1024; // KB to bytes
        let source = parts.get(1).map(|s| s.to_string()).unwrap_or_else(|| package_name.to_string());
        let essential = parts.get(2).map(|s| *s == "yes").unwrap_or(false);
        
        Ok((size, source, essential))
    }
    
    /// Check for risky or suspicious packages
    fn check_risky_packages(&self, packages: &[Package], result: &mut ScanResult) -> Result<(), ScanError> {
        info!("Checking for risky packages...");
        
        let risky_patterns = [
            "backdoor", "keylogger", "rootkit", "trojan", "malware",
            "bitcoin", "miner", "crypto", "tor", "proxy", "tunnel"
        ];
        
        let suspicious_sources = HashSet::from([
            "unknown", "unofficial", "third-party", "custom"
        ]);
        
        for package in packages {
            // Check package name for risky patterns
            let package_lower = package.name.to_lowercase();
            for pattern in &risky_patterns {
                if package_lower.contains(pattern) {
                    let finding = Finding {
                        id: format!("PKG-RISKY-{}", package.name),
                        title: format!("Risky package detected: {}", package.name),
                        description: format!(
                            "Package '{}' contains suspicious keyword '{}' and may pose security risks.",
                            package.name, pattern
                        ),
                        severity: Severity::High,
                        category: Category::Security,
                        affected_item: package.name.clone(),
                        current_value: Some(package.version.clone()),
                        recommended_value: Some("Review and remove if unnecessary".to_string()),
                        references: vec![
                            "https://wiki.debian.org/PackageSecurity".to_string(),
                        ],
                        cve_ids: vec![],
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }
            }
            
            // Check for packages from suspicious sources
            if suspicious_sources.contains(package.source.as_str()) {
                let finding = Finding {
                    id: format!("PKG-SRC-{}", package.name),
                    title: format!("Package from unverified source: {}", package.name),
                    description: format!(
                        "Package '{}' is from potentially unverified source: '{}'",
                        package.name, package.source
                    ),
                    severity: Severity::Medium,
                    category: Category::Security,
                    affected_item: package.name.clone(),
                    current_value: Some(package.source.clone()),
                    recommended_value: Some("Verify package authenticity".to_string()),
                    references: vec![
                        "https://wiki.debian.org/RepositoryFormat".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: false,
                };
                result.add_finding(finding);
            }
        }
        
        Ok(())
    }
    
    /// Generate vulnerability statistics
    fn generate_vulnerability_stats(&self, result: &ScanResult) -> VulnerabilityStats {
        let mut stats = VulnerabilityStats {
            total_packages: result.metadata.items_scanned as usize,
            vulnerable_packages: 0,
            critical_cves: 0,
            high_cves: 0,
            medium_cves: 0,
            low_cves: 0,
            outdated_packages: 0,
            unverified_packages: 0,
            risky_packages: 0,
        };
        
        let mut vulnerable_packages = HashSet::new();
        
        for finding in &result.findings {
            match finding.severity {
                Severity::Critical => stats.critical_cves += 1,
                Severity::High => stats.high_cves += 1,
                Severity::Medium => stats.medium_cves += 1,
                Severity::Low => stats.low_cves += 1,
                _ => {}
            }
            
            if finding.id.contains("CVE") {
                vulnerable_packages.insert(&finding.affected_item);
            } else if finding.id.contains("OUT") {
                stats.outdated_packages += 1;
            } else if finding.id.contains("SRC") {
                stats.unverified_packages += 1;
            } else if finding.id.contains("RISKY") {
                stats.risky_packages += 1;
            }
        }
        
        stats.vulnerable_packages = vulnerable_packages.len();
        stats
    }

    /// Check outdated packages
    fn check_outdated_packages(
        &self,
        _packages: &[Package],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        info!("Checking outdated packages...");

        // apt list --upgradable komutu ile güncellenebilir paketleri bul
        let output = Command::new("apt").args(["list", "--upgradable"]).output();

        let upgradable_packages = match output {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                self.parse_upgradable_packages(&text)
            }
            _ => {
                // RPM-based sistemler için yum/dnf check-update
                self.check_rpm_updates()?
            }
        };

        // Bulgular oluştur
        for (package_name, old_version, new_version) in upgradable_packages {
            let finding = Finding {
                id: format!("PKG-OUT-{}", package_name),
                title: format!("Güncel olmayan paket: {}", package_name),
                description: format!(
                    "Paket '{}' güncel değil. Mevcut versiyon: {}, Güncel versiyon: {}",
                    package_name, old_version, new_version
                ),
                severity: Severity::Medium,
                category: Category::Package,
                affected_item: package_name.clone(),
                current_value: Some(old_version),
                recommended_value: Some(new_version),
                references: vec![
                    "https://wiki.debian.org/AptSafety".to_string(),
                    "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/"
                        .to_string(),
                ],
                cve_ids: vec![], // CVE kontrolünde doldurulacak
                fix_available: true,
            };

            result.add_finding(finding);
        }

        Ok(())
    }

    /// Check CVE vulnerabilities (temporarily disabled to avoid runtime conflicts)
    fn check_cve_vulnerabilities(
        &self,
        packages: &[Package],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        info!("CVE vulnerability checking temporarily disabled to avoid runtime conflicts...");
        
        // TODO: Implement proper async CVE checking without blocking runtime
        // For now, just log that CVE checking was skipped
        let package_count = packages.len();
        info!("Skipped CVE checking for {} packages", package_count);
        
        // Add a finding to indicate CVE checking was skipped
        let finding = Finding {
            id: "CVE-CHECK-SKIPPED".to_string(),
            title: "CVE Checking Skipped".to_string(),
            description: format!(
                "CVE vulnerability checking was skipped for {} packages due to runtime constraints. Consider running CVE check separately.",
                package_count
            ),
            severity: Severity::Low,
            category: Category::Package,
            affected_item: "CVE Checking".to_string(),
            current_value: Some("Disabled".to_string()),
            recommended_value: Some("Enable CVE checking in standalone mode".to_string()),
            references: vec![
                "https://nvd.nist.gov/".to_string(),
            ],
            cve_ids: vec![],
            fix_available: false,
        };
        result.add_finding(finding);
        
        Ok(())
    }

    /// apt list --upgradable çıktısını parse et
    fn parse_upgradable_packages(&self, text: &str) -> Vec<(String, String, String)> {
        let mut packages = Vec::new();

        for line in text.lines() {
            if line.contains("upgradable") {
                // Örnek format: "package/release version [upgradable from: old_version]"
                if let Some(package_part) = line.split('/').next() {
                    if let Some(version_part) = line.split(' ').nth(1) {
                        if let Some(old_version_part) = line.split("upgradable from: ").nth(1) {
                            let old_version = old_version_part.trim_end_matches(']');
                            packages.push((
                                package_part.to_string(),
                                old_version.to_string(),
                                version_part.to_string(),
                            ));
                        }
                    }
                }
            }
        }

        packages
    }

    /// RPM-based sistemlerde güncellemeleri kontrol et
    fn check_rpm_updates(&self) -> Result<Vec<(String, String, String)>, ScanError> {
        let output = Command::new("yum")
            .args(["check-update", "--quiet"])
            .output()
            .or_else(|_| {
                Command::new("dnf")
                    .args(["check-update", "--quiet"])
                    .output()
            })
            .map_err(|e| ScanError::CommandError(format!("Package update check failed: {}", e)))?;

        // check-update komutunun exit code 100 olması güncellemeler olduğunu gösterir
        if output.status.code() == Some(100) {
            let text = String::from_utf8_lossy(&output.stdout);
            return Ok(self.parse_yum_updates(&text));
        }

        Ok(Vec::new())
    }

    /// yum/dnf check-update çıktısını parse et
    fn parse_yum_updates(&self, text: &str) -> Vec<(String, String, String)> {
        let mut packages = Vec::new();

        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let package_name = parts[0].split('.').next().unwrap_or(parts[0]);
                packages.push((
                    package_name.to_string(),
                    "unknown".to_string(), // No old version information available
                    parts[1].to_string(),  // Yeni versiyon
                ));
            }
        }

        packages
    }
}
