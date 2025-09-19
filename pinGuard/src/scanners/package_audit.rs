use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
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
        let mut result = ScanResult::new("Package Audit".to_string());

        info!("Starting package audit scan...");

        // Paket listesini al
        let packages = self.get_installed_packages()?;
        result.set_items_scanned(packages.len() as u32);

        info!("{} paket tespit edildi", packages.len());

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

        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;

        info!(
            "Package audit completed: {} findings",
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
                });
            }
        }

        Ok(packages)
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

    /// Check CVE vulnerabilities
    fn check_cve_vulnerabilities(
        &self,
        packages: &[Package],
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        info!("Checking CVE vulnerabilities...");

        let cve_manager = match &self.cve_manager {
            Some(manager) => manager,
            None => {
                return Err(ScanError::ConfigurationError(
                    "CVE manager not available".to_string(),
                ));
            }
        };

        // Async runtime for CVE operations
        let rt = tokio::runtime::Runtime::new().map_err(|e| {
            ScanError::InternalError(format!("Failed to create async runtime: {}", e))
        })?;

        // Health check
        let health_check = rt.block_on(async { cve_manager.health_check().await });

        match health_check {
            Ok(health) => {
                if !health.is_healthy() {
                    warn!(
                        "CVE manager sağlık kontrolü başarısız: API={}, Cache={}",
                        health.nvd_api_healthy, health.cache_healthy
                    );
                }
            }
            Err(e) => {
                error!("CVE manager health check error: {}", e);
                return Err(ScanError::ExternalServiceError(format!(
                    "CVE service unavailable: {}",
                    e
                )));
            }
        }

        let mut cve_findings_count = 0;

        // Her paket için CVE kontrol et (batch olarak)
        let package_names: Vec<String> = packages
            .iter()
            .take(50) // İlk 50 paket ile sınırla (rate limiting için)
            .map(|p| p.name.clone())
            .collect();

        for package_name in package_names {
            debug!("🔍 Package için CVE aranıyor: {}", package_name);

            match rt.block_on(async { cve_manager.find_cves_for_package(&package_name).await }) {
                Ok(cve_list) => {
                    if !cve_list.is_empty() {
                        info!("{} için {} CVE bulundu", package_name, cve_list.len());

                        // Her CVE için finding oluştur
                        for cve_data in cve_list {
                            let severity = match cve_data.severity {
                                CveSeverity::Critical => Severity::Critical,
                                CveSeverity::High => Severity::High,
                                CveSeverity::Medium => Severity::Medium,
                                CveSeverity::Low => Severity::Low,
                                CveSeverity::Unknown => Severity::Info,
                                CveSeverity::None => Severity::Info,
                            };

                            let finding = Finding {
                                id: format!("CVE-{}-{}", cve_data.cve_id, package_name),
                                title: format!("CVE güvenlik açığı: {} ({})", cve_data.cve_id, package_name),
                                description: format!(
                                    "Paket '{}' için CVE güvenlik açığı tespit edildi: {}\n\nAçıklama: {}",
                                    package_name,
                                    cve_data.cve_id,
                                    cve_data.description
                                ),
                                severity,
                                category: Category::Security,
                                affected_item: package_name.clone(),
                                current_value: None,
                                recommended_value: Some("Paket güncellemesi gerekli".to_string()),
                                references: vec![
                                    format!("https://nvd.nist.gov/vuln/detail/{}", cve_data.cve_id),
                                    format!("https://cve.mitre.org/cgi-bin/cvename.cgi?name={}", cve_data.cve_id),
                                ],
                                cve_ids: vec![cve_data.cve_id.clone()],
                                fix_available: true, // Paket güncellemesi ile çözülebilir varsayımı
                            };

                            result.add_finding(finding);
                            cve_findings_count += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!("CVE search error {}: {}", package_name, e);
                    // Continue with other packages
                }
            }

            // Rate limiting - small delay between packages
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        info!(
            "CVE check completed: {} vulnerabilities found",
            cve_findings_count
        );
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
