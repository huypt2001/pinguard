use super::{Scanner, ScanResult, ScanError, Finding, Severity, Category, ScanStatus};
use std::process::Command;
use serde::{Deserialize, Serialize};
use std::time::Instant;

pub struct KernelCheck;

#[derive(Debug, Serialize, Deserialize)]
struct KernelInfo {
    version: String,
    release: String,
    machine: String,
    os: String,
}

impl Scanner for KernelCheck {
    fn name(&self) -> &'static str {
        "Kernel Check"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config.scanner.enabled_modules.contains(&"kernel_check".to_string())
    }

    fn scan(&self) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        let mut result = ScanResult::new("Kernel Check".to_string());
        
        tracing::info!("Starting kernel security scan...");
        
        // Get kernel information
        let kernel_info = self.get_kernel_info()?;
        result.set_items_scanned(1);
        
        tracing::info!("Kernel info: {} {}", kernel_info.os, kernel_info.release);
        
        // Kernel versiyonu kontrolleri
        self.check_kernel_version(&kernel_info, &mut result)?;
        
        // Güvenlik güncellemeleri kontrol et
        self.check_security_updates(&kernel_info, &mut result)?;
        
        // /proc/version dosyasını kontrol et
        self.check_proc_version(&mut result)?;
        
        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;
        
        tracing::info!("Kernel check tamamlandı: {} bulgu", result.findings.len());
        
        Ok(result)
    }
}

impl KernelCheck {
    /// Collect kernel information
    fn get_kernel_info(&self) -> Result<KernelInfo, ScanError> {
        // Get kernel information using uname -a command
        let output = Command::new("uname")
            .args(&["-a"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("uname failed: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError("uname command failed".to_string()));
        }

        let uname_output = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = uname_output.trim().split_whitespace().collect();
        
        if parts.len() < 3 {
            return Err(ScanError::ParseError("Invalid uname output".to_string()));
        }

        Ok(KernelInfo {
            os: parts[0].to_string(),           // Linux
            version: parts[2].to_string(),      // Kernel version
            release: parts[2].to_string(),      // Release info
            machine: parts.get(4).unwrap_or(&"unknown").to_string(), // Architecture
        })
    }

    /// Kernel version security checks
    fn check_kernel_version(&self, kernel_info: &KernelInfo, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking kernel version security...");
        
        // Kernel version parsing
        let version_parts: Vec<&str> = kernel_info.version.split('.').collect();
        if version_parts.len() >= 3 {
            let major: u32 = version_parts[0].parse().unwrap_or(0);
            let minor: u32 = version_parts[1].parse().unwrap_or(0);
            let _patch: u32 = version_parts[2].split('-').next().unwrap_or("0").parse().unwrap_or(0);
            
            // Çok eski kernel versiyonları kontrol et
            if major < 4 || (major == 4 && minor < 19) {
                let finding = Finding {
                    id: "KERNEL-OLD-001".to_string(),
                    title: "Eski Kernel Versiyonu".to_string(),
                    description: format!(
                        "Sistem çok eski bir kernel versiyonu kullanıyor: {}. Bu versiyon güvenlik açıklarına karşı savunmasız olabilir.",
                        kernel_info.version
                    ),
                    severity: Severity::High,
                    category: Category::Kernel,
                    affected_item: "Kernel".to_string(),
                    current_value: Some(kernel_info.version.clone()),
                    recommended_value: Some("4.19+ veya daha yeni".to_string()),
                    references: vec![
                        "https://www.kernel.org/".to_string(),
                        "https://wiki.debian.org/KernelFAQ".to_string(),
                        "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=linux+kernel".to_string(),
                    ],
                    cve_ids: self.get_kernel_cves(&kernel_info.version),
                    fix_available: true,
                };
                result.add_finding(finding);
            }
            
            // Warning for non-LTS kernels
            if !self.is_lts_kernel(major, minor) {
                let finding = Finding {
                    id: "KERNEL-LTS-001".to_string(),
                    title: "LTS Olmayan Kernel".to_string(),
                    description: format!(
                        "Kernel versiyon {} LTS (Long Term Support) değil. Güvenlik güncellemeleri kısa sürede sona erecek.",
                        kernel_info.version
                    ),
                    severity: Severity::Medium,
                    category: Category::Kernel,
                    affected_item: "Kernel".to_string(),
                    current_value: Some(kernel_info.version.clone()),
                    recommended_value: Some("LTS kernel versiyonu".to_string()),
                    references: vec![
                        "https://www.kernel.org/category/releases.html".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }

        Ok(())
    }

    /// Check security updates
    fn check_security_updates(&self, _kernel_info: &KernelInfo, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking kernel security updates...");
        
        // apt list --upgradable ile kernel güncellemelerini kontrol et
        let output = Command::new("apt")
            .args(&["list", "--upgradable"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let kernel_updates = self.find_kernel_updates(&text);
                
                for (package, old_version, new_version) in kernel_updates {
                    let finding = Finding {
                        id: format!("KERNEL-UPD-{}", package),
                        title: "Kernel Güvenlik Güncellemesi Mevcut".to_string(),
                        description: format!(
                            "Kernel paketi '{}' için güvenlik güncellemesi mevcut. Mevcut: {}, Yeni: {}",
                            package, old_version, new_version
                        ),
                        severity: Severity::High,
                        category: Category::Kernel,
                        affected_item: package.clone(),
                        current_value: Some(old_version),
                        recommended_value: Some(new_version),
                        references: vec![
                            "https://wiki.debian.org/KernelFAQ#Security_Updates".to_string(),
                            "https://security-tracker.debian.org/tracker/source-package/linux".to_string(),
                        ],
                        cve_ids: self.get_package_cves(&package),
                        fix_available: true,
                    };
                    result.add_finding(finding);
                }
            }
        }

        Ok(())
    }

    /// /proc/version dosyasını kontrol et
    fn check_proc_version(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        let proc_version = std::fs::read_to_string("/proc/version")
            .map_err(|e| ScanError::IoError(e))?;

        // Check compiler information
        if proc_version.contains("gcc version") {
            // GCC versiyonu çok eski mi?
            if let Some(gcc_part) = proc_version.split("gcc version ").nth(1) {
                if let Some(gcc_version) = gcc_part.split_whitespace().next() {
                    let version_num: f32 = gcc_version.split('.').next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0.0);
                    
                    if version_num < 7.0 {
                        let finding = Finding {
                            id: "KERNEL-GCC-001".to_string(),
                            title: "Eski GCC ile Derlenmiş Kernel".to_string(),
                            description: format!(
                                "Kernel eski bir GCC versiyonu ({}) ile derlenmiş. Bu güvenlik açıklarına neden olabilir.",
                                gcc_version
                            ),
                            severity: Severity::Medium,
                            category: Category::Kernel,
                            affected_item: "Kernel Compiler".to_string(),
                            current_value: Some(gcc_version.to_string()),
                            recommended_value: Some("GCC 7.0+".to_string()),
                            references: vec![
                                "https://gcc.gnu.org/releases.html".to_string(),
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

    /// LTS kernel kontrolü
    fn is_lts_kernel(&self, major: u32, minor: u32) -> bool {
        // Bilinen LTS versiyonları
        match (major, minor) {
            (4, 4) | (4, 9) | (4, 14) | (4, 19) | 
            (5, 4) | (5, 10) | (5, 15) | 
            (6, 1) | (6, 6) => true,
            _ => false,
        }
    }

    /// Kernel güncellemelerini bul
    fn find_kernel_updates(&self, text: &str) -> Vec<(String, String, String)> {
        let mut updates = Vec::new();
        
        for line in text.lines() {
            if line.contains("linux-") && line.contains("upgradable") {
                if let Some(package_part) = line.split('/').next() {
                    if let Some(version_part) = line.split(' ').nth(1) {
                        if let Some(old_version_part) = line.split("upgradable from: ").nth(1) {
                            let old_version = old_version_part.trim_end_matches(']');
                            updates.push((
                                package_part.to_string(),
                                old_version.to_string(),
                                version_part.to_string(),
                            ));
                        }
                    }
                }
            }
        }
        
        updates
    }

    /// Kernel versiyonu için bilinen CVE'leri al
    fn get_kernel_cves(&self, kernel_version: &str) -> Vec<String> {
        // Basit kernel versiyonu - CVE mapping
        // Gerçek implementasyonda CVE veritabanından çekilecek
        let major_minor = kernel_version.split('.').take(2).collect::<Vec<_>>().join(".");
        
        match major_minor.as_str() {
            "6.14" | "6.13" | "6.12" => vec![], // Nispeten yeni
            "6.11" | "6.10" => vec!["CVE-2024-example".to_string()],
            "6.9" | "6.8" => vec!["CVE-2024-26581".to_string(), "CVE-2024-26586".to_string()],
            "6.7" | "6.6" => vec!["CVE-2024-26581".to_string()],
            _ if major_minor.starts_with("5.") => vec!["CVE-2023-52340".to_string()],
            _ if major_minor.starts_with("4.") => vec!["CVE-2023-52340".to_string(), "CVE-2022-0847".to_string()],
            _ => vec!["CVE-legacy-kernel".to_string()],
        }
    }

    /// Paket için bilinen CVE'leri al
    fn get_package_cves(&self, package: &str) -> Vec<String> {
        // Basit paket - CVE mapping
        // Gerçek implementasyonda CVE veritabanından çekilecek
        match package {
            p if p.contains("linux-image") => vec!["CVE-2024-kernel-update".to_string()],
            p if p.contains("linux-headers") => vec![],
            p if p.contains("linux-modules") => vec!["CVE-2024-kernel-modules".to_string()],
            _ => vec![],
        }
    }
}