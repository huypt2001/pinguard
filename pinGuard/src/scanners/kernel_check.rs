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
        
        tracing::info!("🔍 Kernel güvenlik taraması başlatılıyor...");
        
        // Kernel bilgilerini al
        let kernel_info = self.get_kernel_info()?;
        result.set_items_scanned(1);
        
        tracing::info!("🐧 Kernel bilgisi: {} {}", kernel_info.os, kernel_info.release);
        
        // Kernel versiyonu kontrolleri
        self.check_kernel_version(&kernel_info, &mut result)?;
        
        // Güvenlik güncellemeleri kontrol et
        self.check_security_updates(&kernel_info, &mut result)?;
        
        // /proc/version dosyasını kontrol et
        self.check_proc_version(&mut result)?;
        
        result.set_duration(start_time.elapsed().as_millis() as u64);
        result.status = ScanStatus::Success;
        
        tracing::info!("✅ Kernel check tamamlandı: {} bulgu", result.findings.len());
        
        Ok(result)
    }
}

impl KernelCheck {
    /// Kernel bilgilerini topla
    fn get_kernel_info(&self) -> Result<KernelInfo, ScanError> {
        // uname -a komutu ile kernel bilgilerini al
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

    /// Kernel versiyonu güvenlik kontrolleri
    fn check_kernel_version(&self, kernel_info: &KernelInfo, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("🔍 Kernel versiyon güvenliği kontrol ediliyor...");
        
        // Kernel version parsing
        let version_parts: Vec<&str> = kernel_info.version.split('.').collect();
        if version_parts.len() >= 3 {
            let major: u32 = version_parts[0].parse().unwrap_or(0);
            let minor: u32 = version_parts[1].parse().unwrap_or(0);
            let patch: u32 = version_parts[2].split('-').next().unwrap_or("0").parse().unwrap_or(0);
            
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
                    ],
                    cve_ids: vec![], // TODO: Kernel CVE veritabanı entegrasyonu
                    fix_available: true,
                };
                result.add_finding(finding);
            }
            
            // LTS olmayan kerneller için uyarı
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

    /// Güvenlik güncellemelerini kontrol et
    fn check_security_updates(&self, _kernel_info: &KernelInfo, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("🔍 Kernel güvenlik güncellemeleri kontrol ediliyor...");
        
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
                        ],
                        cve_ids: vec![], // TODO: CVE bilgilerini çek
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

        // Compiler bilgilerini kontrol et
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
}