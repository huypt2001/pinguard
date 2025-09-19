use super::{Category, Finding, ScanError, ScanResult, ScanStatus, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
use std::time::Instant;

pub struct KernelCheck;

#[derive(Debug, Serialize, Deserialize)]
struct KernelInfo {
    version: String,
    release: String,
    machine: String,
    os: String,
    build_date: String,
    compiler: String,
    config_flags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KernelSecurityFeature {
    name: String,
    enabled: bool,
    description: String,
    severity_if_disabled: Severity,
}

#[derive(Debug, Serialize, Deserialize)]
struct KernelVulnerability {
    cve_id: String,
    title: String,
    affected_versions: Vec<String>,
    fixed_in: String,
    severity: Severity,
}

impl Default for KernelCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelCheck {
    pub fn new() -> Self {
        Self
    }
}

impl Scanner for KernelCheck {
    fn name(&self) -> &'static str {
        "kernel_check"
    }

    fn is_enabled(&self, config: &crate::core::config::Config) -> bool {
        config
            .scanner
            .enabled_modules
            .contains(&"kernel_check".to_string())
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

        // Kernel güvenlik özelliklerini kontrol et
        self.check_security_features(&mut result)?;

        // Kernel modül güvenliğini kontrol et
        self.check_kernel_modules(&mut result)?;

        // Memory protection kontrolü
        self.check_memory_protection(&mut result)?;

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
            .args(["-a"])
            .output()
            .map_err(|e| ScanError::CommandError(format!("uname failed: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError("uname command failed".to_string()));
        }

        let uname_output = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = uname_output.split_whitespace().collect();

        if parts.len() < 3 {
            return Err(ScanError::ParseError("Invalid uname output".to_string()));
        }

        Ok(KernelInfo {
            os: parts[0].to_string(),                                // Linux
            version: parts[2].to_string(),                           // Kernel version
            release: parts[2].to_string(),                           // Release info
            machine: parts.get(4).unwrap_or(&"unknown").to_string(), // Architecture
            build_date: self.get_kernel_build_date()?,
            compiler: self.get_kernel_compiler()?,
            config_flags: self.get_kernel_config_flags()?,
        })
    }

    /// Kernel version security checks
    fn check_kernel_version(
        &self,
        kernel_info: &KernelInfo,
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        tracing::info!("Checking kernel version security...");

        // Kernel version parsing
        let version_parts: Vec<&str> = kernel_info.version.split('.').collect();
        if version_parts.len() >= 3 {
            let major: u32 = version_parts[0].parse().unwrap_or(0);
            let minor: u32 = version_parts[1].parse().unwrap_or(0);
            let _patch: u32 = version_parts[2]
                .split('-')
                .next()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);

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
    fn check_security_updates(
        &self,
        _kernel_info: &KernelInfo,
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        tracing::info!("Checking kernel security updates...");

        // apt list --upgradable ile kernel güncellemelerini kontrol et
        let output = Command::new("apt").args(["list", "--upgradable"]).output();

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
                        cve_ids: vec![], // Will be populated by CVE analysis
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
        let proc_version = std::fs::read_to_string("/proc/version").map_err(ScanError::IoError)?;

        // Check compiler information
        if proc_version.contains("gcc version") {
            // GCC versiyonu çok eski mi?
            if let Some(gcc_part) = proc_version.split("gcc version ").nth(1) {
                if let Some(gcc_version) = gcc_part.split_whitespace().next() {
                    let version_num: f32 = gcc_version
                        .split('.')
                        .next()
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
        matches!(
            (major, minor),
            (4, 4) | (4, 9) | (4, 14) | (4, 19) | (5, 4) | (5, 10) | (5, 15) | (6, 1) | (6, 6)
        )
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
        // Known kernel vulnerabilities database (simplified)
        let mut cves = Vec::new();
        
        // Parse version for vulnerability matching
        if let Some(major_minor) = kernel_version.split('.').take(2).collect::<Vec<_>>().get(0..2) {
            let version_key = format!("{}.{}", major_minor[0], major_minor[1]);
            
            // Sample known vulnerabilities (in real implementation, this would be from a database)
            let known_vulns = self.get_known_kernel_vulnerabilities();
            
            for vuln in known_vulns {
                if vuln.affected_versions.contains(&version_key) {
                    cves.push(vuln.cve_id);
                }
            }
        }
        
        cves
    }
    
    /// Get kernel build date
    fn get_kernel_build_date(&self) -> Result<String, ScanError> {
        match fs::read_to_string("/proc/version") {
            Ok(content) => {
                // Extract build date from /proc/version
                if let Some(date_start) = content.find("(") {
                    if let Some(date_end) = content[date_start..].find(")") {
                        return Ok(content[date_start+1..date_start+date_end].to_string());
                    }
                }
                Ok("unknown".to_string())
            }
            Err(_) => Ok("unknown".to_string()),
        }
    }
    
    /// Get kernel compiler information
    fn get_kernel_compiler(&self) -> Result<String, ScanError> {
        match fs::read_to_string("/proc/version") {
            Ok(content) => {
                if content.contains("gcc") {
                    for part in content.split_whitespace() {
                        if part.starts_with("gcc") {
                            return Ok(part.to_string());
                        }
                    }
                }
                Ok("unknown".to_string())
            }
            Err(_) => Ok("unknown".to_string()),
        }
    }
    
    /// Get kernel configuration flags
    fn get_kernel_config_flags(&self) -> Result<Vec<String>, ScanError> {
        let config_paths = [
            "/proc/config.gz",
            "/boot/config",
            &format!("/boot/config-{}", std::env::var("KERNEL_VERSION").unwrap_or_default()),
        ];
        
        for path in &config_paths {
            if let Ok(content) = fs::read_to_string(path) {
                return Ok(content.lines()
                    .filter(|line| line.starts_with("CONFIG_"))
                    .take(20) // Limit for performance
                    .map(|s| s.to_string())
                    .collect());
            }
        }
        
        Ok(Vec::new())
    }
    
    /// Check kernel security features
    fn check_security_features(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking kernel security features...");
        
        let security_features = self.get_security_features_to_check();
        
        for feature in security_features {
            if !feature.enabled {
                let finding = Finding {
                    id: format!("KERNEL-SEC-{}", feature.name.replace("_", "-")),
                    title: format!("Kernel güvenlik özelliği devre dışı: {}", feature.name),
                    description: format!(
                        "Kernel güvenlik özelliği '{}' devre dışı. {}",
                        feature.name, feature.description
                    ),
                    severity: feature.severity_if_disabled,
                    category: Category::Kernel,
                    affected_item: feature.name.clone(),
                    current_value: Some("Disabled".to_string()),
                    recommended_value: Some("Enabled".to_string()),
                    references: vec![
                        "https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project".to_string(),
                        "https://wiki.archlinux.org/title/Security#Kernel_hardening".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }
        
        Ok(())
    }
    
    /// Check kernel modules security
    fn check_kernel_modules(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking kernel modules security...");
        
        // Check for unsigned modules
        if let Ok(modules) = fs::read_to_string("/proc/modules") {
            let module_count = modules.lines().count();
            
            if module_count > 200 {
                let finding = Finding {
                    id: "KERNEL-MOD-001".to_string(),
                    title: "Çok fazla kernel modülü yüklü".to_string(),
                    description: format!(
                        "Sistemde {} kernel modülü yüklü. Bu, saldırı yüzeyini artırabilir.",
                        module_count
                    ),
                    severity: Severity::Medium,
                    category: Category::Kernel,
                    affected_item: "Kernel Modules".to_string(),
                    current_value: Some(module_count.to_string()),
                    recommended_value: Some("Gereksiz modülleri kaldır".to_string()),
                    references: vec![
                        "https://wiki.archlinux.org/title/Kernel_module".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }
        
        Ok(())
    }
    
    /// Check memory protection features
    fn check_memory_protection(&self, result: &mut ScanResult) -> Result<(), ScanError> {
        tracing::info!("Checking memory protection features...");
        
        // Check ASLR
        if let Ok(aslr) = fs::read_to_string("/proc/sys/kernel/randomize_va_space") {
            let aslr_level: u32 = aslr.trim().parse().unwrap_or(0);
            
            if aslr_level < 2 {
                let finding = Finding {
                    id: "KERNEL-ASLR-001".to_string(),
                    title: "ASLR (Address Space Layout Randomization) yetersiz".to_string(),
                    description: format!(
                        "ASLR seviyesi {} (önerilen: 2). Bu, buffer overflow saldırılarına karşı korumayı azaltır.",
                        aslr_level
                    ),
                    severity: Severity::High,
                    category: Category::Kernel,
                    affected_item: "ASLR".to_string(),
                    current_value: Some(aslr_level.to_string()),
                    recommended_value: Some("2".to_string()),
                    references: vec![
                        "https://linux-audit.com/linux-aslr-and-kernexec-some-protection-provided/".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: true,
                };
                result.add_finding(finding);
            }
        }
        
        // Check DEP/NX bit
        if let Ok(output) = Command::new("grep").args(["nx", "/proc/cpuinfo"]).output() {
            if output.stdout.is_empty() {
                let finding = Finding {
                    id: "KERNEL-NX-001".to_string(),
                    title: "NX bit desteği eksik".to_string(),
                    description: "CPU NX bit desteği eksik. Bu, kod enjeksiyon saldırılarına karşı korumayı azaltır.".to_string(),
                    severity: Severity::High,
                    category: Category::Kernel,
                    affected_item: "NX bit".to_string(),
                    current_value: Some("Not supported".to_string()),
                    recommended_value: Some("NX bit destekli CPU".to_string()),
                    references: vec![
                        "https://en.wikipedia.org/wiki/NX_bit".to_string(),
                    ],
                    cve_ids: vec![],
                    fix_available: false,
                };
                result.add_finding(finding);
            }
        }
        
        Ok(())
    }
    
    /// Get known kernel vulnerabilities (simplified database)
    fn get_known_kernel_vulnerabilities(&self) -> Vec<KernelVulnerability> {
        vec![
            KernelVulnerability {
                cve_id: "CVE-2023-32233".to_string(),
                title: "Netfilter nf_tables Privilege Escalation".to_string(),
                affected_versions: vec!["6.1".to_string(), "6.2".to_string()],
                fixed_in: "6.3.1".to_string(),
                severity: Severity::Critical,
            },
            KernelVulnerability {
                cve_id: "CVE-2022-32250".to_string(),
                title: "Netfilter nf_tables Buffer Overflow".to_string(),
                affected_versions: vec!["5.4".to_string(), "5.10".to_string(), "5.15".to_string()],
                fixed_in: "5.18.3".to_string(),
                severity: Severity::High,
            },
            KernelVulnerability {
                cve_id: "CVE-2021-4034".to_string(),
                title: "PwnKit - pkexec Local Privilege Escalation".to_string(),
                affected_versions: vec!["4.19".to_string(), "5.4".to_string(), "5.10".to_string()],
                fixed_in: "5.16.5".to_string(),
                severity: Severity::Critical,
            },
        ]
    }
    
    /// Get security features to check
    fn get_security_features_to_check(&self) -> Vec<KernelSecurityFeature> {
        // In a real implementation, this would read from /proc/config.gz or /boot/config-*
        vec![
            KernelSecurityFeature {
                name: "CONFIG_STRICT_KERNEL_RWX".to_string(),
                enabled: self.check_config_flag("CONFIG_STRICT_KERNEL_RWX"),
                description: "Kernel bellek koruma (W^X)".to_string(),
                severity_if_disabled: Severity::High,
            },
            KernelSecurityFeature {
                name: "CONFIG_STACKPROTECTOR_STRONG".to_string(),
                enabled: self.check_config_flag("CONFIG_STACKPROTECTOR_STRONG"),
                description: "Stack smashing protection".to_string(),
                severity_if_disabled: Severity::Medium,
            },
            KernelSecurityFeature {
                name: "CONFIG_FORTIFY_SOURCE".to_string(),
                enabled: self.check_config_flag("CONFIG_FORTIFY_SOURCE"),
                description: "Buffer overflow detection".to_string(),
                severity_if_disabled: Severity::Medium,
            },
            KernelSecurityFeature {
                name: "CONFIG_SLAB_FREELIST_RANDOM".to_string(),
                enabled: self.check_config_flag("CONFIG_SLAB_FREELIST_RANDOM"),
                description: "SLAB freelist randomization".to_string(),
                severity_if_disabled: Severity::Low,
            },
        ]
    }
    
    /// Check if a kernel config flag is enabled
    fn check_config_flag(&self, flag: &str) -> bool {
        // Try to read from various kernel config locations
        let config_paths = [
            "/proc/config.gz",
            "/boot/config",
            "/boot/config-current",
        ];
        
        for path in &config_paths {
            if let Ok(content) = fs::read_to_string(path) {
                if content.contains(&format!("{}=y", flag)) {
                    return true;
                }
            }
        }
        
        // Default to false if we can't determine
        false
    }
}
