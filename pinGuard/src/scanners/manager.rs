use super::{Scanner, ScanResult, ScanError};
use crate::core::config::Config;
use crate::scanners::{
    package_audit::PackageAudit,
    kernel_check::KernelCheck,
    permission_audit::PermissionAudit,
    service_audit::ServiceAudit,
    user_audit::UserAudit,
    network_audit::NetworkAudit,
};

pub struct ScannerManager {
    scanners: Vec<Box<dyn Scanner>>,
}

impl ScannerManager {
    pub fn new() -> Self {
        let mut scanners: Vec<Box<dyn Scanner>> = Vec::new();
        
        // Mevcut scanner'ları ekle
        scanners.push(Box::new(PackageAudit::new()));
        scanners.push(Box::new(KernelCheck));
        scanners.push(Box::new(PermissionAudit));
        scanners.push(Box::new(ServiceAudit));
        scanners.push(Box::new(UserAudit));
        scanners.push(Box::new(NetworkAudit));
        
        Self { scanners }
    }

    /// Tüm etkin scanner'ları çalıştır
    pub fn run_all_scans(&self, config: &Config) -> Vec<ScanResult> {
        let mut results = Vec::new();
        
        tracing::info!("Tüm taramalar başlatılıyor...");
        
        for scanner in &self.scanners {
            if scanner.is_enabled(config) {
                tracing::info!("{} taraması başlatılıyor...", scanner.name());
                
                match scanner.scan() {
                    Ok(result) => {
                        tracing::info!("{} tamamlandı: {} bulgu", 
                            scanner.name(), result.findings.len());
                        results.push(result);
                    }
                    Err(e) => {
                        tracing::error!("{} taraması başarısız: {}", scanner.name(), e);
                        // Hata durumunda bile boş bir result ekle
                        let mut error_result = ScanResult::new(scanner.name().to_string());
                        error_result.status = super::ScanStatus::Error(e.to_string());
                        results.push(error_result);
                    }
                }
            } else {
                tracing::info!("{} taraması devre dışı", scanner.name());
            }
        }
        
        tracing::info!("Tüm taramalar tamamlandı: {} scanner çalıştı", results.len());
        results
    }

    /// Belirli bir scanner'ı çalıştır
    pub fn run_specific_scan(&self, scanner_name: &str, config: &Config) -> Result<ScanResult, ScanError> {
        tracing::info!("Belirli tarama başlatılıyor: {}", scanner_name);
        
        for scanner in &self.scanners {
            if scanner.name().to_lowercase().contains(&scanner_name.to_lowercase()) {
                if scanner.is_enabled(config) {
                    return scanner.scan();
                } else {
                    return Err(ScanError::ConfigError(
                        format!("Scanner '{}' is disabled in configuration", scanner_name)
                    ));
                }
            }
        }
        
        Err(ScanError::ConfigError(
            format!("Scanner '{}' not found", scanner_name)
        ))
    }

    /// Mevcut scanner'ları listele
    pub fn list_scanners(&self) -> Vec<&str> {
        self.scanners.iter().map(|s| s.name()).collect()
    }

    /// Tarama sonuçlarını JSON formatında topla
    pub fn results_to_json(&self, results: &[ScanResult]) -> Result<String, ScanError> {
        serde_json::to_string_pretty(results)
            .map_err(|e| ScanError::ParseError(format!("JSON serialization failed: {}", e)))
    }

    /// Özet rapor oluştur
    pub fn generate_summary(&self, results: &[ScanResult]) -> ScanSummary {
        let mut summary = ScanSummary::new();
        
        for result in results {
            summary.total_scans += 1;
            summary.total_findings += result.findings.len();
            
            match &result.status {
                super::ScanStatus::Success => summary.successful_scans += 1,
                super::ScanStatus::Warning => summary.warning_scans += 1,
                super::ScanStatus::Error(_) => summary.failed_scans += 1,
                super::ScanStatus::Skipped(_) => summary.skipped_scans += 1,
            }
            
            // Severity bazında sayım
            for finding in &result.findings {
                match finding.severity {
                    super::Severity::Critical => summary.critical_issues += 1,
                    super::Severity::High => summary.high_issues += 1,
                    super::Severity::Medium => summary.medium_issues += 1,
                    super::Severity::Low => summary.low_issues += 1,
                    super::Severity::Info => summary.low_issues += 1,
                }
            }
        }
        
        summary
    }
}

#[derive(Debug, serde::Serialize)]
pub struct ScanSummary {
    pub total_scans: usize,
    pub successful_scans: usize,
    pub warning_scans: usize,
    pub failed_scans: usize,
    pub skipped_scans: usize,
    pub total_findings: usize,
    pub critical_issues: usize,
    pub high_issues: usize,
    pub medium_issues: usize,
    pub low_issues: usize,
    pub scan_timestamp: String,
}

impl ScanSummary {
    fn new() -> Self {
        Self {
            total_scans: 0,
            successful_scans: 0,
            warning_scans: 0,
            failed_scans: 0,
            skipped_scans: 0,
            total_findings: 0,
            critical_issues: 0,
            high_issues: 0,
            medium_issues: 0,
            low_issues: 0,
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Risk seviyesini hesapla
    pub fn get_risk_level(&self) -> &'static str {
        if self.critical_issues > 0 {
            "CRITICAL"
        } else if self.high_issues > 3 {
            "HIGH"
        } else if self.high_issues > 0 || self.medium_issues > 5 {
            "MEDIUM"
        } else if self.medium_issues > 0 || self.low_issues > 10 {
            "LOW"
        } else {
            "MINIMAL"
        }
    }

    /// Güvenlik puanı hesapla (0-100)
    pub fn get_security_score(&self) -> u8 {
        if self.total_findings == 0 {
            return 100;
        }
        
        let weighted_issues = (self.critical_issues * 10) + 
                             (self.high_issues * 5) + 
                             (self.medium_issues * 2) + 
                             self.low_issues;
                             
        let max_possible = self.total_findings * 10;
        let score = 100 - ((weighted_issues * 100) / max_possible.max(1));
        
        score.min(100) as u8
    }
}