use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::scanners::{ScanResult, Finding, Severity, Category};
use crate::fixers::FixResult;

pub mod json_reporter;
pub mod html_reporter;
// pub mod pdf_reporter; // TODO: PDF support will be added later
pub mod manager;

/// Report formatları
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportFormat {
    Json,
    Html,
    Pdf,
    Csv,
}

impl std::str::FromStr for ReportFormat {
    type Err = ReportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(ReportFormat::Json),
            "html" => Ok(ReportFormat::Html),
            "pdf" => Ok(ReportFormat::Pdf),
            "csv" => Ok(ReportFormat::Csv),
            _ => Err(ReportError::UnsupportedFormat(s.to_string())),
        }
    }
}

/// Report hataları
#[derive(Debug, Serialize, Deserialize, Clone, Error)]
pub enum ReportError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Template error: {0}")]
    TemplateError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("Rendering error: {0}")]
    RenderingError(String),
}

/// Ana rapor veri yapısı
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityReport {
    pub metadata: ReportMetadata,
    pub summary: ReportSummary,
    pub scan_results: Vec<ScanResult>,
    pub fix_results: Option<Vec<FixResult>>,
    pub statistics: ReportStatistics,
    pub recommendations: Vec<String>,
}

/// Rapor metadata'sı
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportMetadata {
    pub report_id: String,
    pub generated_at: u64, // Unix timestamp
    pub pinGuard_version: String,
    pub system_info: SystemInfo,
    pub scan_duration_ms: u64,
    pub report_format: String,
}

/// Sistem bilgileri
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub uptime_seconds: Option<u64>,
}

/// Rapor özeti
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportSummary {
    pub total_scans: u32,
    pub successful_scans: u32,
    pub failed_scans: u32,
    pub total_findings: u32,
    pub critical_findings: u32,
    pub high_findings: u32,
    pub medium_findings: u32,
    pub low_findings: u32,
    pub security_score: u32, // 0-100
    pub risk_level: String,
}

/// Rapor istatistikleri
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportStatistics {
    pub findings_by_category: std::collections::HashMap<String, u32>,
    pub findings_by_severity: std::collections::HashMap<String, u32>,
    pub scan_performance: ScanPerformance,
    pub top_vulnerabilities: Vec<TopVulnerability>,
}

/// Tarama performansı
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanPerformance {
    pub items_per_second: f64,
    pub fastest_scanner: String,
    pub slowest_scanner: String,
    pub total_items_scanned: u32,
}

/// En önemli zafiyetler
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TopVulnerability {
    pub title: String,
    pub severity: String,
    pub category: String,
    pub count: u32,
    pub cve_ids: Vec<String>,
}

/// Reporter trait - her rapor formatı bu trait'i implement eder
pub trait Reporter {
    fn generate_report(&self, report: &SecurityReport, output_path: &str) -> Result<String, ReportError>;
    fn format_name(&self) -> &'static str;
    fn file_extension(&self) -> &'static str;
}

impl SecurityReport {
    /// Yeni rapor oluştur
    pub fn new(
        scan_results: Vec<ScanResult>, 
        fix_results: Option<Vec<FixResult>>,
        scan_duration_ms: u64
    ) -> Self {
        let total_findings: u32 = scan_results.iter()
            .map(|result| result.findings.len() as u32)
            .sum();

        let summary = Self::generate_summary(&scan_results);
        let statistics = Self::generate_statistics(&scan_results);
        let recommendations = Self::generate_recommendations(&scan_results);

        SecurityReport {
            metadata: ReportMetadata {
                report_id: Self::generate_report_id(),
                generated_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs(),
                pinGuard_version: env!("CARGO_PKG_VERSION").to_string(),
                system_info: Self::get_system_info(),
                scan_duration_ms,
                report_format: "multi".to_string(),
            },
            summary,
            scan_results,
            fix_results,
            statistics,
            recommendations,
        }
    }

    /// Rapor özeti oluştur
    fn generate_summary(scan_results: &[ScanResult]) -> ReportSummary {
        let total_scans = scan_results.len() as u32;
        let successful_scans = scan_results.iter()
            .filter(|r| r.status == crate::scanners::ScanStatus::Success)
            .count() as u32;
        let failed_scans = total_scans - successful_scans;

        let all_findings: Vec<&Finding> = scan_results.iter()
            .flat_map(|r| &r.findings)
            .collect();

        let total_findings = all_findings.len() as u32;
        let critical_findings = all_findings.iter()
            .filter(|f| f.severity == Severity::Critical)
            .count() as u32;
        let high_findings = all_findings.iter()
            .filter(|f| f.severity == Severity::High)
            .count() as u32;
        let medium_findings = all_findings.iter()
            .filter(|f| f.severity == Severity::Medium)
            .count() as u32;
        let low_findings = all_findings.iter()
            .filter(|f| f.severity == Severity::Low)
            .count() as u32;

        let security_score = Self::calculate_security_score(&all_findings);
        let risk_level = Self::calculate_risk_level(security_score);

        ReportSummary {
            total_scans,
            successful_scans,
            failed_scans,
            total_findings,
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            security_score,
            risk_level,
        }
    }

    /// İstatistikleri oluştur
    fn generate_statistics(scan_results: &[ScanResult]) -> ReportStatistics {
        let all_findings: Vec<&Finding> = scan_results.iter()
            .flat_map(|r| &r.findings)
            .collect();

        let mut findings_by_category = std::collections::HashMap::new();
        let mut findings_by_severity = std::collections::HashMap::new();

        for finding in &all_findings {
            let category = format!("{:?}", finding.category);
            *findings_by_category.entry(category).or_insert(0) += 1;

            let severity = format!("{:?}", finding.severity);
            *findings_by_severity.entry(severity).or_insert(0) += 1;
        }

        let scan_performance = Self::calculate_scan_performance(scan_results);
        let top_vulnerabilities = Self::get_top_vulnerabilities(&all_findings);

        ReportStatistics {
            findings_by_category,
            findings_by_severity,
            scan_performance,
            top_vulnerabilities,
        }
    }

    /// Güvenlik puanını hesapla (0-100)
    fn calculate_security_score(findings: &[&Finding]) -> u32 {
        if findings.is_empty() {
            return 100;
        }

        let total_findings = findings.len() as f64;
        let critical_weight = 20.0;
        let high_weight = 10.0;
        let medium_weight = 5.0;
        let low_weight = 1.0;

        let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count() as f64;
        let high_count = findings.iter().filter(|f| f.severity == Severity::High).count() as f64;
        let medium_count = findings.iter().filter(|f| f.severity == Severity::Medium).count() as f64;
        let low_count = findings.iter().filter(|f| f.severity == Severity::Low).count() as f64;

        let weighted_score = (critical_count * critical_weight) + 
                           (high_count * high_weight) + 
                           (medium_count * medium_weight) + 
                           (low_count * low_weight);

        let max_possible_score = total_findings * critical_weight;
        let score_percentage = 100.0 - ((weighted_score / max_possible_score) * 100.0);

        score_percentage.max(0.0).min(100.0) as u32
    }

    /// Risk seviyesini hesapla
    fn calculate_risk_level(security_score: u32) -> String {
        match security_score {
            90..=100 => "LOW",
            70..=89 => "MEDIUM", 
            50..=69 => "HIGH",
            _ => "CRITICAL",
        }.to_string()
    }

    /// Tarama performansını hesapla
    fn calculate_scan_performance(scan_results: &[ScanResult]) -> ScanPerformance {
        let total_items: u32 = scan_results.iter().map(|r| r.metadata.items_scanned).sum();
        let total_duration_ms: u64 = scan_results.iter().map(|r| r.metadata.duration_ms).sum();
        let total_duration_s = total_duration_ms as f64 / 1000.0;

        let items_per_second = if total_duration_s > 0.0 {
            total_items as f64 / total_duration_s
        } else {
            0.0
        };

        let fastest_scanner = scan_results.iter()
            .min_by_key(|r| r.metadata.duration_ms)
            .map(|r| r.scanner_name.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        let slowest_scanner = scan_results.iter()
            .max_by_key(|r| r.metadata.duration_ms)
            .map(|r| r.scanner_name.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        ScanPerformance {
            items_per_second,
            fastest_scanner,
            slowest_scanner,
            total_items_scanned: total_items,
        }
    }

    /// En önemli zafiyetleri al
    fn get_top_vulnerabilities(findings: &[&Finding]) -> Vec<TopVulnerability> {
        let mut vulnerability_map: std::collections::HashMap<String, TopVulnerability> = std::collections::HashMap::new();

        for finding in findings {
            let key = format!("{}-{:?}", finding.title, finding.severity);
            
            vulnerability_map.entry(key)
                .and_modify(|v| v.count += 1)
                .or_insert(TopVulnerability {
                    title: finding.title.clone(),
                    severity: format!("{:?}", finding.severity),
                    category: format!("{:?}", finding.category),
                    count: 1,
                    cve_ids: finding.cve_ids.clone(),
                });
        }

        let mut vulnerabilities: Vec<TopVulnerability> = vulnerability_map.into_values().collect();
        vulnerabilities.sort_by(|a, b| {
            // Önce severity'ye göre sırala, sonra count'a göre
            let severity_order = |s: &str| match s {
                "Critical" => 4,
                "High" => 3,
                "Medium" => 2,
                "Low" => 1,
                _ => 0,
            };
            
            let a_severity = severity_order(&a.severity);
            let b_severity = severity_order(&b.severity);
            
            b_severity.cmp(&a_severity).then(b.count.cmp(&a.count))
        });

        vulnerabilities.into_iter().take(10).collect()
    }

    /// Öneriler oluştur
    fn generate_recommendations(scan_results: &[ScanResult]) -> Vec<String> {
        let mut recommendations = Vec::new();

        let all_findings: Vec<&Finding> = scan_results.iter()
            .flat_map(|r| &r.findings)
            .collect();

        let critical_count = all_findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high_count = all_findings.iter().filter(|f| f.severity == Severity::High).count();

        if critical_count > 0 {
            recommendations.push(format!("🚨 ACIL: {} kritik güvenlik açığı bulundu. Derhal düzeltilmesi gerekir.", critical_count));
        }

        if high_count > 10 {
            recommendations.push("🔥 Çok sayıda yüksek riskli güvenlik açığı tespit edildi. Sistem güvenliği tehlikede.".to_string());
        }

        // Kategori bazlı öneriler
        let categories: std::collections::HashSet<&Category> = all_findings.iter().map(|f| &f.category).collect();
        
        for category in categories {
            match category {
                Category::Package => recommendations.push("📦 Paket güvenlik açıkları için düzenli güncelleme yapın.".to_string()),
                Category::Kernel => recommendations.push("🔧 Kernel güncellemelerini takip edin ve güvenlik yamalarını uygulayın.".to_string()),
                Category::Permission => recommendations.push("🔒 Dosya izinlerini gözden geçirin ve en az yetki prensibini uygulayın.".to_string()),
                Category::Service => recommendations.push("🛡️ Gereksiz servisleri devre dışı bırakın ve mevcut servisleri sertleştirin.".to_string()),
                Category::User => recommendations.push("👥 Kullanıcı hesap politikalarını güçlendirin ve parola kurallarını uygulayın.".to_string()),
                Category::Network => recommendations.push("🌐 Firewall kurallarını yapılandırın ve network trafiğini izleyin.".to_string()),
                _ => {}
            }
        }

        if recommendations.is_empty() {
            recommendations.push("✅ Sistem güvenliği iyi durumda. Düzenli tarama yapmaya devam edin.".to_string());
        }

        recommendations
    }

    /// Sistem bilgilerini al
    fn get_system_info() -> SystemInfo {
        let hostname = std::process::Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string());

        let os_info = std::process::Command::new("lsb_release")
            .args(&["-d", "-s"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown Linux".to_string());

        let kernel_version = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string());

        let architecture = std::process::Command::new("uname")
            .arg("-m")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string());

        SystemInfo {
            hostname,
            os_name: "Linux".to_string(),
            os_version: os_info,
            kernel_version,
            architecture,
            uptime_seconds: None, // TODO: Implement uptime calculation
        }
    }

    /// Benzersiz rapor ID'si oluştur
    fn generate_report_id() -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        let mut hasher = DefaultHasher::new();
        now.hash(&mut hasher);
        
        format!("pinGuard-{:x}", hasher.finish())
    }
}