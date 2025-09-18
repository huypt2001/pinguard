use std::fs;
use std::path::Path;
use serde_json;
use crate::report::{Reporter, ReportError, SecurityReport};

/// JSON formatında rapor üreten yapı
pub struct JsonReporter {
    pretty_print: bool,
}

impl JsonReporter {
    /// Yeni JSON reporter oluştur
    pub fn new(pretty_print: bool) -> Self {
        Self { pretty_print }
    }

    /// Varsayılan JSON reporter (pretty print ile)
    pub fn default() -> Self {
        Self::new(true)
    }

    /// JSON'u dosyaya yaz
    fn write_json_file(&self, report: &SecurityReport, output_path: &str) -> Result<String, ReportError> {
        // Çıkış dizinini oluştur
        if let Some(parent) = Path::new(output_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ReportError::IoError(format!("Failed to create output directory: {}", e)))?;
        }

        // JSON'a çevir
        let json_data = if self.pretty_print {
            serde_json::to_string_pretty(report)
                .map_err(|e| ReportError::SerializationError(e.to_string()))?
        } else {
            serde_json::to_string(report)
                .map_err(|e| ReportError::SerializationError(e.to_string()))?
        };

        // Dosyaya yaz
        fs::write(output_path, json_data)
            .map_err(|e| ReportError::IoError(format!("Failed to write JSON file: {}", e)))?;

        Ok(output_path.to_string())
    }

    /// Kompakt JSON çıktısı al (dosya yazmadan)
    pub fn to_json_string(&self, report: &SecurityReport) -> Result<String, ReportError> {
        if self.pretty_print {
            serde_json::to_string_pretty(report)
                .map_err(|e| ReportError::SerializationError(e.to_string()))
        } else {
            serde_json::to_string(report)
                .map_err(|e| ReportError::SerializationError(e.to_string()))
        }
    }

    /// Belirli bir bölümü JSON olarak al (debug için)
    pub fn export_section<T: serde::Serialize>(&self, section: &T, section_name: &str) -> Result<String, ReportError> {
        let json_data = if self.pretty_print {
            serde_json::to_string_pretty(section)
                .map_err(|e| ReportError::SerializationError(format!("Failed to serialize {}: {}", section_name, e)))?
        } else {
            serde_json::to_string(section)
                .map_err(|e| ReportError::SerializationError(format!("Failed to serialize {}: {}", section_name, e)))?
        };

        Ok(json_data)
    }
}

impl Reporter for JsonReporter {
    fn generate_report(&self, report: &SecurityReport, output_path: &str) -> Result<String, ReportError> {
        // Dosya uzantısını kontrol et ve gerekirse ekle
        let final_path = if output_path.ends_with(".json") {
            output_path.to_string()
        } else {
            format!("{}.json", output_path)
        };

        self.write_json_file(report, &final_path)
    }

    fn format_name(&self) -> &'static str {
        "JSON"
    }

    fn file_extension(&self) -> &'static str {
        "json"
    }
}

/// Hızlı JSON rapor oluşturma fonksiyonu
pub fn generate_json_report(
    report: &SecurityReport, 
    output_path: &str, 
    pretty_print: bool
) -> Result<String, ReportError> {
    let reporter = JsonReporter::new(pretty_print);
    reporter.generate_report(report, output_path)
}

/// Konsola JSON çıktı veren fonksiyon
pub fn print_json_summary(report: &SecurityReport) -> Result<(), ReportError> {
    let reporter = JsonReporter::new(true);
    
    // Sadece özet bilgileri yazdır
    println!("\n📊 REPORT SUMMARY (JSON)");
    println!("================================");
    
    let summary_json = reporter.export_section(&report.summary, "summary")?;
    println!("{}", summary_json);
    
    println!("\n📈 STATISTICS (JSON)");
    println!("================================");
    
    let stats_json = reporter.export_section(&report.statistics, "statistics")?;
    println!("{}", stats_json);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{ScanResult, ScanStatus, Finding, Severity, Category};
    use std::collections::HashMap;

    fn create_test_report() -> SecurityReport {
        let scan_result = ScanResult {
            scanner_name: "test_scanner".to_string(),
            status: ScanStatus::Success,
            message: "Test scan completed".to_string(),
            findings: vec![
                Finding {
                    id: "TEST-001".to_string(),
                    title: "Test vulnerability".to_string(),
                    description: "Test description".to_string(),
                    severity: Severity::High,
                    category: Category::Package,
                    affected_item: "test-package".to_string(),
                    remediation: Some("Update package".to_string()),
                    cve_ids: vec!["CVE-2023-12345".to_string()],
                    references: vec!["https://example.com".to_string()],
                    metadata: HashMap::new(),
                }
            ],
            items_scanned: 100,
            duration_ms: 5000,
            scanner_version: "1.0.0".to_string(),
        };

        SecurityReport::new(vec![scan_result], None, 5000)
    }

    #[test]
    fn test_json_reporter_creation() {
        let reporter = JsonReporter::new(true);
        assert_eq!(reporter.format_name(), "JSON");
        assert_eq!(reporter.file_extension(), "json");
    }

    #[test]
    fn test_json_serialization() {
        let reporter = JsonReporter::new(true);
        let report = create_test_report();
        
        let json_result = reporter.to_json_string(&report);
        assert!(json_result.is_ok());
        
        let json_string = json_result.unwrap();
        assert!(json_string.contains("metadata"));
        assert!(json_string.contains("summary"));
        assert!(json_string.contains("TEST-001"));
    }

    #[test]
    fn test_section_export() {
        let reporter = JsonReporter::new(true);
        let report = create_test_report();
        
        let summary_json = reporter.export_section(&report.summary, "summary");
        assert!(summary_json.is_ok());
        
        let summary_string = summary_json.unwrap();
        assert!(summary_string.contains("total_findings"));
        assert!(summary_string.contains("security_score"));
    }
}