use std::fs;
use std::path::Path;
use serde_json;
use crate::report::{Reporter, ReportError, SecurityReport};

/// Structure that generates reports in JSON format
pub struct JsonReporter {
    pretty_print: bool,
}

impl JsonReporter {
    /// Create new JSON reporter
    pub fn new(pretty_print: bool) -> Self {
        Self { pretty_print }
    }

    /// Default JSON reporter (with pretty print)
    pub fn default() -> Self {
        Self::new(true)
    }

    /// Write JSON to file
    fn write_json_file(&self, report: &SecurityReport, output_path: &str) -> Result<String, ReportError> {
        // Create output directory
        if let Some(parent) = Path::new(output_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ReportError::IoError(format!("Failed to create output directory: {}", e)))?;
        }

        // Convert to JSON
        let json_data = if self.pretty_print {
            serde_json::to_string_pretty(report)
                .map_err(|e| ReportError::SerializationError(e.to_string()))?
        } else {
            serde_json::to_string(report)
                .map_err(|e| ReportError::SerializationError(e.to_string()))?
        };

        // Write to file
        fs::write(output_path, json_data)
            .map_err(|e| ReportError::IoError(format!("Failed to write JSON file: {}", e)))?;

        Ok(output_path.to_string())
    }

    /// Get compact JSON output (without writing to file)
    pub fn to_json_string(&self, report: &SecurityReport) -> Result<String, ReportError> {
        if self.pretty_print {
            serde_json::to_string_pretty(report)
                .map_err(|e| ReportError::SerializationError(e.to_string()))
        } else {
            serde_json::to_string(report)
                .map_err(|e| ReportError::SerializationError(e.to_string()))
        }
    }

    /// Get specific section as JSON (for debugging)
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
        // Check file extension and add if necessary
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

/// Quick JSON report generation function
pub fn generate_json_report(
    report: &SecurityReport, 
    output_path: &str, 
    pretty_print: bool
) -> Result<String, ReportError> {
    let reporter = JsonReporter::new(pretty_print);
    reporter.generate_report(report, output_path)
}

/// Function that outputs JSON to console
pub fn print_json_summary(report: &SecurityReport) -> Result<(), ReportError> {
    let reporter = JsonReporter::new(true);
    
    // Print only summary information
    println!("REPORT SUMMARY (JSON)");
    println!("================================");
    
    let summary_json = reporter.export_section(&report.summary, "summary")?;
    println!("{}", summary_json);
    
    println!("STATISTICS (JSON)");
    println!("================================");
    
    let stats_json = reporter.export_section(&report.statistics, "statistics")?;
    println!("{}", stats_json);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{ScanResult, ScanStatus, Finding, Severity, Category, ScanMetadata};

    fn create_test_report() -> SecurityReport {
        let scan_result = ScanResult {
            scanner_name: "test_scanner".to_string(),
            scan_time: "2024-01-01T00:00:00Z".to_string(),
            status: ScanStatus::Success,
            findings: vec![
                Finding {
                    id: "TEST-001".to_string(),
                    title: "Test vulnerability".to_string(),
                    description: "Test description".to_string(),
                    severity: Severity::High,
                    category: Category::Package,
                    affected_item: "test-package".to_string(),
                    current_value: Some("1.0.0".to_string()),
                    recommended_value: Some("1.1.0".to_string()),
                    references: vec!["https://example.com".to_string()],
                    cve_ids: vec!["CVE-2023-12345".to_string()],
                    fix_available: true,
                }
            ],
            metadata: ScanMetadata {
                duration_ms: 5000,
                items_scanned: 100,
                issues_found: 1,
                scan_timestamp: "2024-01-01T00:00:00Z".to_string(),
                scanner_version: "1.0.0".to_string(),
            },
            raw_data: None,
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