use std::path::Path;
use crate::report::{
    Reporter, ReportError, SecurityReport, ReportFormat,
    json_reporter::JsonReporter,
    html_reporter::HtmlReporter,
    // pdf_reporter::PdfReporter, // TODO: Add back when PDF is fixed
};

/// Report manager structure - coordinates all report formats
pub struct ReportManager {
    output_directory: String,
    default_format: ReportFormat,
}

impl ReportManager {
    /// Create new report manager
    pub fn new(output_directory: Option<String>, default_format: Option<ReportFormat>) -> Self {
        Self {
            output_directory: output_directory.unwrap_or_else(|| "reports".to_string()),
            default_format: default_format.unwrap_or(ReportFormat::Json),
        }
    }

    /// Default report manager
    pub fn default() -> Self {
        Self::new(None, None)
    }

    /// Generate report in specified format
    pub fn generate_report(
        &self,
        report: &SecurityReport,
        format: &ReportFormat,
        output_filename: Option<String>,
    ) -> Result<String, ReportError> {
        let reporter: Box<dyn Reporter> = match format {
            ReportFormat::Json => Box::new(JsonReporter::default()),
            ReportFormat::Html => Box::new(HtmlReporter::default()),
            ReportFormat::Pdf => return Err(ReportError::UnsupportedFormat("PDF format not yet implemented".to_string())),
            ReportFormat::Csv => return Err(ReportError::UnsupportedFormat("CSV format not yet implemented".to_string())),
        };

        let filename = output_filename.unwrap_or_else(|| {
            self.generate_default_filename(&report.metadata.report_id, format)
        });

        let output_path = Path::new(&self.output_directory).join(&filename);
        let output_path_str = output_path.to_string_lossy().to_string();

        reporter.generate_report(report, &output_path_str)
    }

    /// Generate report in multiple formats
    pub fn generate_multi_format_report(
        &self,
        report: &SecurityReport,
        formats: Vec<ReportFormat>,
        base_filename: Option<String>,
    ) -> Result<Vec<String>, ReportError> {
        let mut generated_files = Vec::new();

        let base_name = base_filename.unwrap_or_else(|| {
            format!("pinGuard-report-{}", report.metadata.report_id)
        });

        for format in formats {
            let filename = format!("{}.{}", base_name, self.get_file_extension(&format));
            match self.generate_report(report, &format, Some(filename)) {
                Ok(path) => generated_files.push(path),
                Err(e) => {
                    tracing::warn!("Failed to generate {:?} report: {}", format, e);
                    // Continue with other formats
                }
            }
        }

        if generated_files.is_empty() {
            Err(ReportError::RenderingError("Failed to generate any reports".to_string()))
        } else {
            Ok(generated_files)
        }
    }

    /// Quick report generation - with default settings
    pub fn quick_report(
        &self,
        report: &SecurityReport,
        format: Option<ReportFormat>,
    ) -> Result<String, ReportError> {
        let report_format = format.unwrap_or_else(|| self.default_format.clone());
        self.generate_report(report, &report_format, None)
    }

    /// Generate report in all supported formats
    pub fn generate_all_formats(
        &self,
        report: &SecurityReport,
        base_filename: Option<String>,
    ) -> Result<Vec<String>, ReportError> {
        let formats = vec![
            ReportFormat::Json,
            ReportFormat::Html,
            // ReportFormat::Pdf, // TODO: Add back when PDF is fixed
        ];

        self.generate_multi_format_report(report, formats, base_filename)
    }

    /// Print report summary to console
    pub fn print_report_summary(&self, report: &SecurityReport) -> Result<(), ReportError> {
        println!("PINGUARD SECURITY REPORT SUMMARY");
        println!("=====================================");
        
        println!("Report ID: {}", report.metadata.report_id);
        println!("Generated: {}", self.format_timestamp(report.metadata.generated_at));
        println!("System: {} ({})", 
            report.metadata.system_info.hostname,
            report.metadata.system_info.os_version
        );
        
        println!("SECURITY DASHBOARD");
        println!("---------------------");
        println!("Security Score: {}/100 ({})", 
            report.summary.security_score,
            report.summary.risk_level
        );
        
        println!("FINDINGS BREAKDOWN");
        println!("---------------------");
        println!("Critical: {}", report.summary.critical_findings);
        println!("High:     {}", report.summary.high_findings);
        println!("Medium:   {}", report.summary.medium_findings);
        println!("Low:      {}", report.summary.low_findings);
        println!("Total:    {}", report.summary.total_findings);

        println!("SCAN PERFORMANCE");
        println!("-------------------");
        println!("Duration: {} ms", report.metadata.scan_duration_ms);
        println!("Items/sec: {:.1}", report.statistics.scan_performance.items_per_second);
        println!("Scanners: {}/{} successful", 
            report.summary.successful_scans,
            report.summary.total_scans
        );

        if !report.recommendations.is_empty() {
            println!("TOP RECOMMENDATIONS");
            println!("----------------------");
            for (i, recommendation) in report.recommendations.iter().take(3).enumerate() {
                println!("{}. {}", i + 1, recommendation);
            }
        }

        Ok(())
    }

    /// Print detailed report statistics
    pub fn print_detailed_statistics(&self, report: &SecurityReport) -> Result<(), ReportError> {
        println!("DETAILED STATISTICS");
        println!("======================");

        println!("Findings by Category:");
        for (category, count) in &report.statistics.findings_by_category {
            println!("  • {}: {}", category, count);
        }

        println!("\n⚡ Findings by Severity:");
        for (severity, count) in &report.statistics.findings_by_severity {
            println!("  • {}: {}", severity, count);
        }

        println!("Top Vulnerabilities:");
        for (i, vuln) in report.statistics.top_vulnerabilities.iter().take(5).enumerate() {
            println!("  {}. {} ({} - Count: {})", 
                i + 1, vuln.title, vuln.severity, vuln.count);
        }

        println!("Scanner Performance:");
        println!("  • Fastest: {}", report.statistics.scan_performance.fastest_scanner);
        println!("  • Slowest: {}", report.statistics.scan_performance.slowest_scanner);
        println!("  • Total Items: {}", report.statistics.scan_performance.total_items_scanned);

        Ok(())
    }

    /// Set output directory
    pub fn set_output_directory(&mut self, directory: String) -> Result<(), ReportError> {
        std::fs::create_dir_all(&directory)
            .map_err(|e| ReportError::IoError(format!("Failed to create output directory: {}", e)))?;
        
        self.output_directory = directory;
        Ok(())
    }

    /// Get output directory
    pub fn get_output_directory(&self) -> &str {
        &self.output_directory
    }

    /// Set default format
    pub fn set_default_format(&mut self, format: ReportFormat) {
        self.default_format = format;
    }

    /// Get default format
    pub fn get_default_format(&self) -> &ReportFormat {
        &self.default_format
    }

    /// List supported formats
    pub fn list_supported_formats(&self) -> Vec<ReportFormat> {
        vec![
            ReportFormat::Json,
            ReportFormat::Html,
            // ReportFormat::Pdf, // TODO: Add back when PDF is fixed
        ]
    }

    /// Print format information
    pub fn print_format_info(&self) {
        println!("SUPPORTED REPORT FORMATS");
        println!("============================");
        
        let formats = [
            (ReportFormat::Json, "JSON", "Machine-readable data format, perfect for integration"),
            (ReportFormat::Html, "HTML", "Interactive web report with charts and filtering"),
            // (ReportFormat::Pdf, "PDF", "Professional printable report for documentation"), // TODO: Add back
        ];

        for (format, name, description) in formats.iter() {
            let marker = if format == &self.default_format { "👉" } else { "  " };
            println!("{} {}: {}", marker, name, description);
        }
        
        println!("\nDefault format: {:?}", self.default_format);
        println!("Output directory: {}", self.output_directory);
    }

    /// Generate default filename
    fn generate_default_filename(&self, report_id: &str, format: &ReportFormat) -> String {
        format!("{}.{}", report_id, self.get_file_extension(format))
    }

    /// Get file extension
    fn get_file_extension(&self, format: &ReportFormat) -> &'static str {
        match format {
            ReportFormat::Json => "json",
            ReportFormat::Html => "html",
            ReportFormat::Pdf => "pdf",
            ReportFormat::Csv => "csv",
        }
    }

    /// Format timestamp
    fn format_timestamp(&self, timestamp: u64) -> String {
        use std::time::{SystemTime, Duration};
        
        let datetime = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
        format!("{:?}", datetime)
            .replace("SystemTime", "")
            .trim()
            .to_string()
    }
}

/// Quick report generation functions
pub mod quick {
    use super::*;

    /// Generate JSON report
    pub fn json_report(report: &SecurityReport, output_path: &str) -> Result<String, ReportError> {
        let reporter = JsonReporter::default();
        reporter.generate_report(report, output_path)
    }

    /// Generate HTML report
    pub fn html_report(report: &SecurityReport, output_path: &str) -> Result<String, ReportError> {
        let reporter = HtmlReporter::default();
        reporter.generate_report(report, output_path)
    }

    /// Generate PDF report (currently disabled)
    pub fn pdf_report(_report: &SecurityReport, _output_path: &str) -> Result<String, ReportError> {
        Err(ReportError::IoError("PDF reporting is temporarily disabled".to_string()))
    }

    /// Print summary to console
    pub fn print_summary(report: &SecurityReport) -> Result<(), ReportError> {
        let manager = ReportManager::default();
        manager.print_report_summary(report)
    }

    /// Print detailed statistics to console
    pub fn print_statistics(report: &SecurityReport) -> Result<(), ReportError> {
        let manager = ReportManager::default();
        manager.print_detailed_statistics(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{ScanResult, ScanStatus, Finding, Severity, Category, ScanMetadata};
    use std::collections::HashMap;
    use std::fs;

    fn create_test_report() -> SecurityReport {
        let scan_metadata = crate::scanners::ScanMetadata {
            duration_ms: 5000,
            items_scanned: 100,
            issues_found: 1,
            scan_timestamp: "2023-01-01T00:00:00Z".to_string(),
            scanner_version: "1.0.0".to_string(),
        };

        let scan_result = ScanResult {
            scanner_name: "test_scanner".to_string(),
            scan_time: "2023-01-01T00:00:00Z".to_string(),
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
                    cve_ids: vec!["CVE-2023-12345".to_string()],
                    references: vec!["https://example.com".to_string()],
                    fix_available: true,
                }
            ],
            metadata: scan_metadata,
            raw_data: Some(HashMap::new()),
        };

        SecurityReport::new(vec![scan_result], None, 5000)
    }

    #[test]
    fn test_report_manager_creation() {
        let manager = ReportManager::new(Some("test_reports".to_string()), Some(ReportFormat::Html));
        assert_eq!(manager.get_output_directory(), "test_reports");
        assert_eq!(manager.get_default_format(), &ReportFormat::Html);
    }

    #[test]
    fn test_quick_report_generation() {
        let manager = ReportManager::default();
        let report = create_test_report();
        
        // Create test directory
        let test_dir = "test_output";
        std::fs::create_dir_all(test_dir).unwrap();
        
        let mut test_manager = manager;
        test_manager.set_output_directory(test_dir.to_string()).unwrap();
        
        let result = test_manager.quick_report(&report, Some(ReportFormat::Json));
        assert!(result.is_ok());
        
        // Cleanup
        let _ = fs::remove_dir_all(test_dir);
    }

    #[test]
    fn test_multi_format_generation() {
        let manager = ReportManager::default();
        let report = create_test_report();
        
        let test_dir = "test_multi_output";
        std::fs::create_dir_all(test_dir).unwrap();
        
        let mut test_manager = manager;
        test_manager.set_output_directory(test_dir.to_string()).unwrap();
        
        let formats = vec![ReportFormat::Json, ReportFormat::Html];
        let result = test_manager.generate_multi_format_report(&report, formats, Some("test-report".to_string()));
        
        assert!(result.is_ok());
        let files = result.unwrap();
        assert_eq!(files.len(), 2);
        
        // Cleanup
        let _ = fs::remove_dir_all(test_dir);
    }

    #[test]
    fn test_supported_formats() {
        let manager = ReportManager::default();
        let formats = manager.list_supported_formats();
        
        assert!(formats.contains(&ReportFormat::Json));
        assert!(formats.contains(&ReportFormat::Html));
        // PDF support is currently disabled
        // assert!(formats.contains(&ReportFormat::Pdf));
    }
}