use std::fs;
use std::path::Path;
use printpdf::*;
use crate::report::{Reporter, ReportError, SecurityReport};

/// PDF formatında rapor üreten yapı
pub struct PdfReporter {
    page_size: (f32, f32), // (width, height) in mm
    margin: f32,           // margin in mm
    font_size_title: f32,
    font_size_heading: f32,
    font_size_body: f32,
    font_size_small: f32,
}

impl PdfReporter {
    /// Yeni PDF reporter oluştur
    pub fn new() -> Self {
        Self {
            page_size: (210.0, 297.0), // A4
            margin: 20.0,
            font_size_title: 20.0,
            font_size_heading: 16.0,
            font_size_body: 11.0,
            font_size_small: 9.0,
        }
    }

    /// Varsayılan PDF reporter
    pub fn default() -> Self {
        Self::new()
    }

    /// A4 boyutunda PDF oluştur
    pub fn a4() -> Self {
        Self {
            page_size: (210.0, 297.0),
            margin: 20.0,
            font_size_title: 20.0,
            font_size_heading: 16.0,
            font_size_body: 11.0,
            font_size_small: 9.0,
        }
    }

    /// Letter boyutunda PDF oluştur
    pub fn letter() -> Self {
        Self {
            page_size: (215.9, 279.4), // Letter size
            margin: 20.0,
            font_size_title: 20.0,
            font_size_heading: 16.0,
            font_size_body: 11.0,
            font_size_small: 9.0,
        }
    }

    /// PDF render et
    fn render_pdf(&self, report: &SecurityReport) -> Result<Vec<u8>, ReportError> {
        // PDF dokümanı oluştur
        let (doc, page1, layer1) = PdfDocument::new(
            "pinGuard Security Report",
            Mm(self.page_size.0),
            Mm(self.page_size.1),
            "Layer 1"
        );

        let current_layer = doc.get_page(page1).get_layer(layer1);

        // Font yükle (built-in font kullan)
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

        let mut y_position = self.page_size.1 - self.margin;
        let x_margin = self.margin;
        let page_width = self.page_size.0 - (2.0 * self.margin);

        // PDF içeriğini oluştur
        self.add_header(&current_layer, &font_bold, &font, report, x_margin, &mut y_position, page_width)?;
        self.add_executive_summary(&current_layer, &font_bold, &font, report, x_margin, &mut y_position, page_width)?;
        self.add_security_dashboard(&current_layer, &font_bold, &font, report, x_margin, &mut y_position, page_width)?;
        self.add_findings_overview(&current_layer, &font_bold, &font, report, x_margin, &mut y_position, page_width)?;
        
        // Yeni sayfa gerekirse ekle
        if y_position < 50.0 {
            let (page2, layer2) = doc.add_page(Mm(self.page_size.0), Mm(self.page_size.1), "Layer 1");
            let current_layer = doc.get_page(page2).get_layer(layer2);
            y_position = self.page_size.1 - self.margin;
            
            self.add_detailed_findings(&current_layer, &font_bold, &font, report, x_margin, &mut y_position, page_width)?;
        } else {
            self.add_detailed_findings(&current_layer, &font_bold, &font, report, x_margin, &mut y_position, page_width)?;
        }
        
        self.add_statistics(&current_layer, &font_bold, &font, report, x_margin, &mut y_position, page_width)?;
        self.add_recommendations(&current_layer, &font_bold, &font, report, x_margin, &mut y_position, page_width)?;
        self.add_system_info(&current_layer, &font_bold, &font, report, x_margin, &mut y_position, page_width)?;

        // PDF'i byte array'e çevir
        let pdf_bytes = doc.save_to_bytes()
            .map_err(|e| ReportError::RenderingError(format!("Failed to generate PDF bytes: {:?}", e)))?;

        Ok(pdf_bytes)
    }

    /// PDF header ekle
    fn add_header(
        &self,
        layer: &PdfLayerReference,
        font_bold: &IndirectFontRef,
        font: &IndirectFontRef,
        report: &SecurityReport,
        x: f32,
        y: &mut f32,
        _page_width: f32,
    ) -> Result<(), ReportError> {
        // Ana başlık
        layer.use_text(format!("🛡️ pinGuard Security Report"), self.font_size_title, Mm(x), Mm(*y), font_bold);
        *y -= 10.0;

        // Alt başlık bilgileri
        layer.use_text(
            format!("Report ID: {}", report.metadata.report_id),
            self.font_size_body,
            Mm(x),
            Mm(*y),
            font
        );
        *y -= 6.0;

        layer.use_text(
            format!("Generated: {}", self.format_timestamp(report.metadata.generated_at)),
            self.font_size_body,
            Mm(x),
            Mm(*y),
            font
        );
        *y -= 6.0;

        layer.use_text(
            format!("System: {} ({})", 
                report.metadata.system_info.hostname,
                report.metadata.system_info.os_version
            ),
            self.font_size_body,
            Mm(x),
            Mm(*y),
            font
        );
        *y -= 15.0;

        Ok(())
    }

    /// Executive summary ekle
    fn add_executive_summary(
        &self,
        layer: &PdfLayerReference,
        font_bold: &IndirectFontRef,
        font: &IndirectFontRef,
        report: &SecurityReport,
        x: f32,
        y: &mut f32,
        _page_width: f32,
    ) -> Result<(), ReportError> {
        // Bölüm başlığı
        layer.use_text("📋 Executive Summary", self.font_size_heading, Mm(x), Mm(*y), font_bold);
        *y -= 12.0;

        // Güvenlik puanı
        layer.use_text(
            format!("Security Score: {}/100 ({})", 
                report.summary.security_score,
                report.summary.risk_level
            ),
            self.font_size_body,
            Mm(x + 5.0),
            Mm(*y),
            font_bold
        );
        *y -= 8.0;

        // Toplam bulgular
        layer.use_text(
            format!("Total Findings: {} ({} scans completed)", 
                report.summary.total_findings,
                report.summary.total_scans
            ),
            self.font_size_body,
            Mm(x + 5.0),
            Mm(*y),
            font
        );
        *y -= 8.0;

        // Scan süresi
        layer.use_text(
            format!("Scan Duration: {} ms ({:.1} items/sec)", 
                report.metadata.scan_duration_ms,
                report.statistics.scan_performance.items_per_second
            ),
            self.font_size_body,
            Mm(x + 5.0),
            Mm(*y),
            font
        );
        *y -= 15.0;

        Ok(())
    }

    /// Security dashboard ekle
    fn add_security_dashboard(
        &self,
        layer: &PdfLayerReference,
        font_bold: &IndirectFontRef,
        font: &IndirectFontRef,
        report: &SecurityReport,
        x: f32,
        y: &mut f32,
        _page_width: f32,
    ) -> Result<(), ReportError> {
        // Bölüm başlığı
        layer.use_text("🎯 Security Dashboard", self.font_size_heading, Mm(x), Mm(*y), font_bold);
        *y -= 12.0;

        // Severity dağılımı
        let severities = [
            ("🚨 Critical", report.summary.critical_findings),
            ("🔥 High", report.summary.high_findings),
            ("⚠️ Medium", report.summary.medium_findings),
            ("ℹ️ Low", report.summary.low_findings),
        ];

        for (severity_name, count) in severities.iter() {
            layer.use_text(
                format!("{}: {}", severity_name, count),
                self.font_size_body,
                Mm(x + 5.0),
                Mm(*y),
                if *count > 0 { font_bold } else { font }
            );
            *y -= 6.0;
        }

        *y -= 10.0;
        Ok(())
    }

    /// Findings overview ekle
    fn add_findings_overview(
        &self,
        layer: &PdfLayerReference,
        font_bold: &IndirectFontRef,
        font: &IndirectFontRef,
        report: &SecurityReport,
        x: f32,
        y: &mut f32,
        _page_width: f32,
    ) -> Result<(), ReportError> {
        // Bölüm başlığı
        layer.use_text("🔍 Scanner Results Overview", self.font_size_heading, Mm(x), Mm(*y), font_bold);
        *y -= 12.0;

        // Tablo başlıkları
        layer.use_text("Scanner", self.font_size_small, Mm(x + 5.0), Mm(*y), font_bold);
        layer.use_text("Status", self.font_size_small, Mm(x + 60.0), Mm(*y), font_bold);
        layer.use_text("Findings", self.font_size_small, Mm(x + 100.0), Mm(*y), font_bold);
        layer.use_text("Duration", self.font_size_small, Mm(x + 140.0), Mm(*y), font_bold);
        *y -= 8.0;

        // Çizgi çiz
        let line = Line {
            points: vec![
                (Point::new(Mm(x), Mm(*y)), false),
                (Point::new(Mm(x + 180.0), Mm(*y)), false),
            ],
            is_closed: false,
            has_fill: false,
            has_stroke: true,
            is_clipping_path: false,
        };
        layer.add_shape(line);
        *y -= 5.0;

        // Scanner sonuçları
        for scan_result in &report.scan_results {
            layer.use_text(&scan_result.scanner_name, self.font_size_small, Mm(x + 5.0), Mm(*y), font);
            layer.use_text(
                &format!("{:?}", scan_result.status),
                self.font_size_small,
                Mm(x + 60.0),
                Mm(*y),
                font
            );
            layer.use_text(
                &scan_result.findings.len().to_string(),
                self.font_size_small,
                Mm(x + 100.0),
                Mm(*y),
                font
            );
            layer.use_text(
                &format!("{} ms", scan_result.duration_ms),
                self.font_size_small,
                Mm(x + 140.0),
                Mm(*y),
                font
            );
            *y -= 6.0;
        }

        *y -= 10.0;
        Ok(())
    }

    /// Detaylı findings ekle
    fn add_detailed_findings(
        &self,
        layer: &PdfLayerReference,
        font_bold: &IndirectFontRef,
        font: &IndirectFontRef,
        report: &SecurityReport,
        x: f32,
        y: &mut f32,
        page_width: f32,
    ) -> Result<(), ReportError> {
        // Bölüm başlığı
        layer.use_text("🔎 Critical & High Severity Findings", self.font_size_heading, Mm(x), Mm(*y), font_bold);
        *y -= 12.0;

        let mut finding_count = 0;
        for scan_result in &report.scan_results {
            for finding in &scan_result.findings {
                // Sadece Critical ve High severity göster (PDF boyut limiti için)
                if !matches!(finding.severity, crate::scanners::Severity::Critical | crate::scanners::Severity::High) {
                    continue;
                }

                if finding_count >= 10 {
                    layer.use_text("... (additional findings truncated for brevity)", self.font_size_small, Mm(x), Mm(*y), font);
                    *y -= 8.0;
                    break;
                }

                // Finding ID ve severity
                let severity_icon = match finding.severity {
                    crate::scanners::Severity::Critical => "🚨",
                    crate::scanners::Severity::High => "🔥",
                    crate::scanners::Severity::Medium => "⚠️",
                    crate::scanners::Severity::Low => "ℹ️",
                };

                layer.use_text(
                    format!("{} {} [{}]", severity_icon, finding.title, finding.id),
                    self.font_size_body,
                    Mm(x + 5.0),
                    Mm(*y),
                    font_bold
                );
                *y -= 8.0;

                // Description (kısaltılmış)
                let description = if finding.description.len() > 80 {
                    format!("{}...", &finding.description[..80])
                } else {
                    finding.description.clone()
                };

                layer.use_text(description, self.font_size_small, Mm(x + 10.0), Mm(*y), font);
                *y -= 6.0;

                // Affected item
                layer.use_text(
                    format!("Affected: {}", finding.affected_item),
                    self.font_size_small,
                    Mm(x + 10.0),
                    Mm(*y),
                    font
                );
                *y -= 6.0;

                // CVE IDs (varsa)
                if !finding.cve_ids.is_empty() {
                    layer.use_text(
                        format!("CVE: {}", finding.cve_ids.join(", ")),
                        self.font_size_small,
                        Mm(x + 10.0),
                        Mm(*y),
                        font
                    );
                    *y -= 6.0;
                }

                *y -= 3.0; // Spacing
                finding_count += 1;

                // Sayfa kontrolü
                if *y < 50.0 {
                    break;
                }
            }
        }

        *y -= 10.0;
        Ok(())
    }

    /// İstatistikler ekle
    fn add_statistics(
        &self,
        layer: &PdfLayerReference,
        font_bold: &IndirectFontRef,
        font: &IndirectFontRef,
        report: &SecurityReport,
        x: f32,
        y: &mut f32,
        _page_width: f32,
    ) -> Result<(), ReportError> {
        // Bölüm başlığı
        layer.use_text("📊 Statistics", self.font_size_heading, Mm(x), Mm(*y), font_bold);
        *y -= 12.0;

        // Kategori bazlı dağılım
        layer.use_text("Findings by Category:", self.font_size_body, Mm(x + 5.0), Mm(*y), font_bold);
        *y -= 8.0;

        for (category, count) in &report.statistics.findings_by_category {
            layer.use_text(
                format!("  • {}: {}", category, count),
                self.font_size_small,
                Mm(x + 10.0),
                Mm(*y),
                font
            );
            *y -= 6.0;
        }

        *y -= 5.0;

        // En önemli zafiyetler
        layer.use_text("Top Vulnerabilities:", self.font_size_body, Mm(x + 5.0), Mm(*y), font_bold);
        *y -= 8.0;

        for (i, vuln) in report.statistics.top_vulnerabilities.iter().take(5).enumerate() {
            layer.use_text(
                format!("{}. {} ({} - Count: {})", i + 1, vuln.title, vuln.severity, vuln.count),
                self.font_size_small,
                Mm(x + 10.0),
                Mm(*y),
                font
            );
            *y -= 6.0;
        }

        *y -= 10.0;
        Ok(())
    }

    /// Öneriler ekle
    fn add_recommendations(
        &self,
        layer: &PdfLayerReference,
        font_bold: &IndirectFontRef,
        font: &IndirectFontRef,
        report: &SecurityReport,
        x: f32,
        y: &mut f32,
        _page_width: f32,
    ) -> Result<(), ReportError> {
        // Bölüm başlığı
        layer.use_text("💡 Recommendations", self.font_size_heading, Mm(x), Mm(*y), font_bold);
        *y -= 12.0;

        for (i, recommendation) in report.recommendations.iter().enumerate() {
            // Öneriyit kısalt (PDF için)
            let short_recommendation = if recommendation.len() > 90 {
                format!("{}...", &recommendation[..90])
            } else {
                recommendation.clone()
            };

            layer.use_text(
                format!("{}. {}", i + 1, short_recommendation),
                self.font_size_small,
                Mm(x + 5.0),
                Mm(*y),
                font
            );
            *y -= 8.0;
        }

        *y -= 10.0;
        Ok(())
    }

    /// Sistem bilgileri ekle
    fn add_system_info(
        &self,
        layer: &PdfLayerReference,
        font_bold: &IndirectFontRef,
        font: &IndirectFontRef,
        report: &SecurityReport,
        x: f32,
        y: &mut f32,
        _page_width: f32,
    ) -> Result<(), ReportError> {
        // Bölüm başlığı
        layer.use_text("💻 System Information", self.font_size_heading, Mm(x), Mm(*y), font_bold);
        *y -= 12.0;

        let system_info = [
            ("Hostname", &report.metadata.system_info.hostname),
            ("OS Version", &report.metadata.system_info.os_version),
            ("Kernel", &report.metadata.system_info.kernel_version),
            ("Architecture", &report.metadata.system_info.architecture),
            ("pinGuard Version", &report.metadata.pinGuard_version),
        ];

        for (label, value) in system_info.iter() {
            layer.use_text(
                format!("{}: {}", label, value),
                self.font_size_small,
                Mm(x + 5.0),
                Mm(*y),
                font
            );
            *y -= 6.0;
        }

        // Footer
        *y -= 10.0;
        layer.use_text(
            format!("Generated by pinGuard at {}", self.format_timestamp(report.metadata.generated_at)),
            self.font_size_small,
            Mm(x),
            Mm(*y),
            font
        );

        Ok(())
    }

    /// Timestamp formatla
    fn format_timestamp(&self, timestamp: u64) -> String {
        use std::time::{SystemTime, UNIX_EPOCH, Duration};
        
        let datetime = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
        format!("{:?}", datetime)
            .replace("SystemTime", "")
            .trim()
            .to_string()
    }

    /// PDF dosyasını yaz
    fn write_pdf_file(&self, pdf_bytes: &[u8], output_path: &str) -> Result<String, ReportError> {
        // Çıkış dizinini oluştur
        if let Some(parent) = Path::new(output_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ReportError::IoError(format!("Failed to create output directory: {}", e)))?;
        }

        // PDF dosyasını yaz
        fs::write(output_path, pdf_bytes)
            .map_err(|e| ReportError::IoError(format!("Failed to write PDF file: {}", e)))?;

        Ok(output_path.to_string())
    }
}

impl Reporter for PdfReporter {
    fn generate_report(&self, report: &SecurityReport, output_path: &str) -> Result<String, ReportError> {
        // Dosya uzantısını kontrol et ve gerekirse ekle
        let final_path = if output_path.ends_with(".pdf") {
            output_path.to_string()
        } else {
            format!("{}.pdf", output_path)
        };

        let pdf_bytes = self.render_pdf(report)?;
        self.write_pdf_file(&pdf_bytes, &final_path)
    }

    fn format_name(&self) -> &'static str {
        "PDF"
    }

    fn file_extension(&self) -> &'static str {
        "pdf"
    }
}

/// Hızlı PDF rapor oluşturma fonksiyonu
pub fn generate_pdf_report(
    report: &SecurityReport,
    output_path: &str,
) -> Result<String, ReportError> {
    let reporter = PdfReporter::new();
    reporter.generate_report(report, output_path)
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
                    severity: Severity::Critical,
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
    fn test_pdf_reporter_creation() {
        let reporter = PdfReporter::new();
        assert_eq!(reporter.format_name(), "PDF");
        assert_eq!(reporter.file_extension(), "pdf");
    }

    #[test]
    fn test_pdf_generation() {
        let reporter = PdfReporter::new();
        let report = create_test_report();
        
        let pdf_result = reporter.render_pdf(&report);
        assert!(pdf_result.is_ok());
        
        let pdf_bytes = pdf_result.unwrap();
        assert!(!pdf_bytes.is_empty());
        
        // PDF header kontrolü
        assert_eq!(&pdf_bytes[0..4], b"%PDF");
    }

    #[test]
    fn test_pdf_page_sizes() {
        let a4_reporter = PdfReporter::a4();
        assert_eq!(a4_reporter.page_size, (210.0, 297.0));

        let letter_reporter = PdfReporter::letter();
        assert_eq!(letter_reporter.page_size, (215.9, 279.4));
    }
}