use std::fs;
use std::path::Path;
use std::collections::HashMap;
use crate::report::{Reporter, ReportError, SecurityReport};

/// HTML formatında rapor üreten yapı
pub struct HtmlReporter {
    template_dir: String,
    include_css: bool,
    interactive: bool,
}

impl HtmlReporter {
    /// Yeni HTML reporter oluştur
    pub fn new(template_dir: Option<String>, include_css: bool, interactive: bool) -> Self {
        Self {
            template_dir: template_dir.unwrap_or_else(|| "templates".to_string()),
            include_css,
            interactive,
        }
    }

    /// Varsayılan HTML reporter
    pub fn default() -> Self {
        Self::new(None, true, true)
    }

    /// HTML template'ini render et
    fn render_html(&self, report: &SecurityReport) -> Result<String, ReportError> {
        let mut html = self.generate_html_header(report)?;
        html.push_str(&self.generate_html_body(report)?);
        html.push_str(&self.generate_html_footer());
        Ok(html)
    }

    /// HTML header oluştur
    fn generate_html_header(&self, report: &SecurityReport) -> Result<String, ReportError> {
        let css = if self.include_css {
            self.get_embedded_css()
        } else {
            r#"<link rel="stylesheet" href="report.css">"#.to_string()
        };

        let javascript = if self.interactive {
            self.get_embedded_javascript()
        } else {
            String::new()
        };

        Ok(format!(
            r#"<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>pinGuard Security Report - {}</title>
    {}
    {}
</head>
<body>
    <div class="container">
        <header class="report-header">
            <div class="header-content">
                <h1>🛡️ pinGuard Security Report</h1>
                <div class="header-info">
                    <span class="report-id">Report ID: {}</span>
                    <span class="generated-date">Generated: {}</span>
                    <span class="system-info">{} ({})</span>
                </div>
            </div>
        </header>"#,
            report.metadata.system_info.hostname,
            css,
            javascript,
            report.metadata.report_id,
            self.format_timestamp(report.metadata.generated_at),
            report.metadata.system_info.hostname,
            report.metadata.system_info.os_version
        ))
    }

    /// HTML body oluştur
    fn generate_html_body(&self, report: &SecurityReport) -> Result<String, ReportError> {
        let mut body = String::new();

        // Executive Summary
        body.push_str(&self.generate_executive_summary(report));
        
        // Security Score Dashboard
        body.push_str(&self.generate_security_dashboard(report));
        
        // Findings Overview
        body.push_str(&self.generate_findings_overview(report));
        
        // Detailed Findings
        body.push_str(&self.generate_detailed_findings(report));
        
        // Statistics
        body.push_str(&self.generate_statistics_section(report));
        
        // Recommendations
        body.push_str(&self.generate_recommendations_section(report));
        
        // System Information
        body.push_str(&self.generate_system_info_section(report));

        Ok(body)
    }

    /// Executive summary oluştur
    fn generate_executive_summary(&self, report: &SecurityReport) -> String {
        let risk_class = match report.summary.risk_level.as_str() {
            "LOW" => "risk-low",
            "MEDIUM" => "risk-medium",
            "HIGH" => "risk-high",
            "CRITICAL" => "risk-critical",
            _ => "risk-unknown",
        };

        format!(
            r#"
        <section class="executive-summary">
            <h2>📋 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Security Score</h3>
                    <div class="score-display">
                        <span class="score-number">{}</span>
                        <span class="score-max">/100</span>
                    </div>
                    <div class="risk-level {}">
                        <span>{}</span>
                    </div>
                </div>
                <div class="summary-card">
                    <h3>Total Findings</h3>
                    <div class="findings-count">{}</div>
                    <div class="scan-info">{} scans completed</div>
                </div>
                <div class="summary-card">
                    <h3>Scan Duration</h3>
                    <div class="duration">{} ms</div>
                    <div class="performance">{:.1} items/sec</div>
                </div>
            </div>
        </section>"#,
            report.summary.security_score,
            risk_class,
            report.summary.risk_level,
            report.summary.total_findings,
            report.summary.total_scans,
            report.metadata.scan_duration_ms,
            report.statistics.scan_performance.items_per_second
        )
    }

    /// Security dashboard oluştur
    fn generate_security_dashboard(&self, report: &SecurityReport) -> String {
        format!(
            r#"
        <section class="security-dashboard">
            <h2>🎯 Security Dashboard</h2>
            <div class="severity-grid">
                <div class="severity-card critical">
                    <div class="severity-icon">🚨</div>
                    <div class="severity-count">{}</div>
                    <div class="severity-label">Critical</div>
                </div>
                <div class="severity-card high">
                    <div class="severity-icon">🔥</div>
                    <div class="severity-count">{}</div>
                    <div class="severity-label">High</div>
                </div>
                <div class="severity-card medium">
                    <div class="severity-icon">⚠️</div>
                    <div class="severity-count">{}</div>
                    <div class="severity-label">Medium</div>
                </div>
                <div class="severity-card low">
                    <div class="severity-icon">ℹ️</div>
                    <div class="severity-count">{}</div>
                    <div class="severity-label">Low</div>
                </div>
            </div>
        </section>"#,
            report.summary.critical_findings,
            report.summary.high_findings,
            report.summary.medium_findings,
            report.summary.low_findings
        )
    }

    /// Findings overview oluştur
    fn generate_findings_overview(&self, report: &SecurityReport) -> String {
        let mut overview = String::from(
            r#"
        <section class="findings-overview">
            <h2>🔍 Findings Overview</h2>
            <div class="findings-table-container">
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>Scanner</th>
                            <th>Status</th>
                            <th>Findings</th>
                            <th>Duration</th>
                            <th>Items Scanned</th>
                        </tr>
                    </thead>
                    <tbody>"#
        );

        for scan_result in &report.scan_results {
            let status_class = match scan_result.status {
                crate::scanners::ScanStatus::Success => "status-success",
                crate::scanners::ScanStatus::Warning => "status-warning",
                crate::scanners::ScanStatus::Error(_) => "status-failed",
                crate::scanners::ScanStatus::Skipped(_) => "status-skipped",
            };

            overview.push_str(&format!(
                r#"
                        <tr>
                            <td class="scanner-name">{}</td>
                            <td class="{}">
                                <span class="status-indicator"></span>
                                {:?}
                            </td>
                            <td class="findings-count">{}</td>
                            <td class="duration">{} ms</td>
                            <td class="items-count">{}</td>
                        </tr>"#,
                scan_result.scanner_name,
                status_class,
                scan_result.status,
                scan_result.findings.len(),
                scan_result.metadata.duration_ms,
                scan_result.metadata.items_scanned
            ));
        }

        overview.push_str(
            r#"
                    </tbody>
                </table>
            </div>
        </section>"#
        );

        overview
    }

    /// Detaylı findings oluştur
    fn generate_detailed_findings(&self, report: &SecurityReport) -> String {
        let mut findings_html = String::from(
            r#"
        <section class="detailed-findings">
            <h2>🔎 Detailed Findings</h2>
            <div class="findings-list">"#
        );

        for scan_result in &report.scan_results {
            if !scan_result.findings.is_empty() {
                findings_html.push_str(&format!(
                    r#"
                <div class="scanner-findings">
                    <h3 class="scanner-title">{}</h3>
                    <div class="findings-cards">"#,
                    scan_result.scanner_name
                ));

                for finding in &scan_result.findings {
                    let severity_class = format!("severity-{}", format!("{:?}", finding.severity).to_lowercase());
                    let severity_icon = match finding.severity {
                        crate::scanners::Severity::Critical => "�",
                        crate::scanners::Severity::High => "�",
                        crate::scanners::Severity::Medium => "🟡",
                        crate::scanners::Severity::Low => "ℹ️",
                        crate::scanners::Severity::Info => "💡",
                    };

                    findings_html.push_str(&format!(
                        r#"
                        <div class="finding-card {}">
                            <div class="finding-header">
                                <span class="severity-icon">{}</span>
                                <h4 class="finding-title">{}</h4>
                                <span class="finding-id">{}</span>
                            </div>
                            <div class="finding-body">
                                <p class="finding-description">{}</p>
                                <div class="finding-details">
                                    <div class="detail-item">
                                        <strong>Affected Item:</strong> {}
                                    </div>
                                    <div class="detail-item">
                                        <strong>Category:</strong> {:?}
                                    </div>
                                    {}
                                    {}
                                    {}
                                </div>
                            </div>
                        </div>"#,
                        severity_class,
                        severity_icon,
                        finding.title,
                        finding.id,
                        finding.description,
                        finding.affected_item,
                        finding.category,
                        if finding.recommended_value.is_some() {
                            format!(r#"<div class="detail-item remediation"><strong>Recommended Value:</strong> {}</div>"#, 
                                finding.recommended_value.as_ref().unwrap())
                        } else {
                            String::new()
                        },
                        if !finding.cve_ids.is_empty() {
                            format!(r#"<div class="detail-item cve-ids"><strong>CVE IDs:</strong> {}</div>"#, finding.cve_ids.join(", "))
                        } else {
                            String::new()
                        },
                        if !finding.references.is_empty() {
                            format!(r#"<div class="detail-item references"><strong>References:</strong> {}</div>"#, 
                                finding.references.iter()
                                    .map(|r| format!(r#"<a href="{}" target="_blank">{}</a>"#, r, r))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        } else {
                            String::new()
                        }
                    ));
                }

                findings_html.push_str(
                    r#"
                    </div>
                </div>"#
                );
            }
        }

        findings_html.push_str(
            r#"
            </div>
        </section>"#
        );

        findings_html
    }

    /// İstatistikler bölümü oluştur
    fn generate_statistics_section(&self, report: &SecurityReport) -> String {
        let mut stats_html = String::from(
            r#"
        <section class="statistics">
            <h2>📊 Statistics</h2>
            <div class="stats-grid">
                <div class="stats-card">
                    <h3>Findings by Category</h3>
                    <div class="chart-container">
                        <div class="category-chart">"#
        );

        for (category, count) in &report.statistics.findings_by_category {
            let percentage = if report.summary.total_findings > 0 {
                (*count as f64 / report.summary.total_findings as f64) * 100.0
            } else {
                0.0
            };

            stats_html.push_str(&format!(
                r#"
                            <div class="category-item">
                                <span class="category-name">{}</span>
                                <div class="category-bar">
                                    <div class="category-fill" style="width: {}%"></div>
                                </div>
                                <span class="category-count">{}</span>
                            </div>"#,
                category, percentage, count
            ));
        }

        stats_html.push_str(
            r#"
                        </div>
                    </div>
                </div>
                <div class="stats-card">
                    <h3>Top Vulnerabilities</h3>
                    <div class="vulnerabilities-list">"#
        );

        for (i, vuln) in report.statistics.top_vulnerabilities.iter().take(5).enumerate() {
            stats_html.push_str(&format!(
                r#"
                        <div class="vulnerability-item">
                            <span class="vuln-rank">#{}</span>
                            <div class="vuln-info">
                                <div class="vuln-title">{}</div>
                                <div class="vuln-details">{} - Count: {}</div>
                            </div>
                        </div>"#,
                i + 1,
                vuln.title,
                vuln.severity,
                vuln.count
            ));
        }

        stats_html.push_str(
            r#"
                    </div>
                </div>
            </div>
        </section>"#
        );

        stats_html
    }

    /// Öneriler bölümü oluştur
    fn generate_recommendations_section(&self, report: &SecurityReport) -> String {
        let mut recommendations_html = String::from(
            r#"
        <section class="recommendations">
            <h2>💡 Recommendations</h2>
            <div class="recommendations-list">"#
        );

        for (i, recommendation) in report.recommendations.iter().enumerate() {
            recommendations_html.push_str(&format!(
                r#"
                <div class="recommendation-item">
                    <span class="recommendation-number">{}</span>
                    <div class="recommendation-text">{}</div>
                </div>"#,
                i + 1,
                recommendation
            ));
        }

        recommendations_html.push_str(
            r#"
            </div>
        </section>"#
        );

        recommendations_html
    }

    /// Sistem bilgileri bölümü oluştur
    fn generate_system_info_section(&self, report: &SecurityReport) -> String {
        format!(
            r#"
        <section class="system-info">
            <h2>💻 System Information</h2>
            <div class="system-grid">
                <div class="system-item">
                    <strong>Hostname:</strong> {}
                </div>
                <div class="system-item">
                    <strong>OS:</strong> {}
                </div>
                <div class="system-item">
                    <strong>Kernel:</strong> {}
                </div>
                <div class="system-item">
                    <strong>Architecture:</strong> {}
                </div>
                <div class="system-item">
                    <strong>pinGuard Version:</strong> {}
                </div>
                <div class="system-item">
                    <strong>Report Generated:</strong> {}
                </div>
            </div>
        </section>"#,
            report.metadata.system_info.hostname,
            report.metadata.system_info.os_version,
            report.metadata.system_info.kernel_version,
            report.metadata.system_info.architecture,
            report.metadata.pinGuard_version,
            self.format_timestamp(report.metadata.generated_at)
        )
    }

    /// HTML footer oluştur
    fn generate_html_footer(&self) -> String {
        format!(
            r#"
        <footer class="report-footer">
            <div class="footer-content">
                <p>Generated by <strong>pinGuard</strong> - Linux Security Scanner & Remediator</p>
                <p>Report generated at {}</p>
            </div>
        </footer>
    </div>
</body>
</html>"#,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )
    }

    /// Gömülü CSS al
    fn get_embedded_css(&self) -> String {
        r#"
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            min-height: 100vh;
        }

        .report-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 0 0 20px 20px;
        }

        .header-content h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .header-info {
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
            font-size: 0.9rem;
            opacity: 0.9;
        }

        section {
            margin: 2rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        section h2 {
            background: #f8f9fa;
            padding: 1rem 2rem;
            margin: 0;
            border-bottom: 2px solid #e9ecef;
            color: #495057;
        }

        .summary-grid, .severity-grid, .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            padding: 2rem;
        }

        .summary-card, .severity-card, .stats-card {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }

        .summary-card:hover, .severity-card:hover, .stats-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }

        .score-display {
            font-size: 3rem;
            font-weight: bold;
            margin: 1rem 0;
        }

        .score-number {
            color: #28a745;
        }

        .score-max {
            color: #6c757d;
            font-size: 1.5rem;
        }

        .risk-level {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .risk-low { background: #d4edda; color: #155724; }
        .risk-medium { background: #fff3cd; color: #856404; }
        .risk-high { background: #f8d7da; color: #721c24; }
        .risk-critical { background: #f5c6cb; color: #491217; }

        .severity-card {
            text-align: center;
        }

        .severity-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .severity-count {
            font-size: 2.5rem;
            font-weight: bold;
            margin: 0.5rem 0;
        }

        .severity-card.critical .severity-count { color: #dc3545; }
        .severity-card.high .severity-count { color: #fd7e14; }
        .severity-card.medium .severity-count { color: #ffc107; }
        .severity-card.low .severity-count { color: #28a745; }

        .findings-table-container {
            padding: 2rem;
            overflow-x: auto;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }

        .findings-table th,
        .findings-table td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }

        .findings-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }

        .status-success { color: #28a745; }
        .status-failed { color: #dc3545; }
        .status-skipped { color: #6c757d; }

        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }

        .status-success .status-indicator { background: #28a745; }
        .status-failed .status-indicator { background: #dc3545; }
        .status-skipped .status-indicator { background: #6c757d; }

        .detailed-findings {
            padding: 2rem;
        }

        .scanner-findings {
            margin-bottom: 2rem;
        }

        .scanner-title {
            color: #495057;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
        }

        .findings-cards {
            display: grid;
            gap: 1rem;
        }

        .finding-card {
            border: 1px solid #e9ecef;
            border-radius: 8px;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }

        .finding-card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }

        .finding-header {
            display: flex;
            align-items: center;
            padding: 1rem;
            gap: 1rem;
        }

        .severity-critical .finding-header { background: #f8d7da; }
        .severity-high .finding-header { background: #ffeaa7; }
        .severity-medium .finding-header { background: #fff3cd; }
        .severity-low .finding-header { background: #d4edda; }

        .finding-title {
            flex: 1;
            margin: 0;
        }

        .finding-id {
            font-family: monospace;
            background: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }

        .finding-body {
            padding: 1rem;
        }

        .finding-description {
            margin-bottom: 1rem;
            color: #6c757d;
        }

        .finding-details {
            display: grid;
            gap: 0.5rem;
        }

        .detail-item {
            padding: 0.5rem;
            background: #f8f9fa;
            border-radius: 4px;
        }

        .detail-item strong {
            color: #495057;
        }

        .remediation {
            border-left: 4px solid #28a745;
        }

        .cve-ids {
            font-family: monospace;
            font-size: 0.9rem;
        }

        .category-chart {
            display: grid;
            gap: 1rem;
        }

        .category-item {
            display: grid;
            grid-template-columns: 1fr 2fr auto;
            align-items: center;
            gap: 1rem;
        }

        .category-bar {
            background: #e9ecef;
            height: 20px;
            border-radius: 10px;
            overflow: hidden;
        }

        .category-fill {
            background: linear-gradient(90deg, #667eea, #764ba2);
            height: 100%;
            transition: width 0.3s ease;
        }

        .vulnerabilities-list, .recommendations-list {
            padding: 2rem;
        }

        .vulnerability-item, .recommendation-item {
            display: flex;
            align-items: flex-start;
            gap: 1rem;
            padding: 1rem;
            border-bottom: 1px solid #e9ecef;
        }

        .vuln-rank, .recommendation-number {
            background: #667eea;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-weight: bold;
            min-width: 2rem;
            text-align: center;
        }

        .system-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
            padding: 2rem;
        }

        .system-item {
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }

        .report-footer {
            background: #343a40;
            color: white;
            text-align: center;
            padding: 2rem;
            margin-top: 2rem;
        }

        .footer-content p {
            margin: 0.25rem 0;
        }

        @media (max-width: 768px) {
            .container {
                margin: 0;
                border-radius: 0;
            }

            section {
                margin: 1rem;
            }

            .header-info {
                flex-direction: column;
                gap: 0.5rem;
            }

            .findings-table-container {
                padding: 1rem;
            }

            .summary-grid, .severity-grid {
                grid-template-columns: 1fr;
            }
        }

        @media print {
            body {
                background: white;
            }

            .container {
                box-shadow: none;
            }

            section {
                break-inside: avoid;
                box-shadow: none;
                border: 1px solid #ddd;
            }
        }
    </style>"#.to_string()
    }

    /// Gömülü JavaScript al
    fn get_embedded_javascript(&self) -> String {
        r###"
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Smooth scrolling for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    document.querySelector(this.getAttribute('href')).scrollIntoView({
                        behavior: 'smooth'
                    });
                });
            });

            // Add click-to-expand functionality for finding cards
            document.querySelectorAll('.finding-card').forEach(function(card) {
                card.addEventListener('click', function() {
                    this.classList.toggle('expanded');
                });
            });

            // Add filtering functionality
            var createFilter = function() {
                var filterContainer = document.createElement('div');
                filterContainer.className = 'filter-container';
                filterContainer.innerHTML = 
                    '<div style="padding: 1rem; background: #f8f9fa; margin: 1rem 2rem; border-radius: 8px;">' +
                        '<label for="severity-filter">Filter by Severity:</label>' +
                        '<select id="severity-filter" style="margin-left: 1rem; padding: 0.5rem;">' +
                            '<option value="">All</option>' +
                            '<option value="critical">Critical</option>' +
                            '<option value="high">High</option>' +
                            '<option value="medium">Medium</option>' +
                            '<option value="low">Low</option>' +
                        '</select>' +
                    '</div>';

                var findingsSection = document.querySelector('.detailed-findings');
                if (findingsSection) {
                    findingsSection.insertBefore(filterContainer, findingsSection.firstChild);

                    document.getElementById('severity-filter').addEventListener('change', function() {
                        var selectedSeverity = this.value;
                        document.querySelectorAll('.finding-card').forEach(function(card) {
                            if (!selectedSeverity || card.classList.contains('severity-' + selectedSeverity)) {
                                card.style.display = 'block';
                            } else {
                                card.style.display = 'none';
                            }
                        });
                    });
                }
            };

            createFilter();

            // Add export functionality
            var addExportButton = function() {
                var exportButton = document.createElement('button');
                exportButton.innerHTML = '📥 Export Report';
                exportButton.style.cssText = 
                    'position: fixed;' +
                    'top: 20px;' +
                    'right: 20px;' +
                    'padding: 10px 20px;' +
                    'background: #667eea;' +
                    'color: white;' +
                    'border: none;' +
                    'border-radius: 5px;' +
                    'cursor: pointer;' +
                    'z-index: 1000;';

                exportButton.addEventListener('click', function() {
                    window.print();
                });

                document.body.appendChild(exportButton);
            };

            addExportButton();

            console.log('pinGuard HTML Report loaded successfully');
        });
    </script>"###.to_string()
    }

    /// Timestamp'i formatla
    fn format_timestamp(&self, timestamp: u64) -> String {
        use std::time::{SystemTime, UNIX_EPOCH, Duration};
        
        let datetime = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
        
        // Basit format (chrono kullanmadan)
        format!("{:?}", datetime)
            .replace("SystemTime", "")
            .trim()
            .to_string()
    }

    /// HTML dosyasını yaz
    fn write_html_file(&self, html_content: &str, output_path: &str) -> Result<String, ReportError> {
        // Çıkış dizinini oluştur
        if let Some(parent) = Path::new(output_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ReportError::IoError(format!("Failed to create output directory: {}", e)))?;
        }

        // HTML dosyasını yaz
        fs::write(output_path, html_content)
            .map_err(|e| ReportError::IoError(format!("Failed to write HTML file: {}", e)))?;

        Ok(output_path.to_string())
    }
}

impl Reporter for HtmlReporter {
    fn generate_report(&self, report: &SecurityReport, output_path: &str) -> Result<String, ReportError> {
        // Dosya uzantısını kontrol et ve gerekirse ekle
        let final_path = if output_path.ends_with(".html") {
            output_path.to_string()
        } else {
            format!("{}.html", output_path)
        };

        let html_content = self.render_html(report)?;
        self.write_html_file(&html_content, &final_path)
    }

    fn format_name(&self) -> &'static str {
        "HTML"
    }

    fn file_extension(&self) -> &'static str {
        "html"
    }
}

/// Hızlı HTML rapor oluşturma fonksiyonu
pub fn generate_html_report(
    report: &SecurityReport,
    output_path: &str,
    include_css: bool,
    interactive: bool,
) -> Result<String, ReportError> {
    let reporter = HtmlReporter::new(None, include_css, interactive);
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
    fn test_html_reporter_creation() {
        let reporter = HtmlReporter::new(None, true, true);
        assert_eq!(reporter.format_name(), "HTML");
        assert_eq!(reporter.file_extension(), "html");
    }

    #[test]
    fn test_html_generation() {
        let reporter = HtmlReporter::new(None, true, false);
        let report = create_test_report();
        
        let html_result = reporter.render_html(&report);
        assert!(html_result.is_ok());
        
        let html_content = html_result.unwrap();
        assert!(html_content.contains("<!DOCTYPE html"));
        assert!(html_content.contains("pinGuard Security Report"));
        assert!(html_content.contains("TEST-001"));
        assert!(html_content.contains("Test vulnerability"));
    }

    #[test]
    fn test_executive_summary_generation() {
        let reporter = HtmlReporter::default();
        let report = create_test_report();
        
        let summary = reporter.generate_executive_summary(&report);
        assert!(summary.contains("Executive Summary"));
        assert!(summary.contains("Security Score"));
        assert!(summary.contains("Total Findings"));
    }
}