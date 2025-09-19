//! Scan command implementation

use crate::cli::display::Display;
use crate::core::{config::Config, errors::PinGuardResult};
use crate::scanners::{manager::ScannerManager, Severity, ScanResult, ScanMetadata};
use clap::ArgMatches;
use tracing::warn;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use chrono;

/// Handle the scan command
pub fn handle(matches: &ArgMatches, config: &Config, display: &Display) -> PinGuardResult<()> {
    display.section_header("System Security Scan");
    
    let scanner_manager = ScannerManager::new();
    
    // Determine scan type
    if let Some(module) = matches.get_one::<String>("module") {
        handle_module_scan(module, matches, config, &scanner_manager, display)
    } else {
        handle_full_scan(matches, config, &scanner_manager, display)
    }
}

/// Handle scanning a specific module
fn handle_module_scan(
    module: &str,
    matches: &ArgMatches,
    config: &Config,
    scanner_manager: &ScannerManager,
    display: &Display,
) -> PinGuardResult<()> {
    display.info(&format!("Running {} scanner...", module));
    
    match scanner_manager.run_specific_scan(module, config) {
        Ok(result) => {
            let critical = result.findings.iter().filter(|f| f.severity == Severity::Critical).count();
            let high = result.findings.iter().filter(|f| f.severity == Severity::High).count();
            let medium = result.findings.iter().filter(|f| f.severity == Severity::Medium).count();
            let low = result.findings.iter().filter(|f| f.severity == Severity::Low).count();
            
            display.scan_summary(result.findings.len(), critical, high, medium, low);
            
            // Show detailed findings if requested
            if !matches.get_flag("quiet") {
                show_findings(&result.findings, display);
            }
            
            // Save results if output specified
            if let Some(output_file) = matches.get_one::<String>("output") {
                save_results(&result, output_file, matches, display)?;
            }
            
            display.success(&format!("{} scan completed successfully", module));
            Ok(())
        }
        Err(e) => {
            display.error(&format!("Scan failed: {}", e));
            Err(crate::core::errors::PinGuardError::Scanner {
                scanner: module.to_string(),
                message: e.to_string(),
                source: None,
            })
        }
    }
}

/// Handle full system scan
fn handle_full_scan(
    matches: &ArgMatches,
    config: &Config,
    scanner_manager: &ScannerManager,
    display: &Display,
) -> PinGuardResult<()> {
    display.info("Starting comprehensive system scan...");
    
    let quick_scan = matches.get_flag("quick");
    let excluded_modules: Vec<&str> = matches
        .get_many::<String>("exclude")
        .map(|v| v.map(|s| s.as_str()).collect())
        .unwrap_or_default();
    
    if quick_scan {
        display.info("Quick scan mode enabled - skipping intensive checks");
    }
    
    if !excluded_modules.is_empty() {
        display.info(&format!("Excluding modules: {}", excluded_modules.join(", ")));
    }
    
    // Get available modules from config
    let mut enabled_modules = config.scanner.enabled_modules.clone();
    
    // Remove excluded modules
    enabled_modules.retain(|module| !excluded_modules.contains(&module.as_str()));
    
    let total_modules = enabled_modules.len();
    let mut completed = 0;
    let mut all_findings = Vec::new();
    
    // Run each scanner module
    for module in &enabled_modules {
        display.progress_bar(completed, total_modules, &format!("Scanning {}", module));
        
        match scanner_manager.run_specific_scan(module, config) {
            Ok(result) => {
                all_findings.extend(result.findings);
                completed += 1;
                display.progress_bar(completed, total_modules, &format!("Completed {}", module));
            }
            Err(e) => {
                warn!("Scanner {} failed: {}", module, e);
                display.warning(&format!("Scanner {} failed: {}", module, e));
                completed += 1;
            }
        }
    }
    
    // Calculate summary statistics
    let critical = all_findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = all_findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = all_findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = all_findings.iter().filter(|f| f.severity == Severity::Low).count();
    
    display.scan_summary(all_findings.len(), critical, high, medium, low);
    
    // Show detailed findings if requested
    if !matches.get_flag("quiet") && !all_findings.is_empty() {
        show_findings(&all_findings, display);
    }
    
    // Save results if output specified
    if let Some(output_file) = matches.get_one::<String>("output") {
        let full_result = crate::scanners::ScanResult {
            scanner_name: "full_scan".to_string(),
            scan_time: chrono::Utc::now().to_rfc3339(),
            status: crate::scanners::ScanStatus::Success,
            findings: all_findings,
            metadata: crate::scanners::ScanMetadata {
                duration_ms: 0, // This would need to be calculated properly
                items_scanned: 0,
                issues_found: (critical + high + medium + low) as u32,
                scan_timestamp: chrono::Utc::now().to_rfc3339(),
                scanner_version: "1.0.0".to_string(),
            },
            raw_data: None,
        };
        save_results(&full_result, output_file, matches, display)?;
    }
    
    display.success("Full system scan completed successfully");
    Ok(())
}

/// Display scan findings
fn show_findings(findings: &[crate::scanners::Finding], display: &Display) {
    if findings.is_empty() {
        display.success("No security issues found!");
        return;
    }
    
    display.section_header("Security Findings");
    
    // Group findings by severity
    let mut by_severity: std::collections::HashMap<String, Vec<&crate::scanners::Finding>> = 
        std::collections::HashMap::new();
    
    for finding in findings {
        by_severity
            .entry(format!("{:?}", finding.severity))
            .or_insert_with(Vec::new)
            .push(finding);
    }
    
    // Show findings in order of severity
    for severity in &["Critical", "High", "Medium", "Low"] {
        if let Some(severity_findings) = by_severity.get(*severity) {
            if !severity_findings.is_empty() {
                println!();
                match *severity {
                    "Critical" => display.error(&format!("🔴 Critical Issues ({})", severity_findings.len())),
                    "High" => display.warning(&format!("🟠 High Priority Issues ({})", severity_findings.len())),
                    "Medium" => display.info(&format!("🟡 Medium Priority Issues ({})", severity_findings.len())),
                    "Low" => display.info(&format!("🟢 Low Priority Issues ({})", severity_findings.len())),
                    _ => display.info(&format!("Issues ({})", severity_findings.len())),
                }
                
                for (i, finding) in severity_findings.iter().enumerate() {
                    println!("  {}. {}", i + 1, finding.title);
                    if !finding.description.is_empty() {
                        println!("     {}", finding.description);
                    }
                    if !finding.cve_ids.is_empty() {
                        println!("     CVE: {}", finding.cve_ids.join(", "));
                    }
                    if !finding.affected_item.is_empty() {
                        println!("     Affected: {}", finding.affected_item);
                    }
                    if let Some(recommended) = &finding.recommended_value {
                        println!("     Recommendation: {}", recommended);
                    }
                    println!();
                }
            }
        }
    }
}

/// Save scan results to file
fn save_results(
    result: &crate::scanners::ScanResult,
    output_file: &str,
    matches: &ArgMatches,
    display: &Display,
) -> PinGuardResult<()> {
    let format = matches.get_one::<String>("format").map(|s| s.as_str()).unwrap_or("json");
    
    match format {
        "json" => {
            let content = serde_json::to_string_pretty(result)
                .map_err(|e| crate::core::errors::PinGuardError::Parse {
                    message: format!("Failed to serialize to JSON: {}", e),
                    source: None,
                })?;
            std::fs::write(output_file, content)
                .map_err(|e| crate::core::errors::PinGuardError::Io {
                    message: format!("Failed to write file {}: {}", output_file, e),
                    source: None,
                })?;
        }
        "yaml" => {
            let content = serde_yaml::to_string(result)
                .map_err(|e| crate::core::errors::PinGuardError::Parse {
                    message: format!("Failed to serialize to YAML: {}", e),
                    source: None,
                })?;
            std::fs::write(output_file, content)
                .map_err(|e| crate::core::errors::PinGuardError::Io {
                    message: format!("Failed to write file {}: {}", output_file, e),
                    source: None,
                })?;
        }
        "table" => {
            // Create a simple table format
            let mut content = String::new();
            content.push_str(&format!("PinGuard Scan Results - {}\n", result.scan_time));
            content.push_str(&format!("Scanner: {}\n", result.scanner_name));
            content.push_str(&format!("Total Findings: {}\n\n", result.findings.len()));
            
            for finding in &result.findings {
                content.push_str(&format!("Severity: {:?}\n", finding.severity));
                content.push_str(&format!("Title: {}\n", finding.title));
                content.push_str(&format!("Description: {}\n", finding.description));
                if !finding.cve_ids.is_empty() {
                    content.push_str(&format!("CVE: {}\n", finding.cve_ids.join(", ")));
                }
                if !finding.affected_item.is_empty() {
                    content.push_str(&format!("Affected: {}\n", finding.affected_item));
                }
                if let Some(recommended) = &finding.recommended_value {
                    content.push_str(&format!("Recommendation: {}\n", recommended));
                }
                content.push_str("---\n\n");
            }
            
            std::fs::write(output_file, content)
                .map_err(|e| crate::core::errors::PinGuardError::Io {
                    message: format!("Failed to write file {}: {}", output_file, e),
                    source: None,
                })?;
        }
        _ => {
            return Err(crate::core::errors::PinGuardError::Validation {
                message: format!("Unsupported output format: {}", format),
                source: None,
            });
        }
    }
    
    display.success(&format!("Results saved to: {}", output_file));
    Ok(())
}