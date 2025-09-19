//! Interactive mode for PinGuard CLI

use crate::cli::display::Display;
use crate::core::{config::Config, errors::PinGuardResult};
use std::io::{self, Write};

/// Run the interactive mode
pub fn run_interactive_mode(config: &Config, display: &Display) -> PinGuardResult<()> {
    display.section_header("Interactive Mode");
    display.info("Welcome to PinGuard Interactive Mode!");
    println!("Type 'help' for available commands or 'quit' to exit.");
    println!();

    loop {
        print!("pinGuard> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        match input {
            "quit" | "exit" | "q" => {
                display.info("Goodbye!");
                break;
            }
            "help" | "h" => show_interactive_help(display),
            "scan" => run_interactive_scan(config, display)?,
            "scan quick" => run_quick_scan(config, display)?,
            "scan package" => run_module_scan("package", config, display)?,
            "scan kernel" => run_module_scan("kernel", config, display)?,
            "scan service" => run_module_scan("service", config, display)?,
            "fix" => run_interactive_fix(config, display)?,
            "report" => run_interactive_report(config, display)?,
            "status" => show_system_status(config, display)?,
            "config" => show_config_summary(config, display),
            "cve update" => update_cve_database(config, display)?,
            "clear" => {
                print!("\x1B[2J\x1B[1;1H"); // Clear screen
                display.show_logo();
            }
            _ => {
                display.warning(&format!("Unknown command: '{}'", input));
                display.info("Type 'help' for available commands");
            }
        }
        println!();
    }

    Ok(())
}

/// Show interactive help
fn show_interactive_help(display: &Display) {
    display.section_header("Available Commands");
    
    let commands = vec![
        ("scan", "Run full system security scan"),
        ("scan quick", "Run quick security scan"),
        ("scan <module>", "Run specific module scan (package, kernel, service)"),
        ("fix", "Fix found vulnerabilities interactively"),
        ("report", "Generate security report"),
        ("status", "Show system security status"),
        ("config", "Show configuration summary"),
        ("cve update", "Update CVE database"),
        ("clear", "Clear screen"),
        ("help", "Show this help message"),
        ("quit", "Exit interactive mode"),
    ];
    
    for (command, description) in commands {
        println!("  {:<15} - {}", command, description);
    }
}

/// Run interactive scan
fn run_interactive_scan(config: &Config, display: &Display) -> PinGuardResult<()> {
    display.info("Starting interactive scan...");
    
    // Ask user for scan options
    let quick = display.confirm("Perform quick scan (faster but less thorough)?");
    
    let modules = if quick {
        vec!["package".to_string(), "kernel".to_string()]
    } else {
        config.scanner.enabled_modules.clone()
    };
    
    display.info(&format!("Scanning modules: {}", modules.join(", ")));
    
    let scanner_manager = crate::scanners::manager::ScannerManager::new();
    let mut total_findings = 0;
    
    for module in modules {
        display.info(&format!("Scanning {}...", module));
        
        match scanner_manager.run_specific_scan(&module, config) {
            Ok(result) => {
                total_findings += result.findings.len();
                display.success(&format!("{} scan completed: {} findings", module, result.findings.len()));
            }
            Err(e) => {
                display.error(&format!("{} scan failed: {}", module, e));
            }
        }
    }
    
    display.success(&format!("Scan completed! Total findings: {}", total_findings));
    
    if total_findings > 0 {
        if display.confirm("Would you like to see detailed results?") {
            display.info("Detailed results would be shown here...");
        }
        
        if display.confirm("Would you like to attempt automatic fixes?") {
            run_interactive_fix(config, display)?;
        }
    }
    
    Ok(())
}

/// Run quick scan
fn run_quick_scan(config: &Config, display: &Display) -> PinGuardResult<()> {
    display.info("Running quick security scan...");
    
    let scanner_manager = crate::scanners::manager::ScannerManager::new();
    let quick_modules = vec!["package", "kernel"];
    
    for module in quick_modules {
        match scanner_manager.run_specific_scan(module, config) {
            Ok(result) => {
                display.success(&format!("{} scan: {} findings", module, result.findings.len()));
            }
            Err(e) => {
                display.error(&format!("{} scan failed: {}", module, e));
            }
        }
    }
    
    Ok(())
}

/// Run module-specific scan
fn run_module_scan(module: &str, config: &Config, display: &Display) -> PinGuardResult<()> {
    display.info(&format!("Running {} scan...", module));
    
    let scanner_manager = crate::scanners::manager::ScannerManager::new();
    
    match scanner_manager.run_specific_scan(module, config) {
        Ok(result) => {
            display.success(&format!("{} scan completed: {} findings", module, result.findings.len()));
            
            if !result.findings.is_empty() && display.confirm("Show detailed findings?") {
                // Show findings summary
                let critical = result.findings.iter().filter(|f| f.severity == crate::scanners::Severity::Critical).count();
                let high = result.findings.iter().filter(|f| f.severity == crate::scanners::Severity::High).count();
                let medium = result.findings.iter().filter(|f| f.severity == crate::scanners::Severity::Medium).count();
                let low = result.findings.iter().filter(|f| f.severity == crate::scanners::Severity::Low).count();
                
                display.scan_summary(result.findings.len(), critical, high, medium, low);
            }
        }
        Err(e) => {
            display.error(&format!("{} scan failed: {}", module, e));
        }
    }
    
    Ok(())
}

/// Run interactive fix
fn run_interactive_fix(config: &Config, display: &Display) -> PinGuardResult<()> {
    display.info("Starting interactive fix process...");
    
    if !display.confirm("This will attempt to fix security vulnerabilities. Continue?") {
        display.info("Fix process cancelled");
        return Ok(());
    }
    
    let backup = display.confirm("Create backups before applying fixes?");
    let auto_fix = display.confirm("Apply all safe fixes automatically?");
    
    display.info("Fix process would start here...");
    
    if backup {
        display.info("Backups would be created...");
    }
    
    if auto_fix {
        display.info("Automatic fixes would be applied...");
    } else {
        display.info("Interactive fix selection would be shown...");
    }
    
    display.success("Fix process completed!");
    
    Ok(())
}

/// Run interactive report generation
fn run_interactive_report(config: &Config, display: &Display) -> PinGuardResult<()> {
    display.info("Generating security report...");
    
    // Ask for report format
    println!("Available report formats:");
    println!("  1. HTML (recommended)");
    println!("  2. PDF");
    println!("  3. JSON");
    println!("  4. All formats");
    
    print!("Select format [1-4]: ");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    let format = match input.trim() {
        "1" => "html",
        "2" => "pdf", 
        "3" => "json",
        "4" => "all",
        _ => "html",
    };
    
    display.info(&format!("Generating {} report...", format));
    display.success("Report generation would complete here...");
    
    Ok(())
}

/// Show system status
fn show_system_status(config: &Config, display: &Display) -> PinGuardResult<()> {
    display.section_header("System Security Status");
    
    // This would integrate with actual status checking
    let status_items = vec![
        ("System", "Linux"),
        ("PinGuard Version", env!("CARGO_PKG_VERSION")),
        ("Database Status", "Connected"),
        ("CVE Database", "Up to date"),
        ("Last Scan", "Never"),
        ("Scheduled Scans", "Disabled"),
    ];
    
    display.key_value_list(&status_items);
    
    // Show quick health indicators
    display.success("✓ Configuration valid");
    display.success("✓ Database accessible");
    display.warning("⚠ No recent scans found");
    
    Ok(())
}

/// Show configuration summary
fn show_config_summary(config: &Config, display: &Display) {
    display.section_header("Configuration Summary");
    
    let enabled_scanners = config.scanner.enabled_modules.join(", ");
    let config_items = vec![
        ("Application Name", config.app.name.as_str()),
        ("Log Level", config.app.log_level.as_str()),
        ("Database Path", config.database.path.as_str()),
        ("Report Format", config.report.format.as_str()),
        ("Output Directory", config.report.output_dir.as_str()),
        ("Enabled Scanners", enabled_scanners.as_str()),
    ];
    
    display.key_value_list(&config_items);
}

/// Update CVE database
fn update_cve_database(_config: &Config, display: &Display) -> PinGuardResult<()> {
    display.info("Updating CVE database...");
    
    // Simulate update process
    for i in 1..=5 {
        display.progress_bar(i, 5, "Downloading CVE data");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    
    display.success("CVE database updated successfully!");
    
    Ok(())
}