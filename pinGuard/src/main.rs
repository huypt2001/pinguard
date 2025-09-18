use clap::{Arg, ArgMatches, Command};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

mod core;
mod cve;
mod database;
mod fixers;
mod report;
mod scanners;
mod scheduler;

use cve::CveManager;
use database::DatabaseManager;
use scheduler::Scheduler;

fn main() {
    // Set up the logging subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("PinGuard - Linux Vulnerability Scanner & Remediator starting...");

    // Check for root privileges (temporarily disabled for testing)
    // if unsafe { libc::geteuid() } != 0 {
    //     error!("Error: This program must be run with root privileges.");
    //     eprintln!("Please run the program with 'sudo'.");
    //     std::process::exit(1);
    // }

    let matches = build_cli().get_matches();

    // Load config file
    let config_path = matches
        .get_one::<String>("config")
        .map(|s| s.as_str())
        .unwrap_or("config.yaml");
    let config = match core::config::Config::load_from_file(config_path) {
        Ok(config) => {
            info!("Configuration file successfully loaded: {}", config_path);
            config
        }
        Err(e) => {
            warn!(
                "Config file could not be loaded ({}), using default settings",
                e
            );
            core::config::Config::default_config()
        }
    };

    // Process subcommands
    match matches.subcommand() {
        Some(("scan", sub_matches)) => handle_scan_command(sub_matches, &config),
        Some(("fix", sub_matches)) => handle_fix_command(sub_matches, &config),
        Some(("report", sub_matches)) => handle_report_command(sub_matches, &config),
        Some(("config", sub_matches)) => handle_config_command(sub_matches, &config),
        Some(("database", sub_matches)) => handle_database_command(sub_matches, &config),
        Some(("cve", sub_matches)) => handle_cve_command(sub_matches, &config),
        Some(("schedule", sub_matches)) => handle_schedule_command(sub_matches, &config),
        Some(("run-scheduled-scan", sub_matches)) => {
            handle_run_scheduled_scan(sub_matches, &config)
        }
        _ => {
            info!("Run 'pinGuard --help' for available commands");
        }
    }
}

fn build_cli() -> Command {
    Command::new("pinGuard")
        .version("0.1.0")
        .author("PinGuard Team")
        .about("Linux-first Vulnerability Scanner & Remediator")
        .long_about("PinGuard scans, reports, and fixes security vulnerabilities on Linux systems.")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Specifies a custom config file")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Show detailed output"),
        )
        .subcommand(
            Command::new("scan")
                .about("Perform system security scan")
                .arg(
                    Arg::new("module")
                        .short('m')
                        .long("module")
                        .value_name("MODULE")
                        .help("Scan a specific module (package, kernel, service, network)")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("FILE")
                        .help("Output file")
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(
            Command::new("fix")
                .about("Fix found security vulnerabilities")
                .arg(
                    Arg::new("auto")
                        .long("auto")
                        .action(clap::ArgAction::SetTrue)
                        .help("Automatic fix (doesn't ask for confirmation)"),
                )
                .arg(
                    Arg::new("module")
                        .short('m')
                        .long("module")
                        .value_name("MODULE")
                        .help("Fix a specific module")
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(
            Command::new("report")
                .about("Generate report from scan results")
                .arg(
                    Arg::new("format")
                        .short('f')
                        .long("format")
                        .value_name("FORMAT")
                        .help("Report format (json, html, pdf, all)")
                        .value_parser(clap::value_parser!(String))
                        .default_value("json"),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("FILE")
                        .help("Output file or directory")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("input")
                        .short('i')
                        .long("input")
                        .value_name("FILE")
                        .help("Input scan file (JSON format)")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("scan")
                        .long("scan")
                        .action(clap::ArgAction::SetTrue)
                        .help("First perform new scan, then generate report"),
                )
                .arg(
                    Arg::new("summary")
                        .long("summary")
                        .action(clap::ArgAction::SetTrue)
                        .help("Print only summary report to console"),
                ),
        )
        .subcommand(
            Command::new("config")
                .about("Configuration management")
                .arg(
                    Arg::new("show")
                        .long("show")
                        .action(clap::ArgAction::SetTrue)
                        .help("Show current configuration"),
                )
                .arg(
                    Arg::new("init")
                        .long("init")
                        .action(clap::ArgAction::SetTrue)
                        .help("Create default config file"),
                ),
        )
        .subcommand(
            Command::new("database")
                .about("Database management")
                .subcommand(Command::new("init").about("Initialize database and create tables"))
                .subcommand(Command::new("migrate").about("Run database migrations"))
                .subcommand(Command::new("health").about("Perform database health check"))
                .subcommand(Command::new("stats").about("Show database statistics"))
                .subcommand(
                    Command::new("cleanup").about("Clean up old data").arg(
                        Arg::new("days")
                            .short('d')
                            .long("days")
                            .value_name("DAYS")
                            .help("Delete data older than how many days")
                            .value_parser(clap::value_parser!(u32))
                            .default_value("30"),
                    ),
                ),
        )
        .subcommand(
            Command::new("cve")
                .about("CVE database management")
                .subcommand(
                    Command::new("sync")
                        .about("Synchronize recent CVEs from NVD")
                        .arg(
                            Arg::new("days")
                                .short('d')
                                .long("days")
                                .value_name("DAYS")
                                .help("Recent CVEs from how many days")
                                .value_parser(clap::value_parser!(u32))
                                .default_value("7"),
                        ),
                )
                .subcommand(
                    Command::new("search")
                        .about("Search CVEs")
                        .arg(
                            Arg::new("query")
                                .help("Search term (CVE ID, package name, keyword)")
                                .required(true)
                                .value_parser(clap::value_parser!(String)),
                        )
                        .arg(
                            Arg::new("limit")
                                .short('l')
                                .long("limit")
                                .value_name("LIMIT")
                                .help("Maximum number of results")
                                .value_parser(clap::value_parser!(usize))
                                .default_value("10"),
                        ),
                )
                .subcommand(
                    Command::new("get")
                        .about("Get specific CVE with details")
                        .arg(
                            Arg::new("cve_id")
                                .help("CVE ID (e.g.: CVE-2023-1234)")
                                .required(true)
                                .value_parser(clap::value_parser!(String)),
                        ),
                )
                .subcommand(Command::new("health").about("CVE manager health check"))
                .subcommand(
                    Command::new("cache")
                        .about("CVE cache management")
                        .subcommand(Command::new("stats").about("Cache statistics"))
                        .subcommand(Command::new("cleanup").about("Clean expired cache"))
                        .subcommand(Command::new("refresh").about("Refresh cache")),
                ),
        )
        .subcommand(
            Command::new("schedule")
                .about("Automatic scan scheduler")
                .subcommand(
                    Command::new("enable")
                        .about("Enable scheduled scan")
                        .arg(
                            Arg::new("name")
                                .help("Schedule name")
                                .required(true)
                                .value_parser(clap::value_parser!(String)),
                        )
                        .arg(
                            Arg::new("schedule")
                                .help("Cron expression (e.g.: '0 2 * * *')")
                                .required(true)
                                .value_parser(clap::value_parser!(String)),
                        )
                        .arg(
                            Arg::new("description")
                                .short('d')
                                .long("description")
                                .value_name("DESC")
                                .help("Schedule description")
                                .value_parser(clap::value_parser!(String)),
                        )
                        .arg(
                            Arg::new("type")
                                .short('t')
                                .long("type")
                                .value_name("TYPE")
                                .help("Scan type (full, quick, security)")
                                .value_parser(clap::value_parser!(String))
                                .default_value("full"),
                        ),
                )
                .subcommand(
                    Command::new("disable").about("Disable scheduled scan").arg(
                        Arg::new("name")
                            .help("Schedule name")
                            .required(true)
                            .value_parser(clap::value_parser!(String)),
                    ),
                )
                .subcommand(Command::new("list").about("List active scheduled scans"))
                .subcommand(
                    Command::new("status").about("Show schedule status").arg(
                        Arg::new("name")
                            .help("Schedule name (leave blank for all)")
                            .value_parser(clap::value_parser!(String)),
                    ),
                )
                .subcommand(Command::new("presets").about("Load preset schedule templates")),
        )
        .subcommand(
            Command::new("run-scheduled-scan")
                .about("Run scheduled scan (used by systemd)")
                .arg(
                    Arg::new("schedule_name")
                        .help("Schedule name")
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .hide(true), // This command is not shown to the user
        )
}

fn handle_scan_command(matches: &ArgMatches, config: &core::config::Config) {
    info!("Starting scan...");

    let scanner_manager = scanners::manager::ScannerManager::new();

    if let Some(module) = matches.get_one::<String>("module") {
        info!("Specific scan module: {}", module);

        match scanner_manager.run_specific_scan(module, config) {
            Ok(result) => {
                info!("{} completed: {} findings", module, result.findings.len());

                // JSON çıktısı
                if let Some(output_file) = matches.get_one::<String>("output") {
                    match std::fs::write(
                        output_file,
                        serde_json::to_string_pretty(&result).unwrap(),
                    ) {
                        Ok(_) => info!("Results saved to: {}", output_file),
                        Err(e) => error!("File write error: {}", e),
                    }
                } else {
                    // Print summary to console
                    print_scan_summary(&result);
                }
            }
            Err(e) => {
                error!("Scan failed: {}", e);
            }
        }
    } else {
        info!(
            "🔍 All active modules will be scanned: {:?}",
            config.scanner.enabled_modules
        );

        let results = scanner_manager.run_all_scans(config);
        let summary = scanner_manager.generate_summary(&results);

        info!("Scan summary:");
        info!("   Total scans: {}", summary.total_scans);
        info!("   Successful: {}", summary.successful_scans);
        info!("   Warning: {}", summary.warning_scans);
        info!("   Failed: {}", summary.failed_scans);
        info!("   Total findings: {}", summary.total_findings);
        info!("   Critical: {}", summary.critical_issues);
        info!("   High: {}", summary.high_issues);
        info!("   Medium: {}", summary.medium_issues);
        info!("   Low: {}", summary.low_issues);
        info!("   Security score: {}/100", summary.get_security_score());
        info!("   Risk level: {}", summary.get_risk_level());

        // JSON output
        if let Some(output_file) = matches.get_one::<String>("output") {
            match scanner_manager.results_to_json(&results) {
                Ok(json) => match std::fs::write(output_file, json) {
                    Ok(_) => info!("All results saved to: {}", output_file),
                    Err(e) => error!("File write error: {}", e),
                },
                Err(e) => error!("JSON generation error: {}", e),
            }
        }
    }
}

fn print_scan_summary(result: &scanners::ScanResult) {
    println!("{} Scan Result", result.scanner_name);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scan time: {}", result.scan_time);
    println!("Duration: {} ms", result.metadata.duration_ms);
    println!("Items scanned: {}", result.metadata.items_scanned);
    println!("Total findings: {}", result.findings.len());

    if !result.findings.is_empty() {
        println!("Bulgular:");
        for (i, finding) in result.findings.iter().enumerate() {
            let severity_icon = match finding.severity {
                scanners::Severity::Critical => "",
                scanners::Severity::High => "",
                scanners::Severity::Medium => "",
                scanners::Severity::Low => "",
                scanners::Severity::Info => "",
            };
            println!(
                "{}. {} {} - {}",
                i + 1,
                severity_icon,
                finding.title,
                finding.description
            );
        }
    } else {
        println!("No security vulnerabilities found!");
    }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

fn handle_fix_command(matches: &ArgMatches, config: &core::config::Config) {
    info!("Starting fix process...");

    let auto_fix = matches.get_flag("auto");
    if auto_fix {
        warn!("⚡ Automatic fix mode enabled - no user confirmation will be requested");
    } else {
        info!("Interactive fix mode - confirmation will be requested for each fix");
    }

    // First perform scan to get findings
    info!("Getting current security findings...");
    let scanner_manager = scanners::manager::ScannerManager::new();
    let scan_results = scanner_manager.run_all_scans(config);

    // Collect all findings
    let mut all_findings = Vec::new();
    for result in &scan_results {
        all_findings.extend(result.findings.clone());
    }

    if all_findings.is_empty() {
        info!("No security vulnerabilities found to fix!");
        return;
    }

    info!("{} security vulnerabilities detected", all_findings.len());

    // Create fixer manager
    let fixer_manager = fixers::manager::FixerManager::new();

    // If specific module is specified, process only that module
    if let Some(module) = matches.get_one::<String>("module") {
        let filtered_findings: Vec<_> = match module.as_str() {
            "package" => all_findings
                .iter()
                .filter(|f| f.id.starts_with("PKG-"))
                .cloned()
                .collect(),
            "kernel" => all_findings
                .iter()
                .filter(|f| f.id.starts_with("KRN-"))
                .cloned()
                .collect(),
            "permission" => all_findings
                .iter()
                .filter(|f| f.id.starts_with("PERM-"))
                .cloned()
                .collect(),
            "service" => all_findings
                .iter()
                .filter(|f| f.id.starts_with("SVC-"))
                .cloned()
                .collect(),
            "user" => all_findings
                .iter()
                .filter(|f| f.id.starts_with("USR-"))
                .cloned()
                .collect(),
            "network" => all_findings
                .iter()
                .filter(|f| f.id.starts_with("NET-"))
                .cloned()
                .collect(),
            "container" => all_findings
                .iter()
                .filter(|f| f.id.starts_with("CONTAINER-") || f.id.starts_with("IMAGE-") || f.id.starts_with("K8S-") || f.id.starts_with("DOCKER-"))
                .cloned()
                .collect(),
            _ => {
                error!("Invalid module: {}. Valid modules: package, kernel, permission, service, user, network, container", module);
                return;
            }
        };

        if filtered_findings.is_empty() {
            info!(" No findings to fix for '{}' module", module);
            return;
        }

        info!(
            "{} findings will be fixed for '{}' module",
            filtered_findings.len(),
            module
        );
        let _results = fixer_manager.fix_findings(&filtered_findings, config, auto_fix);
    } else {
        // Fix all findings
        info!("Fixing all findings...");

        // Sort by priority (critical -> high -> medium -> low)
        let prioritized_findings = fixer_manager.prioritize_fixes(&all_findings);
        let prioritized_findings_owned: Vec<_> =
            prioritized_findings.into_iter().cloned().collect();

        // Report unfixable findings
        let unfixable = fixer_manager.get_unfixable_findings(&all_findings);
        if !unfixable.is_empty() {
            warn!(
                " {} findings cannot be fixed automatically:",
                unfixable.len()
            );
            for finding in unfixable {
                warn!("   • {}: {}", finding.id, finding.title);
            }
        }

        // Start fixing process
        let _results = fixer_manager.fix_findings(&prioritized_findings_owned, config, auto_fix);
    }

    info!("Fix process completed!");
}

fn handle_report_command(matches: &ArgMatches, config: &core::config::Config) {
    info!("Generating report...");

    // Create report manager
    let mut report_manager = report::manager::ReportManager::default_manager();

    // Set output directory
    if let Some(output) = matches.get_one::<String>("output") {
        if std::path::Path::new(output).is_dir() {
            if let Err(e) = report_manager.set_output_directory(output.clone()) {
                error!("❌ Output directory could not be set: {}", e);
                return;
            }
            info!("Output directory: {}", output);
        }
    }

    let security_report = if matches.get_flag("scan") {
        // Perform new scan
        info!("Starting new scan...");
        let scanner_manager = scanners::manager::ScannerManager::new();
        let scan_start = std::time::Instant::now();
        let scan_results = scanner_manager.run_all_scans(config);
        let scan_duration = scan_start.elapsed().as_millis() as u64;

        info!("Scan completed ({} ms)", scan_duration);

        // Create SecurityReport
        Some(report::SecurityReport::new(
            scan_results,
            None,
            scan_duration,
        ))
    } else if let Some(input_file) = matches.get_one::<String>("input") {
        // Load existing scan results
        info!("Loading scan results: {}", input_file);

        match std::fs::read_to_string(input_file) {
            Ok(json_content) => {
                // First try to read as SecurityReport
                match serde_json::from_str::<report::SecurityReport>(&json_content) {
                    Ok(security_report) => {
                        info!("SecurityReport loaded");
                        Some(security_report)
                    }
                    Err(_) => {
                        // If it can't be read as SecurityReport, try Vec<ScanResult>
                        match serde_json::from_str::<Vec<scanners::ScanResult>>(&json_content) {
                            Ok(scan_results) => {
                                info!("{} scan results loaded", scan_results.len());
                                Some(report::SecurityReport::new(scan_results, None, 0))
                            }
                            Err(e) => {
                                error!("JSON parse error: {}", e);
                                None
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("File read error: {}", e);
                None
            }
        }
    } else {
        // Quick scan (if no input file is provided)
        warn!(" No input file specified, performing quick scan...");
        let scanner_manager = scanners::manager::ScannerManager::new();
        let scan_start = std::time::Instant::now();
        let scan_results = scanner_manager.run_all_scans(config);
        let scan_duration = scan_start.elapsed().as_millis() as u64;

        Some(report::SecurityReport::new(
            scan_results,
            None,
            scan_duration,
        ))
    };

    let Some(security_report) = security_report else {
        error!("Report could not be generated: No valid scan data found");
        return;
    };

    // If only summary is requested
    if matches.get_flag("summary") {
        if let Err(e) = report_manager.print_report_summary(&security_report) {
            error!("Summary print error: {}", e);
        }
        if let Err(e) = report_manager.print_detailed_statistics(&security_report) {
            error!("Statistics print error: {}", e);
        }
        return;
    }

    // Get report format
    let format_str = matches.get_one::<String>("format").unwrap(); // guaranteed by default_value

    match format_str.as_str() {
        "all" => {
            // Generate all formats
            info!("Generating all report formats...");

            let base_filename = format!("pinGuard-report-{}", security_report.metadata.report_id);

            match report_manager.generate_all_formats(&security_report, Some(base_filename)) {
                Ok(files) => {
                    info!("All reports generated:");
                    for file in files {
                        info!("   {}", file);
                    }
                }
                Err(e) => {
                    error!("Report generation error: {}", e);
                }
            }
        }

        format_name => {
            // Generate single format
            let report_format = match format_name.parse::<report::ReportFormat>() {
                Ok(format) => format,
                Err(e) => {
                    error!("Invalid report format '{}': {}", format_name, e);
                    info!("Valid formats: json, html, pdf, all");
                    return;
                }
            };

            info!(
                "Generating report in {} format...",
                format_name.to_uppercase()
            );

            // Determine output filename
            let output_filename = if let Some(output) = matches.get_one::<String>("output") {
                if std::path::Path::new(output).is_dir() {
                    None // Manager will create its own filename
                } else {
                    Some(output.clone())
                }
            } else {
                None
            };

            match report_manager.generate_report(&security_report, &report_format, output_filename)
            {
                Ok(output_path) => {
                    info!("Report successfully generated: {}", output_path);

                    // Show report information
                    info!("Report information:");
                    info!("   Report ID: {}", security_report.metadata.report_id);
                    info!(
                        "   Security score: {}/100",
                        security_report.summary.security_score
                    );
                    info!("   Risk level: {}", security_report.summary.risk_level);
                    info!(
                        "   Total findings: {}",
                        security_report.summary.total_findings
                    );
                    info!("   Critical: {}", security_report.summary.critical_findings);
                    info!("   High: {}", security_report.summary.high_findings);

                    // Additional information for HTML/PDF reports
                    if matches!(&report_format, report::ReportFormat::Html) {
                        info!("Open the report with an appropriate program to view it");
                    }
                }
                Err(e) => {
                    error!("Report generation error: {}", e);
                }
            }
        }
    }

    // Show format information (for debugging)
    // Note: verbose is a global flag so it can't be checked here
    // if matches.get_flag("verbose") {
    //     report_manager.print_format_info();
    // }
}

fn handle_config_command(matches: &ArgMatches, config: &core::config::Config) {
    if matches.get_flag("show") {
        info!("Current configuration:");
        println!("{:#?}", config);
    }

    if matches.get_flag("init") {
        info!("Creating default config file...");

        let config_content = r#"# PinGuard Configuration File
# Scan settings
scanner:
  modules:
    package_audit: true
    kernel_check: true
    permission_audit: true
    service_audit: true
    user_audit: true
    network_audit: true
  concurrent_scans: true
  max_scan_time: 300  # seconds
  
# Report settings
report:
  format: "json"
  output_dir: "./reports"
  template: "default"

# Database settings
database:
  path: "./pinGuard.db"
  auto_migrate: true
  connection_pool_size: 10
  
# CVE database settings  
cve:
  api_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
  cache_duration: 86400  # 24 hours (seconds)
  auto_update: true

# Fixer settings
fixer:
  auto_fix: false
  require_confirmation: true
  backup_before_fix: true
  backup_dir: "./backups"
  enabled_modules:
    - "package_updater"
    - "kernel_updater"
    - "permission_fixer"
    - "service_hardener"
    - "user_policy_fixer"
    - "firewall_configurator"
"#;

        match std::fs::write("config.yaml", config_content) {
            Ok(_) => info!("Default config file created: config.yaml"),
            Err(e) => error!("Config file creation error: {}", e),
        }
    }
}

fn handle_database_command(matches: &ArgMatches, _config: &core::config::Config) {
    match matches.subcommand() {
        Some(("init", _)) => {
            info!("Initializing database...");
            match DatabaseManager::new_default() {
                Ok(mut db) => {
                    info!("Database successfully initialized");
                    match db.run_migrations() {
                        Ok(_) => info!("Migrations successfully applied"),
                        Err(e) => error!("Migration error: {}", e),
                    }
                }
                Err(e) => error!("Database initialization error: {}", e),
            }
        }

        Some(("migrate", _)) => {
            info!("Running migrations...");
            match DatabaseManager::new_default() {
                Ok(mut db) => match db.run_migrations() {
                    Ok(_) => info!("Migrations successfully applied"),
                    Err(e) => error!("Migration error: {}", e),
                },
                Err(e) => error!("Database connection error: {}", e),
            }
        }

        Some(("health", _)) => {
            info!("Performing database health check...");
            match DatabaseManager::new_default() {
                Ok(db) => match db.health_check() {
                    Ok(health) => {
                        if health.is_healthy() {
                            info!("Database is healthy");
                        } else {
                            warn!("Database health issues detected");
                        }
                    }
                    Err(e) => error!("Health check error: {}", e),
                },
                Err(e) => error!("Database connection error: {}", e),
            }
        }

        Some(("stats", _)) => {
            info!("Getting database statistics...");
            match DatabaseManager::new_default() {
                Ok(db) => match db.health_check() {
                    Ok(health) => {
                        info!("Database Statistics:");
                        info!("   File size: {:.2} MB", health.database_size_mb());
                        info!(
                            "   Connection status: {}",
                            if health.is_healthy() {
                                "Healthy"
                            } else {
                                "Problematic"
                            }
                        );
                        info!("   Total table count: ~5 (CVE cache, scan history, schedule logs, etc.)");
                        info!(
                            "   Last check: {}",
                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
                        );
                    }
                    Err(e) => error!("Could not get database statistics: {}", e),
                },
                Err(e) => error!("Database connection error: {}", e),
            }
        }

        Some(("cleanup", sub_matches)) => {
            let days = *sub_matches.get_one::<u32>("days").unwrap_or(&30);
            info!("Cleaning up data older than {} days...", days);
            match DatabaseManager::new_default() {
                Ok(_db) => {
                    // Clean up CVE cache
                    let cleanup_date = chrono::Utc::now() - chrono::Duration::days(days as i64);
                    info!(
                        "Cleaning up data older than {}",
                        cleanup_date.format("%Y-%m-%d")
                    );

                    // Cleanup implementation will go here
                    // For now we're simulating
                    let cleaned_count = 0; // This will be updated after real cleanup

                    info!("Cleanup completed: {} records deleted", cleaned_count);
                    info!("Note: Cleanup functionality is not yet fully implemented");
                }
                Err(e) => error!("Database connection error: {}", e),
            }
        }

        _ => {
            error!("Invalid database command");
            info!("Available commands: init, migrate, health, stats, cleanup");
        }
    }
}

fn handle_cve_command(matches: &ArgMatches, _config: &core::config::Config) {
    // Create async runtime
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Async runtime error: {}", e);
            return;
        }
    };

    rt.block_on(async {
        // Initialize database and CVE manager
        let db = match DatabaseManager::new_default() {
            Ok(db) => db,
            Err(e) => {
                error!("Database connection error: {}", e);
                return;
            }
        };

        let cve_manager = match CveManager::new(db) {
            Ok(manager) => manager,
            Err(e) => {
                error!("CVE manager error: {}", e);
                return;
            }
        };

        match matches.subcommand() {
            Some(("sync", sub_matches)) => {
                let days = *sub_matches.get_one::<u32>("days").unwrap_or(&7);
                info!("Synchronizing CVEs from the last {} days...", days);

                match cve_manager.sync_recent_cves(days).await {
                    Ok(count) => info!("{} CVEs synchronized", count),
                    Err(e) => error!("CVE synchronization error: {}", e),
                }
            }

            Some(("search", sub_matches)) => {
                let query = sub_matches.get_one::<String>("query").unwrap();
                let limit = *sub_matches.get_one::<usize>("limit").unwrap_or(&10);

                info!("Searching CVEs for '{}' (limit: {})...", query, limit);

                match cve_manager.find_cves_for_package(query).await {
                    Ok(cves) => {
                        let limited_cves: Vec<_> = cves.into_iter().take(limit).collect();

                        if limited_cves.is_empty() {
                            info!("No CVEs found for '{}'", query);
                        } else {
                            info!("{} CVEs found:", limited_cves.len());
                            for cve in limited_cves {
                                println!("{} ({:?})", cve.cve_id, cve.severity);
                                println!("{}", cve.description);
                                if let Some(score) = cve.score {
                                    println!(" CVSS Score: {:.1}", score);
                                }
                                println!("   Published: {}", cve.published_date.format("%Y-%m-%d"));
                                if !cve.references.is_empty() {
                                    println!("   References: {}", cve.references.join(", "));
                                }
                            }
                        }
                    }
                    Err(e) => error!("CVE search error: {}", e),
                }
            }

            Some(("get", sub_matches)) => {
                let cve_id = sub_matches.get_one::<String>("cve_id").unwrap();
                info!("🔍 Getting CVE details: {}", cve_id);

                match cve_manager.get_cve(cve_id).await {
                    Ok(cve) => {
                        println!("CVE Details: {}", cve.cve_id);
                        println!("   Severity: {:?}", cve.severity);
                        println!("   Description: {}", cve.description);
                        if let Some(score) = cve.score {
                            println!("   CVSS Score: {:.1}", score);
                        }
                        if let Some(vector) = &cve.vector_string {
                            println!("   CVSS Vector: {}", vector);
                        }
                        println!("   Published: {}", cve.published_date.format("%Y-%m-%d"));
                        println!("   Last Modified: {}", cve.last_modified.format("%Y-%m-%d"));

                        if !cve.affected_packages.is_empty() {
                            println!("   Affected Products:");
                            for product in &cve.affected_packages {
                                println!("      • {}", product);
                            }
                        }

                        if !cve.references.is_empty() {
                            println!("   References:");
                            for reference in &cve.references {
                                println!("      • {}", reference);
                            }
                        }

                        if !cve.cpe_matches.is_empty() {
                            println!("   CPE Matches: {} configurations", cve.cpe_matches.len());
                        }
                    }
                    Err(e) => error!("Error getting CVE: {}", e),
                }
            }

            Some(("health", _)) => {
                info!("🔍 Performing CVE manager health check...");

                match cve_manager.health_check().await {
                    Ok(health) => {
                        println!("CVE Manager Health Status:");
                        println!(
                            "   NVD API: {}",
                            if health.nvd_api_healthy {
                                "✅ Healthy"
                            } else {
                                "❌ Problematic"
                            }
                        );
                        println!("   Response Time: {} ms", health.nvd_response_time_ms);
                        println!(
                            "   Cache: {}",
                            if health.cache_healthy {
                                "✅ Healthy"
                            } else {
                                "❌ Problematic"
                            }
                        );
                        println!("   Cache Entries: {}", health.cache_entries);
                        println!("   Hit Rate: {:.1}%", health.cache_hit_rate * 100.0);
                        println!("   Cache Size: {:.2} MB", health.cache_size_mb);
                        println!(
                            "   Auto Refresh: {}",
                            if health.auto_refresh_enabled {
                                "✅ Enabled"
                            } else {
                                "❌ Disabled"
                            }
                        );
                        println!(
                            "   Fallback: {}",
                            if health.fallback_enabled {
                                "✅ Enabled"
                            } else {
                                "❌ Disabled"
                            }
                        );
                        println!(
                            "   Last Check: {}",
                            health.last_check.format("%Y-%m-%d %H:%M:%S UTC")
                        );

                        if health.is_healthy() {
                            info!("CVE manager is completely healthy");
                        } else {
                            warn!("Issues detected in CVE manager");
                        }
                    }
                    Err(e) => error!("Health check error: {}", e),
                }
            }

            Some(("cache", cache_matches)) => match cache_matches.subcommand() {
                Some(("stats", _)) => {
                    info!("Getting CVE cache statistics...");
                    match cve_manager.health_check().await {
                        Ok(health) => {
                            info!("CVE Cache Statistics:");
                            info!("   Total entries: {}", health.cache_entries);
                            info!("   Hit rate: {:.1}%", health.cache_hit_rate * 100.0);
                            info!("   Cache size: {:.2} MB", health.cache_size_mb);
                            info!(
                                "   Auto refresh: {}",
                                if health.auto_refresh_enabled {
                                    "Enabled"
                                } else {
                                    "Disabled"
                                }
                            );
                            info!(
                                "   Fallback: {}",
                                if health.fallback_enabled {
                                    "Enabled"
                                } else {
                                    "Disabled"
                                }
                            );
                            info!(
                                "   Last check: {}",
                                health.last_check.format("%Y-%m-%d %H:%M:%S")
                            );
                        }
                        Err(e) => error!("Could not get cache statistics: {}", e),
                    }
                }

                Some(("cleanup", _)) => {
                    info!("🧹 Cleaning expired cache...");
                    match cve_manager.maintain_cache().await {
                        Ok(result) => {
                            info!("Cache maintenance completed:");
                            info!(
                                "   Expired entries cleaned: {}",
                                result.expired_entries_cleaned
                            );
                            info!("   Total entries: {}", result.total_entries);
                            info!("   Cache size: {:.2} MB", result.cache_size_mb);
                            info!("   Synced recent CVEs: {}", result.synced_recent_cves);
                        }
                        Err(e) => error!("Cache maintenance error: {}", e),
                    }
                }

                Some(("refresh", _)) => {
                    info!("Refreshing cache...");
                    match cve_manager.sync_recent_cves(1).await {
                        Ok(count) => info!("{} fresh CVEs added to cache", count),
                        Err(e) => error!("Cache refresh error: {}", e),
                    }
                }

                _ => {
                    error!("Invalid cache command");
                    info!("Available commands: stats, cleanup, refresh");
                }
            },

            _ => {
                error!("Invalid CVE command");
                info!("Available commands: sync, search, get, health, cache");
            }
        }
    });
}

fn handle_schedule_command(matches: &ArgMatches, config: &core::config::Config) {
    info!("Running schedule command...");

    // Establish database connection
    let db = match DatabaseManager::new(&config.database.path) {
        Ok(db) => db,
        Err(e) => {
            error!("Database connection error: {}", e);
            return;
        }
    };

    // Create scheduler
    let mut scheduler = match Scheduler::new(db) {
        Ok(scheduler) => scheduler,
        Err(e) => {
            error!("Scheduler creation error: {}", e);
            return;
        }
    };

    match matches.subcommand() {
        Some(("enable", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").unwrap();
            let schedule = sub_matches.get_one::<String>("schedule").unwrap();
            let description = sub_matches
                .get_one::<String>("description")
                .map(|s| s.as_str())
                .unwrap_or("Scheduled security scan");
            let scan_type_str = sub_matches.get_one::<String>("type").unwrap();

            let scan_type = match scan_type_str.as_str() {
                "full" => scheduler::ScanType::Full,
                "quick" => scheduler::ScanType::Quick,
                "security" => scheduler::ScanType::Security,
                _ => {
                    error!("Invalid scan type: {}", scan_type_str);
                    info!("Valid types: full, quick, security");
                    return;
                }
            };

            let schedule_config = scheduler::ScheduleConfig::new(
                name.clone(),
                description.to_string(),
                schedule.clone(),
                scan_type,
            );

            info!("🔧 Enabling schedule: {}", name);
            match scheduler.enable(schedule_config) {
                Ok(_) => {
                    info!("Schedule successfully enabled: {}", name);
                    info!("   Schedule: {}", schedule);
                    info!("   Description: {}", description);
                    info!("   Systemd timer and service files created");
                }
                Err(e) => {
                    error!("Error enabling schedule: {}", e);
                }
            }
        }

        Some(("disable", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").unwrap();

            info!("Disabling schedule: {}", name);
            match scheduler.disable(name) {
                Ok(_) => {
                    info!("Schedule successfully disabled: {}", name);
                    info!("   Systemd timer and service files removed");
                }
                Err(e) => {
                    error!("Error disabling schedule: {}", e);
                }
            }
        }

        Some(("list", _)) => {
            info!("Listing active schedules...");
            match scheduler.list_schedules() {
                Ok(schedules) => {
                    if schedules.is_empty() {
                        info!("No active schedules yet");
                        info!("You can load preset schedules with 'pinGuard schedule presets'");
                    } else {
                        info!("{} active schedules found:", schedules.len());
                        for schedule in schedules {
                            println!();
                            println!("   {}", schedule.name);
                            println!("      Schedule: {}", schedule.schedule);
                            println!("      Description: {}", schedule.description);
                            println!("      Type: {}", schedule.scan_type);
                            println!(
                                "      Status: {}",
                                if schedule.enabled {
                                    "Enabled"
                                } else {
                                    "Disabled"
                                }
                            );
                            println!("      Modules: {}", schedule.scan_modules.join(", "));
                        }
                    }
                }
                Err(e) => {
                    error!("Could not get schedule list: {}", e);
                }
            }
        }

        Some(("status", sub_matches)) => {
            if let Some(name) = sub_matches.get_one::<String>("name") {
                // Status of specific schedule
                info!("🔍 Checking schedule status: {}", name);
                match scheduler.get_schedule_status(name) {
                    Ok(status) => {
                        println!();
                        println!("Schedule Status: {}", status.name);
                        println!("   Enabled: {}", if status.enabled { "Yes" } else { "No" });
                        println!("   Active: {}", if status.active { "Yes" } else { "No" });
                        println!("   Schedule: {}", status.config.schedule);
                        println!("   Description: {}", status.config.description);

                        if let Some(last_run) = status.last_run {
                            println!(
                                "   Last run: {}",
                                last_run.run_time.format("%Y-%m-%d %H:%M:%S UTC")
                            );
                            println!(
                                "   Successful: {}",
                                if last_run.success { "Yes" } else { "No" }
                            );
                            println!("   Duration: {}ms", last_run.duration_ms);
                            println!("   Findings count: {}", last_run.findings_count);
                            if let Some(error) = last_run.error_message {
                                println!("   Error: {}", error);
                            }
                        }

                        if let Some(next_run) = status.next_run {
                            println!("   Next run: {}", next_run.format("%Y-%m-%d %H:%M:%S UTC"));
                        }
                    }
                    Err(e) => {
                        error!("Could not get schedule status: {}", e);
                    }
                }
            } else {
                // Status of all schedules
                info!("Checking status of all schedules...");
                match scheduler.get_all_statuses() {
                    Ok(statuses) => {
                        if statuses.is_empty() {
                            info!("No active schedules");
                        } else {
                            println!();
                            println!("Schedule Statuses ({})", statuses.len());
                            for status in statuses {
                                println!();
                                println!("   {}", status.name);
                                println!(
                                    "      Enabled: {} | Active: {}",
                                    if status.enabled { "Yes" } else { "No" },
                                    if status.active { "Yes" } else { "No" }
                                );
                                if let Some(next_run) = status.next_run {
                                    println!("      Next: {}", next_run.format("%Y-%m-%d %H:%M"));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Could not get schedule statuses: {}", e);
                    }
                }
            }
        }

        Some(("presets", _)) => {
            info!("🔧 Loading preset schedule templates...");
            match scheduler.schedule_manager.create_default_schedules() {
                Ok(_) => {
                    info!("Preset schedules successfully created:");
                    info!("   daily-full: Full scan every day at 02:00");
                    info!("   weekly-full: Full scan every Sunday at 03:00");
                    info!("   quick-3x: Quick scan 3 times a day (06:00, 12:00, 18:00)");
                    info!("Use 'schedule enable' command to enable these schedules");
                }
                Err(e) => {
                    error!("Could not create preset schedules: {}", e);
                }
            }
        }

        _ => {
            error!("Invalid schedule command");
            info!("Available commands: enable, disable, list, status, presets");
        }
    }
}

fn handle_run_scheduled_scan(matches: &ArgMatches, config: &core::config::Config) {
    let schedule_name = matches.get_one::<String>("schedule_name").unwrap();

    info!("Running scheduled scan: {}", schedule_name);

    // Establish database connection
    let db = match DatabaseManager::new(&config.database.path) {
        Ok(db) => db,
        Err(e) => {
            error!("Database connection error: {}", e);
            std::process::exit(1);
        }
    };

    // Create scheduler
    let scheduler = match Scheduler::new(db) {
        Ok(scheduler) => scheduler,
        Err(e) => {
            error!("Scheduler creation error: {}", e);
            std::process::exit(1);
        }
    };

    // Start async runtime and run scheduled scan
    let rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(scheduler.run_scheduled_scan(schedule_name)) {
        Ok(_) => {
            info!("Scheduled scan completed successfully: {}", schedule_name);
        }
        Err(e) => {
            error!("Scheduled scan error: {}", e);
            std::process::exit(1);
        }
    }
}
