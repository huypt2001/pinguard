//! CLI application builder
//! Defines the complete command-line interface structure

use clap::{Arg, ArgAction, Command, ValueHint};

/// Build the complete CLI application
pub fn build_cli_app() -> Command {
    Command::new("pinGuard")
        .version(env!("CARGO_PKG_VERSION"))
        .author("PinGuard Team <team@pinGuard.dev>")
        .about("🛡️  Linux Vulnerability Scanner & Remediator")
        .long_about(
            "PinGuard is a comprehensive security tool that scans Linux systems for vulnerabilities,\n\
            provides detailed reports, and can automatically fix identified security issues.\n\n\
            Features:\n\
            • Package vulnerability scanning with CVE database\n\
            • Kernel security assessment\n\
            • Service and configuration auditing\n\
            • Network security analysis\n\
            • Automated security fixes\n\
            • Comprehensive reporting (JSON, HTML, PDF)\n\
            • Scheduled scans"
        )
        .before_help("🛡️  PinGuard - Linux Security Scanner")
        .after_help(
            "Examples:\n\
            pinGuard scan                    # Full system scan\n\
            pinGuard scan -m package         # Scan only packages\n\
            pinGuard fix --auto              # Auto-fix vulnerabilities\n\
            pinGuard report -f html          # Generate HTML report\n\
            pinGuard interactive             # Interactive mode\n\n\
            For more information visit: https://github.com/reicalasso/pinGuard"
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .long_help("Specify a custom configuration file. If not provided, pinGuard will look for config.yaml in the current directory.")
                .value_hint(ValueHint::FilePath)
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Enable verbose output")
                .long_help("Show detailed debug information during execution")
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(ArgAction::SetTrue)
                .help("Suppress all output except errors")
                .conflicts_with("verbose")
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .action(ArgAction::SetTrue)
                .help("Disable colored output")
        )
        .subcommand(build_scan_command())
        .subcommand(build_fix_command())
        .subcommand(build_report_command())
        .subcommand(build_config_command())
        .subcommand(build_database_command())
        .subcommand(build_cve_command())
        .subcommand(build_schedule_command())
        .subcommand(build_backup_command())
        .subcommand(build_interactive_command())
        .subcommand(build_completion_command())
        .subcommand(build_version_command())
        .subcommand_required(false)
        .arg_required_else_help(false)
}

/// Build the scan subcommand
fn build_scan_command() -> Command {
    Command::new("scan")
        .about("🔍 Perform system security scan")
        .long_about(
            "Scan your Linux system for security vulnerabilities.\n\n\
            Available scan modules:\n\
            • package    - Check installed packages for CVEs\n\
            • kernel     - Analyze kernel security status\n\
            • service    - Audit running services\n\
            • network    - Network security assessment\n\
            • permission - File and directory permissions\n\
            • user       - User account security\n\
            • container  - Container security (if available)"
        )
        .arg(
            Arg::new("module")
                .short('m')
                .long("module")
                .value_name("MODULE")
                .help("Scan specific module only")
                .long_help("Run only a specific scan module instead of full scan")
                .value_parser(["package", "kernel", "service", "network", "permission", "user", "container", "web", "compliance"])
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Save results to file")
                .value_hint(ValueHint::FilePath)
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format")
                .value_parser(["json", "yaml", "table"])
                .default_value("json")
        )
        .arg(
            Arg::new("quick")
                .long("quick")
                .action(ArgAction::SetTrue)
                .help("Perform quick scan (skip intensive checks)")
        )
        .arg(
            Arg::new("severity")
                .long("min-severity")
                .value_name("LEVEL")
                .help("Minimum severity level to report")
                .value_parser(["low", "medium", "high", "critical"])
                .default_value("medium")
        )
        .arg(
            Arg::new("exclude")
                .long("exclude")
                .value_name("MODULES")
                .help("Exclude specific modules (comma-separated)")
                .value_delimiter(',')
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("SECONDS")
                .help("Scan timeout in seconds")
                .value_parser(clap::value_parser!(u64))
                .default_value("300")
        )
}

/// Build the fix subcommand
fn build_fix_command() -> Command {
    Command::new("fix")
        .about("🔧 Fix security vulnerabilities")
        .long_about(
            "Fix identified security vulnerabilities automatically or interactively.\n\n\
            Available fix modules:\n\
            • package    - Update vulnerable packages\n\
            • kernel     - Apply kernel updates\n\
            • service    - Fix service configurations\n\
            • permission - Correct file permissions\n\
            • firewall   - Configure firewall rules"
        )
        .arg(
            Arg::new("auto")
                .long("auto")
                .action(ArgAction::SetTrue)
                .help("Apply fixes automatically without confirmation")
        )
        .arg(
            Arg::new("module")
                .short('m')
                .long("module")
                .value_name("MODULE")
                .help("Fix specific module only")
                .value_parser(["package", "kernel", "service", "permission", "firewall"])
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .action(ArgAction::SetTrue)
                .help("Show what would be fixed without making changes")
        )
        .arg(
            Arg::new("backup")
                .long("backup")
                .action(ArgAction::SetTrue)
                .help("Create backups before applying fixes")
                .default_value("true")
        )
        .arg(
            Arg::new("severity")
                .long("min-severity")
                .value_name("LEVEL")
                .help("Minimum severity level to fix")
                .value_parser(["low", "medium", "high", "critical"])
                .default_value("high")
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("Load scan results from file")
                .value_hint(ValueHint::FilePath)
        )
}

/// Build the report subcommand
fn build_report_command() -> Command {
    Command::new("report")
        .about("📊 Generate security reports")
        .long_about(
            "Generate comprehensive security reports from scan results.\n\n\
            Available formats:\n\
            • json - Structured JSON format\n\
            • html - Interactive HTML report\n\
            • pdf  - Printable PDF report\n\
            • csv  - Comma-separated values"
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Report format")
                .value_parser(["json", "html", "pdf", "csv", "all"])
                .default_value("html")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("PATH")
                .help("Output file or directory")
                .value_hint(ValueHint::AnyPath)
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("Input scan results file")
                .value_hint(ValueHint::FilePath)
        )
        .arg(
            Arg::new("template")
                .short('t')
                .long("template")
                .value_name("TEMPLATE")
                .help("Report template")
                .value_parser(["default", "executive", "technical", "compliance"])
                .default_value("default")
        )
        .arg(
            Arg::new("scan")
                .long("scan")
                .action(ArgAction::SetTrue)
                .help("Perform fresh scan before generating report")
        )
        .arg(
            Arg::new("summary")
                .long("summary")
                .action(ArgAction::SetTrue)
                .help("Show summary only")
        )
}

/// Build the config subcommand
fn build_config_command() -> Command {
    Command::new("config")
        .about("⚙️ Configuration management")
        .long_about("Manage PinGuard configuration settings")
        .subcommand(
            Command::new("show")
                .about("Show current configuration")
                .arg(
                    Arg::new("section")
                        .help("Show specific configuration section")
                        .value_parser(["app", "scanner", "report", "database", "cve", "fixer"])
                )
        )
        .subcommand(
            Command::new("init")
                .about("Create default configuration file")
                .arg(
                    Arg::new("force")
                        .long("force")
                        .action(ArgAction::SetTrue)
                        .help("Overwrite existing config file")
                )
        )
        .subcommand(
            Command::new("validate")
                .about("Validate configuration file")
                .arg(
                    Arg::new("file")
                        .value_name("FILE")
                        .help("Configuration file to validate")
                        .value_hint(ValueHint::FilePath)
                )
        )
        .subcommand(
            Command::new("set")
                .about("Set configuration value")
                .arg(
                    Arg::new("key")
                        .help("Configuration key (e.g., app.log_level)")
                        .required(true)
                )
                .arg(
                    Arg::new("value")
                        .help("Configuration value")
                        .required(true)
                )
        )
        .subcommand(
            Command::new("get")
                .about("Get configuration value")
                .arg(
                    Arg::new("key")
                        .help("Configuration key")
                        .required(true)
                )
        )
}

/// Build the database subcommand
fn build_database_command() -> Command {
    Command::new("database")
        .about("🗄️ Database management")
        .long_about("Manage PinGuard's internal database")
        .subcommand(Command::new("init").about("Initialize database"))
        .subcommand(Command::new("migrate").about("Run database migrations"))
        .subcommand(Command::new("health").about("Check database health"))
        .subcommand(Command::new("stats").about("Show database statistics"))
        .subcommand(
            Command::new("cleanup")
                .about("Clean up old data")
                .arg(
                    Arg::new("days")
                        .short('d')
                        .long("days")
                        .value_name("DAYS")
                        .help("Delete data older than specified days")
                        .value_parser(clap::value_parser!(u32))
                        .default_value("30")
                )
        )
        .subcommand(Command::new("backup").about("Create database backup"))
        .subcommand(
            Command::new("restore")
                .about("Restore from backup")
                .arg(
                    Arg::new("file")
                        .help("Backup file to restore")
                        .required(true)
                        .value_hint(ValueHint::FilePath)
                )
        )
}

/// Build the CVE subcommand
fn build_cve_command() -> Command {
    Command::new("cve")
        .about("🔒 CVE database management")
        .long_about("Manage CVE (Common Vulnerabilities and Exposures) database")
        .subcommand(
            Command::new("sync")
                .about("Synchronize CVE database")
                .arg(
                    Arg::new("days")
                        .short('d')
                        .long("days")
                        .value_name("DAYS")
                        .help("Sync CVEs from last N days")
                        .value_parser(clap::value_parser!(u32))
                        .default_value("7")
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .action(ArgAction::SetTrue)
                        .help("Force full resync")
                )
        )
        .subcommand(
            Command::new("search")
                .about("Search CVE database")
                .arg(
                    Arg::new("query")
                        .help("Search query (CVE ID, package name, keyword)")
                        .required(true)
                )
                .arg(
                    Arg::new("limit")
                        .short('l')
                        .long("limit")
                        .value_name("LIMIT")
                        .help("Maximum results to show")
                        .value_parser(clap::value_parser!(usize))
                        .default_value("10")
                )
        )
        .subcommand(
            Command::new("info")
                .about("Get CVE details")
                .arg(
                    Arg::new("cve_id")
                        .help("CVE ID (e.g., CVE-2023-1234)")
                        .required(true)
                )
        )
        .subcommand(Command::new("stats").about("Show CVE database statistics"))
        .subcommand(Command::new("update").about("Update CVE database"))
}

/// Build the schedule subcommand
fn build_schedule_command() -> Command {
    Command::new("schedule")
        .about("⏰ Scheduled scan management")
        .long_about("Manage automated security scans")
        .subcommand(
            Command::new("add")
                .about("Add scheduled scan")
                .arg(
                    Arg::new("name")
                        .help("Schedule name")
                        .required(true)
                )
                .arg(
                    Arg::new("cron")
                        .help("Cron expression (e.g., '0 2 * * *')")
                        .required(true)
                )
                .arg(
                    Arg::new("description")
                        .short('d')
                        .long("description")
                        .value_name("DESC")
                        .help("Schedule description")
                )
        )
        .subcommand(
            Command::new("remove")
                .about("Remove scheduled scan")
                .arg(
                    Arg::new("name")
                        .help("Schedule name")
                        .required(true)
                )
        )
        .subcommand(Command::new("list").about("List scheduled scans"))
        .subcommand(
            Command::new("status")
                .about("Show schedule status")
                .arg(
                    Arg::new("name")
                        .help("Schedule name (optional)")
                )
        )
        .subcommand(Command::new("run").about("Run scheduled scan manually"))
}

/// Build the interactive subcommand
fn build_interactive_command() -> Command {
    Command::new("interactive")
        .about("💬 Interactive mode")
        .long_about("Start PinGuard in interactive mode with guided menus")
        .hide(false) // Show in help
}

/// Build the completion subcommand
fn build_completion_command() -> Command {
    Command::new("completion")
        .about("🔧 Generate shell completions")
        .long_about("Generate shell completion scripts for bash, zsh, fish, or PowerShell")
        .arg(
            Arg::new("shell")
                .help("Shell type")
                .value_parser(["bash", "zsh", "fish", "powershell"])
                .required(true)
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file (default: stdout)")
                .value_hint(ValueHint::FilePath)
        )
}

/// Build the version subcommand
fn build_version_command() -> Command {
    Command::new("version")
        .about("📋 Show version information")
        .long_about("Display version and build information")
}

/// Build the backup subcommand
fn build_backup_command() -> Command {
    Command::new("backup")
        .about("💾 Backup and restore system state")
        .long_about(
            "Manage system backups and restore points.\n\n\
            Available operations:\n\
            • create   - Create a new backup snapshot\n\
            • list     - List available backups\n\
            • restore  - Restore from a backup\n\
            • verify   - Verify backup integrity\n\
            • cleanup  - Clean up old backups\n\
            • stats    - Show backup statistics"
        )
        .subcommand(
            Command::new("create")
                .about("Create a new backup snapshot")
                .arg(
                    Arg::new("description")
                        .short('d')
                        .long("description")
                        .value_name("TEXT")
                        .help("Description for this backup")
                        .default_value("Manual backup via CLI")
                )
                .arg(
                    Arg::new("paths")
                        .short('p')
                        .long("paths")
                        .value_name("PATH")
                        .action(ArgAction::Append)
                        .help("Specific paths to backup")
                        .long_help("Specify custom paths to backup. Default: /etc, /usr/local, /var/log")
                        .value_hint(ValueHint::DirPath)
                )
        )
        .subcommand(
            Command::new("list")
                .about("List available backup snapshots")
                .arg(
                    Arg::new("stats")
                        .short('s')
                        .long("stats")
                        .action(ArgAction::SetTrue)
                        .help("Show detailed statistics")
                )
        )
        .subcommand(
            Command::new("restore")
                .about("Restore system from a backup")
                .arg(
                    Arg::new("id")
                        .value_name("BACKUP_ID")
                        .help("Backup ID to restore from")
                        .required(true)
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Simulate restore without making changes")
                )
        )
        .subcommand(
            Command::new("verify")
                .about("Verify backup integrity")
                .arg(
                    Arg::new("id")
                        .value_name("BACKUP_ID")
                        .help("Backup ID to verify")
                        .required(true)
                )
        )
        .subcommand(
            Command::new("cleanup")
                .about("Clean up old backups")
                .arg(
                    Arg::new("days")
                        .short('d')
                        .long("days")
                        .value_name("DAYS")
                        .help("Remove backups older than N days")
                        .default_value("30")
                )
        )
        .subcommand(
            Command::new("stats")
                .about("Show backup system statistics")
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
}