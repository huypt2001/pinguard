//! Enhanced configuration system with environment variable support
//! and validation capabilities

use crate::core::traits::ConfigProvider;
use crate::core::errors::{PinGuardError, PinGuardResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub app: AppConfig,
    pub scanner: ScannerConfig,
    pub report: ReportConfig,
    pub database: DatabaseConfig,
    pub cve: CveConfig,
    pub fixer: FixerConfig,
    pub scheduler: SchedulerConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
    
    // Legacy fields for backward compatibility
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_app_name")]
    pub name: String,
    #[serde(default = "default_app_version")]
    pub version: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_max_threads")]
    pub max_threads: usize,
    #[serde(default)]
    pub debug_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    #[serde(default = "default_enabled_scanners")]
    pub enabled_modules: Vec<String>,
    #[serde(default)]
    pub package_audit: PackageAuditConfig,
    #[serde(default)]
    pub kernel_check: KernelCheckConfig,
    #[serde(default)]
    pub web_security: WebSecurityConfig,
    #[serde(default)]
    pub network_audit: NetworkAuditConfig,
    #[serde(default)]
    pub permission_audit: PermissionAuditConfig,
    #[serde(default)]
    pub service_audit: ServiceAuditConfig,
    #[serde(default)]
    pub user_audit: UserAuditConfig,
    #[serde(default)]
    pub container_security: ContainerSecurityConfig,
    #[serde(default = "default_parallel_scans")]
    pub parallel_scans: usize,
    #[serde(default = "default_scan_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageAuditConfig {
    #[serde(default = "default_true")]
    pub check_cve: bool,
    #[serde(default = "default_true")]
    pub check_outdated: bool,
    #[serde(default)]
    pub exclude_packages: Vec<String>,
    #[serde(default)]
    pub include_dev_packages: bool,
    #[serde(default = "default_cve_severity_threshold")]
    pub min_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCheckConfig {
    #[serde(default = "default_true")]
    pub check_eol: bool,
    #[serde(default = "default_true")]
    pub check_patches: bool,
    #[serde(default)]
    pub check_security_patches_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSecurityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_web_ports")]
    pub target_ports: Vec<u16>,
    #[serde(default = "default_web_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_true")]
    pub check_ssl_certificates: bool,
    #[serde(default = "default_true")]
    pub check_security_headers: bool,
    #[serde(default = "default_true")]
    pub check_server_configs: bool,
    #[serde(default = "default_true")]
    pub check_owasp_vulnerabilities: bool,
    #[serde(default)]
    pub exclude_hosts: Vec<String>,
    #[serde(default)]
    pub custom_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAuditConfig {
    #[serde(default)]
    pub scan_open_ports: bool,
    #[serde(default)]
    pub check_firewall_rules: bool,
    #[serde(default)]
    pub analyze_network_traffic: bool,
    #[serde(default)]
    pub excluded_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionAuditConfig {
    #[serde(default = "default_true")]
    pub check_sudo_config: bool,
    #[serde(default = "default_true")]
    pub check_file_permissions: bool,
    #[serde(default)]
    pub check_suid_files: bool,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAuditConfig {
    #[serde(default = "default_true")]
    pub check_running_services: bool,
    #[serde(default)]
    pub check_service_configs: bool,
    #[serde(default)]
    pub excluded_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAuditConfig {
    #[serde(default = "default_true")]
    pub check_user_accounts: bool,
    #[serde(default)]
    pub check_password_policies: bool,
    #[serde(default)]
    pub check_ssh_keys: bool,
    #[serde(default)]
    pub excluded_users: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub scan_images: bool,
    #[serde(default)]
    pub scan_containers: bool,
    #[serde(default)]
    pub check_runtime_security: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    #[serde(default = "default_output_dir")]
    pub output_dir: String,
    #[serde(default = "default_report_format")]
    pub format: String,
    #[serde(default = "default_template")]
    pub template: String,
    #[serde(default = "default_true")]
    pub include_raw_data: bool,
    #[serde(default)]
    pub compress_reports: bool,
    #[serde(default = "default_max_report_age")]
    pub max_age_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,
    #[serde(default = "default_db_pool_size")]
    pub pool_size: u32,
    #[serde(default = "default_true")]
    pub auto_migrate: bool,
    #[serde(default)]
    pub backup_enabled: bool,
    #[serde(default = "default_backup_interval")]
    pub backup_interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveConfig {
    #[serde(default = "default_cve_api_url")]
    pub api_url: String,
    #[serde(default = "default_cache_duration")]
    pub cache_duration: u64,
    #[serde(default = "default_true")]
    pub auto_update: bool,
    #[serde(default = "default_update_interval")]
    pub update_interval_hours: u64,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixerConfig {
    #[serde(default)]
    pub auto_fix: bool,
    #[serde(default = "default_true")]
    pub require_confirmation: bool,
    #[serde(default = "default_true")]
    pub backup_before_fix: bool,
    #[serde(default = "default_backup_dir")]
    pub backup_dir: String,
    #[serde(default)]
    pub enabled_modules: Vec<String>,
    #[serde(default = "default_max_fixes_per_run")]
    pub max_fixes_per_run: usize,
    #[serde(default)]
    pub dry_run_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_schedule")]
    pub scan_schedule: String,
    #[serde(default)]
    pub auto_fix_schedule: Option<String>,
    #[serde(default)]
    pub update_schedule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default = "default_true")]
    pub console_output: bool,
    #[serde(default)]
    pub structured_logging: bool,
    #[serde(default = "default_max_log_size")]
    pub max_file_size_mb: u64,
    #[serde(default = "default_log_retention")]
    pub retention_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub require_root: bool,
    #[serde(default)]
    pub allowed_users: Vec<String>,
    #[serde(default)]
    pub encrypt_data: bool,
    #[serde(default)]
    pub audit_log_enabled: bool,
    #[serde(default)]
    pub rate_limiting: bool,
}

// Default value functions
fn default_app_name() -> String { "PinGuard".to_string() }
fn default_app_version() -> String { env!("CARGO_PKG_VERSION").to_string() }
fn default_log_level() -> String { "info".to_string() }
fn default_max_threads() -> usize { num_cpus::get() }
fn default_enabled_scanners() -> Vec<String> {
    vec![
        "package_audit".to_string(),
        "kernel_check".to_string(),
        "permission_audit".to_string(),
        "service_audit".to_string(),
        "user_audit".to_string(),
    ]
}
fn default_parallel_scans() -> usize { 4 }
fn default_scan_timeout() -> u64 { 300 }
fn default_true() -> bool { true }
fn default_cve_severity_threshold() -> String { "medium".to_string() }
fn default_web_ports() -> Vec<u16> { vec![80, 443, 8080, 8443] }
fn default_web_timeout() -> u64 { 30 }
fn default_output_dir() -> String { "./reports".to_string() }
fn default_report_format() -> String { "json".to_string() }
fn default_template() -> String { "default".to_string() }
fn default_max_report_age() -> u64 { 30 }
fn default_db_path() -> String { "./pinGuard.db".to_string() }
fn default_db_pool_size() -> u32 { 10 }
fn default_backup_interval() -> u64 { 24 }
fn default_cve_api_url() -> String { "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string() }
fn default_cache_duration() -> u64 { 86400 }
fn default_update_interval() -> u64 { 6 }
fn default_request_timeout() -> u64 { 60 }
fn default_backup_dir() -> String { "./backups".to_string() }
fn default_max_fixes_per_run() -> usize { 10 }
fn default_schedule() -> String { "0 2 * * *".to_string() } // Daily at 2 AM
fn default_max_log_size() -> u64 { 100 }
fn default_log_retention() -> u64 { 30 }

impl Default for Config {
    fn default() -> Self {
        Self {
            app: AppConfig {
                name: default_app_name(),
                version: default_app_version(),
                log_level: default_log_level(),
                max_threads: default_max_threads(),
                debug_mode: false,
            },
            scanner: ScannerConfig {
                enabled_modules: default_enabled_scanners(),
                package_audit: PackageAuditConfig::default(),
                kernel_check: KernelCheckConfig::default(),
                web_security: WebSecurityConfig::default(),
                network_audit: NetworkAuditConfig::default(),
                permission_audit: PermissionAuditConfig::default(),
                service_audit: ServiceAuditConfig::default(),
                user_audit: UserAuditConfig::default(),
                container_security: ContainerSecurityConfig::default(),
                parallel_scans: default_parallel_scans(),
                timeout_seconds: default_scan_timeout(),
            },
            report: ReportConfig {
                output_dir: default_output_dir(),
                format: default_report_format(),
                template: default_template(),
                include_raw_data: true,
                compress_reports: false,
                max_age_days: default_max_report_age(),
            },
            database: DatabaseConfig {
                path: default_db_path(),
                pool_size: default_db_pool_size(),
                auto_migrate: true,
                backup_enabled: false,
                backup_interval_hours: default_backup_interval(),
            },
            cve: CveConfig {
                api_url: default_cve_api_url(),
                cache_duration: default_cache_duration(),
                auto_update: true,
                update_interval_hours: default_update_interval(),
                api_key: None,
                request_timeout_seconds: default_request_timeout(),
            },
            fixer: FixerConfig {
                auto_fix: false,
                require_confirmation: true,
                backup_before_fix: true,
                backup_dir: default_backup_dir(),
                enabled_modules: vec![],
                max_fixes_per_run: default_max_fixes_per_run(),
                dry_run_mode: false,
            },
            scheduler: SchedulerConfig {
                enabled: false,
                scan_schedule: default_schedule(),
                auto_fix_schedule: None,
                update_schedule: None,
            },
            logging: LoggingConfig {
                level: default_log_level(),
                file_path: None,
                console_output: true,
                structured_logging: false,
                max_file_size_mb: default_max_log_size(),
                retention_days: default_log_retention(),
            },
            security: SecurityConfig {
                require_root: false,
                allowed_users: vec![],
                encrypt_data: false,
                audit_log_enabled: false,
                rate_limiting: false,
            },
            key: String::new(),
            value: String::new(),
        }
    }
}

impl Default for PackageAuditConfig {
    fn default() -> Self {
        Self {
            check_cve: true,
            check_outdated: true,
            exclude_packages: vec![],
            include_dev_packages: false,
            min_severity: default_cve_severity_threshold(),
        }
    }
}

impl Default for KernelCheckConfig {
    fn default() -> Self {
        Self {
            check_eol: true,
            check_patches: true,
            check_security_patches_only: false,
        }
    }
}

impl Default for WebSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_ports: default_web_ports(),
            timeout_seconds: default_web_timeout(),
            check_ssl_certificates: true,
            check_security_headers: true,
            check_server_configs: true,
            check_owasp_vulnerabilities: true,
            exclude_hosts: vec![],
            custom_headers: HashMap::new(),
        }
    }
}

impl Default for NetworkAuditConfig {
    fn default() -> Self {
        Self {
            scan_open_ports: false,
            check_firewall_rules: false,
            analyze_network_traffic: false,
            excluded_interfaces: vec![],
        }
    }
}

impl Default for PermissionAuditConfig {
    fn default() -> Self {
        Self {
            check_sudo_config: true,
            check_file_permissions: true,
            check_suid_files: false,
            excluded_paths: vec![],
        }
    }
}

impl Default for ServiceAuditConfig {
    fn default() -> Self {
        Self {
            check_running_services: true,
            check_service_configs: false,
            excluded_services: vec![],
        }
    }
}

impl Default for UserAuditConfig {
    fn default() -> Self {
        Self {
            check_user_accounts: true,
            check_password_policies: false,
            check_ssh_keys: false,
            excluded_users: vec![],
        }
    }
}

impl Default for ContainerSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_images: false,
            scan_containers: false,
            check_runtime_security: false,
        }
    }
}

/// Enhanced implementation of various configuration types
impl Config {
    /// Load configuration from file with environment variable expansion
    #[allow(dead_code)]
    pub fn load_from_file(path: &str) -> Result<Self, PinGuardError> {
        let content = fs::read_to_string(path).map_err(|e| {
            PinGuardError::Config {
                message: format!(
                    "Could not read config file '{}': {}",
                    path,
                    e
                ),
                source: None,
            }
        })?;

        let expanded_content = expand_env_vars(&content)?;
        let config: Config = serde_yaml::from_str(&expanded_content).map_err(|e| {
            PinGuardError::Config {
                message: format!("Invalid YAML in config file: {}", e),
                source: None,
            }
        })?;

        config.validate()?;
        Ok(config)
    }

    /// Load configuration from environment variables
    #[allow(dead_code)]
    pub fn load_from_env() -> PinGuardResult<Self> {
        let mut config = Config::default();
        
        // Override with environment variables
        if let Ok(log_level) = env::var("PINGUARD_LOG_LEVEL") {
            config.app.log_level = log_level;
        }
        
        if let Ok(db_path) = env::var("PINGUARD_DB_PATH") {
            config.database.path = db_path;
        }
        
        if let Ok(cve_api_key) = env::var("PINGUARD_CVE_API_KEY") {
            config.cve.api_key = Some(cve_api_key);
        }
        
        if let Ok(output_dir) = env::var("PINGUARD_OUTPUT_DIR") {
            config.report.output_dir = output_dir;
        }

        config.validate()?;
        Ok(config)
    }

    /// Create a configuration with both file and environment variables
    #[allow(dead_code)]
    pub fn load_with_overrides<P: AsRef<Path>>(path: P) -> PinGuardResult<Self> {
        match Self::load_from_file(path.as_ref().to_str().unwrap()) {
            Ok(mut config) => {
                config.apply_env_overrides()?;
                Ok(config)
            }
            Err(_) => {
                // If file doesn't exist, use environment variables
                Self::load_from_env()
            }
        }
    }

    /// Apply environment variable overrides to existing configuration
    #[allow(dead_code)]
    pub fn apply_env_overrides(&mut self) -> PinGuardResult<()> {
        if let Ok(log_level) = env::var("PINGUARD_LOG_LEVEL") {
            self.app.log_level = log_level;
        }
        
        if let Ok(debug) = env::var("PINGUARD_DEBUG") {
            self.app.debug_mode = debug.parse().unwrap_or(false);
        }
        
        if let Ok(db_path) = env::var("PINGUARD_DB_PATH") {
            self.database.path = db_path;
        }
        
        if let Ok(api_key) = env::var("PINGUARD_CVE_API_KEY") {
            self.cve.api_key = Some(api_key);
        }
        
        if let Ok(output_dir) = env::var("PINGUARD_OUTPUT_DIR") {
            self.report.output_dir = output_dir;
        }
        
        if let Ok(auto_fix) = env::var("PINGUARD_AUTO_FIX") {
            self.fixer.auto_fix = auto_fix.parse().unwrap_or(false);
        }

        Ok(())
    }

    /// Validate the configuration
    #[allow(dead_code)]
    pub fn validate(&self) -> PinGuardResult<()> {
        // Validate log level
        if !["trace", "debug", "info", "warn", "error"].contains(&self.app.log_level.as_str()) {
            return Err(PinGuardError::Validation {
                message: format!("Invalid log level: {}", self.app.log_level),
                source: None,
            });
        }

        // Validate report format
        if !["json", "html", "pdf"].contains(&self.report.format.as_str()) {
            return Err(PinGuardError::Validation {
                message: format!("Invalid report format: {}", self.report.format),
                source: None,
            });
        }

        // Validate paths
        if let Some(parent) = Path::new(&self.database.path).parent() {
            if !parent.exists() {
                return Err(PinGuardError::Validation {
                    message: format!("Database directory does not exist: {}", parent.display()),
                    source: None,
                });
            }
        }

        Ok(())
    }

    /// Save configuration to file
    #[allow(dead_code)]
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> PinGuardResult<()> {
        let content = serde_yaml::to_string(self).map_err(|e| {
            PinGuardError::Config {
                message: format!("Failed to serialize config: {}", e),
                source: None,
            }
        })?;

        fs::write(&path, content).map_err(|e| {
            PinGuardError::Config {
                message: format!(
                    "Failed to write config file '{}': {}",
                    path.as_ref().display(),
                    e
                ),
                source: None,
            }
        })?;

        Ok(())
    }
}

impl ConfigProvider for Config {
    fn get_string(&self, key: &str) -> Option<String> {
        match key {
            "app.name" => Some(self.app.name.clone()),
            "app.version" => Some(self.app.version.clone()),
            "app.log_level" => Some(self.app.log_level.clone()),
            "database.path" => Some(self.database.path.clone()),
            "report.output_dir" => Some(self.report.output_dir.clone()),
            "report.format" => Some(self.report.format.clone()),
            "cve.api_url" => Some(self.cve.api_url.clone()),
            "fixer.backup_dir" => Some(self.fixer.backup_dir.clone()),
            _ => None,
        }
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        match key {
            "app.debug_mode" => Some(self.app.debug_mode),
            "scanner.package_audit.check_cve" => Some(self.scanner.package_audit.check_cve),
            "scanner.package_audit.check_outdated" => Some(self.scanner.package_audit.check_outdated),
            "fixer.auto_fix" => Some(self.fixer.auto_fix),
            "fixer.require_confirmation" => Some(self.fixer.require_confirmation),
            "fixer.backup_before_fix" => Some(self.fixer.backup_before_fix),
            "database.auto_migrate" => Some(self.database.auto_migrate),
            "cve.auto_update" => Some(self.cve.auto_update),
            _ => None,
        }
    }

    fn get_int(&self, key: &str) -> Option<i64> {
        match key {
            "app.max_threads" => Some(self.app.max_threads as i64),
            "scanner.parallel_scans" => Some(self.scanner.parallel_scans as i64),
            "scanner.timeout_seconds" => Some(self.scanner.timeout_seconds as i64),
            "database.pool_size" => Some(self.database.pool_size as i64),
            "cve.cache_duration" => Some(self.cve.cache_duration as i64),
            "fixer.max_fixes_per_run" => Some(self.fixer.max_fixes_per_run as i64),
            _ => None,
        }
    }

    fn get_string_array(&self, key: &str) -> Option<Vec<String>> {
        match key {
            "scanner.enabled_modules" => Some(self.scanner.enabled_modules.clone()),
            "scanner.package_audit.exclude_packages" => Some(self.scanner.package_audit.exclude_packages.clone()),
            "fixer.enabled_modules" => Some(self.fixer.enabled_modules.clone()),
            _ => None,
        }
    }
}

/// Expand environment variables in configuration content
#[allow(dead_code)]
fn expand_env_vars(content: &str) -> PinGuardResult<String> {
    let mut result = content.to_string();
    
    // Simple environment variable substitution: ${VAR} or $VAR
    let env_var_regex = regex::Regex::new(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    
    for captures in env_var_regex.captures_iter(content) {
        let full_match = captures.get(0).unwrap().as_str();
        let var_name = captures.get(1).or_else(|| captures.get(2)).unwrap().as_str();
        
        if let Ok(value) = env::var(var_name) {
            result = result.replace(full_match, &value);
        } else {
            // Keep the original if environment variable is not found
            continue;
        }
    }
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.app.name, "PinGuard");
        assert!(config.scanner.package_audit.check_cve);
        assert!(!config.fixer.auto_fix);
    }

    #[test]
    fn test_config_validation() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        
        let mut invalid_config = config.clone();
        invalid_config.app.log_level = "invalid".to_string();
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_env_var_expansion() {
        env::set_var("TEST_VAR", "test_value");
        let content = "key: ${TEST_VAR}";
        let expanded = expand_env_vars(content).unwrap();
        assert_eq!(expanded, "key: test_value");
        env::remove_var("TEST_VAR");
    }
}