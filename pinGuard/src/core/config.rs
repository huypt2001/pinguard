use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub app: AppConfig,
    pub scanner: ScannerConfig,
    pub report: ReportConfig,
    pub database: DatabaseConfig,
    pub cve: CveConfig,
    pub fixer: FixerConfig,
    // Old fields for backward compatibility
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub name: String,
    pub version: String,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub enabled_modules: Vec<String>,
    pub package_audit: PackageAuditConfig,
    pub kernel_check: KernelCheckConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageAuditConfig {
    pub check_cve: bool,
    pub check_outdated: bool,
    pub exclude_packages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCheckConfig {
    pub check_eol: bool,
    pub check_patches: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    pub output_dir: String,
    pub format: String,
    pub template: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "./pinGuard.db".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveConfig {
    pub api_url: String,
    pub cache_duration: u64,
    pub auto_update: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixerConfig {
    pub auto_fix: bool,
    pub require_confirmation: bool,
    pub backup_before_fix: bool,
    pub backup_dir: String,
    pub enabled_modules: Vec<String>,
}

impl Config {
    /// Load configuration from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Config file could not be read: {} - Error: {}", path.as_ref().display(), e))?;
        
        let config: Config = serde_yaml::from_str(&content)
            .map_err(|e| format!("Config file could not be parsed: {}", e))?;
            
        Ok(config)
    }
    
    /// Default configuration
    pub fn default() -> Self {
        Config {
            app: AppConfig {
                name: "PinGuard".to_string(),
                version: "0.1.0".to_string(),
                log_level: "info".to_string(),
            },
            scanner: ScannerConfig {
                enabled_modules: vec!["package_audit".to_string(), "kernel_check".to_string()],
                package_audit: PackageAuditConfig {
                    check_cve: true,
                    check_outdated: true,
                    exclude_packages: vec![],
                },
                kernel_check: KernelCheckConfig {
                    check_eol: true,
                    check_patches: true,
                },
            },
            report: ReportConfig {
                output_dir: "./reports".to_string(),
                format: "json".to_string(),
                template: "default".to_string(),
            },
            database: DatabaseConfig {
                path: "./pinGuard.db".to_string(),
            },
            cve: CveConfig {
                api_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
                cache_duration: 86400,
                auto_update: true,
            },
            fixer: FixerConfig {
                auto_fix: false,
                require_confirmation: true,
                backup_before_fix: true,
                backup_dir: "./backups".to_string(),
                enabled_modules: vec![
                    "package_updater".to_string(),
                    "kernel_updater".to_string(),
                    "permission_fixer".to_string(),
                    "service_hardener".to_string(),
                    "user_policy_fixer".to_string(),
                    "firewall_configurator".to_string(),
                ],
            },
            key: "example_key".to_string(),
            value: "example_value".to_string(),
        }
    }
}