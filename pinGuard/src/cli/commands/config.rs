//! Configuration command implementation

use crate::cli::display::Display;
use crate::core::{config::Config, errors::PinGuardResult};
use clap::ArgMatches;

/// Handle the config command
pub fn handle(matches: &ArgMatches, config: &Config, display: &Display) -> PinGuardResult<()> {
    match matches.subcommand() {
        Some(("show", sub_matches)) => handle_show(sub_matches, config, display),
        Some(("init", sub_matches)) => handle_init(sub_matches, display),
        Some(("validate", sub_matches)) => handle_validate(sub_matches, display),
        Some(("set", sub_matches)) => handle_set(sub_matches, display),
        Some(("get", sub_matches)) => handle_get(sub_matches, config, display),
        _ => {
            display.error("No subcommand specified");
            display.info("Available subcommands: show, init, validate, set, get");
            Ok(())
        }
    }
}

/// Handle config show command
fn handle_show(matches: &ArgMatches, config: &Config, display: &Display) -> PinGuardResult<()> {
    if let Some(section) = matches.get_one::<String>("section") {
        show_config_section(section, config, display)
    } else {
        show_full_config(config, display)
    }
}

/// Show specific configuration section
fn show_config_section(section: &str, config: &Config, display: &Display) -> PinGuardResult<()> {
    display.section_header(&format!("Configuration Section: {}", section));
    
    match section {
        "app" => {
            let items = vec![
                ("Name", config.app.name.as_str()),
                ("Version", config.app.version.as_str()),
                ("Log Level", config.app.log_level.as_str()),
            ];
            display.key_value_list(&items);
        }
        "scanner" => {
            let enabled_modules_str = config.scanner.enabled_modules.join(", ");
            let items = vec![
                ("Enabled Modules", enabled_modules_str.as_str()),
            ];
            display.key_value_list(&items);
        }
        "database" => {
            let items = vec![
                ("Path", config.database.path.as_str()),
            ];
            display.key_value_list(&items);
        }
        "report" => {
            let items = vec![
                ("Output Directory", config.report.output_dir.as_str()),
                ("Format", config.report.format.as_str()),
                ("Template", config.report.template.as_str()),
            ];
            display.key_value_list(&items);
        }
        "cve" => {
            let cache_duration_str = config.cve.cache_duration.to_string();
            let auto_update_str = config.cve.auto_update.to_string();
            let items = vec![
                ("API URL", config.cve.api_url.as_str()),
                ("Cache Duration", cache_duration_str.as_str()),
                ("Auto Update", auto_update_str.as_str()),
            ];
            display.key_value_list(&items);
        }
        "fixer" => {
            let auto_fix_str = config.fixer.auto_fix.to_string();
            let require_confirmation_str = config.fixer.require_confirmation.to_string();
            let backup_before_fix_str = config.fixer.backup_before_fix.to_string();
            let items = vec![
                ("Auto Fix", auto_fix_str.as_str()),
                ("Require Confirmation", require_confirmation_str.as_str()),
                ("Backup Before Fix", backup_before_fix_str.as_str()),
                ("Backup Directory", config.fixer.backup_dir.as_str()),
            ];
            display.key_value_list(&items);
        }
        _ => {
            display.error(&format!("Unknown configuration section: {}", section));
            display.info("Available sections: app, scanner, database, report, cve, fixer");
        }
    }
    
    Ok(())
}

/// Show full configuration
fn show_full_config(config: &Config, display: &Display) -> PinGuardResult<()> {
    display.section_header("PinGuard Configuration");
    
    // Convert config to YAML for display
    match serde_yaml::to_string(config) {
        Ok(yaml_content) => {
            println!("{}", yaml_content);
        }
        Err(e) => {
            display.error(&format!("Failed to serialize configuration: {}", e));
        }
    }
    
    Ok(())
}

/// Handle config init command
fn handle_init(matches: &ArgMatches, display: &Display) -> PinGuardResult<()> {
    let force = matches.get_flag("force");
    let config_path = "config.yaml";
    
    if std::path::Path::new(config_path).exists() && !force {
        display.warning(&format!("Configuration file '{}' already exists", config_path));
        display.info("Use --force to overwrite existing file");
        return Ok(());
    }
    
    display.info("Creating default configuration file...");
    
    let default_config = Config::default_config();
    // For now, we'll create a basic YAML content since save_to_file may not exist
    let yaml_content = serde_yaml::to_string(&default_config)
        .map_err(|e| crate::core::errors::PinGuardError::Parse {
            message: format!("Failed to serialize config: {}", e),
            source: None,
        })?;
        
    std::fs::write(config_path, yaml_content)
        .map_err(|e| crate::core::errors::PinGuardError::Io {
            message: format!("Failed to write config file: {}", e),
            source: None,
        })?;
        
    display.success(&format!("Configuration file created: {}", config_path));
    display.info("You can now edit the configuration file to customize PinGuard settings");
    
    Ok(())
}

/// Handle config validate command
fn handle_validate(matches: &ArgMatches, display: &Display) -> PinGuardResult<()> {
    let config_file = matches
        .get_one::<String>("file")
        .map(|s| s.as_str())
        .unwrap_or("config.yaml");
    
    display.info(&format!("Validating configuration file: {}", config_file));
    
    match Config::load_from_file(config_file) {
        Ok(config) => {
            display.success("Configuration is valid!");
            
            // Show some basic info about the config
            let enabled_count = config.scanner.enabled_modules.len().to_string();
            let items = vec![
                ("Application", config.app.name.as_str()),
                ("Log Level", config.app.log_level.as_str()),
                ("Enabled Scanners", enabled_count.as_str()),
                ("Report Format", config.report.format.as_str()),
            ];
            display.key_value_list(&items);
        }
        Err(e) => {
            display.error(&format!("Failed to load configuration file: {}", e));
        }
    }
    
    Ok(())
}

/// Handle config set command
fn handle_set(matches: &ArgMatches, display: &Display) -> PinGuardResult<()> {
    let key = matches.get_one::<String>("key").unwrap();
    let value = matches.get_one::<String>("value").unwrap();
    
    display.info(&format!("Setting configuration: {} = {}", key, value));
    
    // For now, just show what would be set
    // In a full implementation, this would update the config file
    display.warning("Configuration setting is not yet implemented");
    display.info("This would set the configuration value in the config file");
    
    Ok(())
}

/// Handle config get command
fn handle_get(matches: &ArgMatches, config: &Config, display: &Display) -> PinGuardResult<()> {
    let key = matches.get_one::<String>("key").unwrap();
    
    // Simple key matching for basic config values
    match key.as_str() {
        "app.name" => println!("{}", config.app.name),
        "app.version" => println!("{}", config.app.version),
        "app.log_level" => println!("{}", config.app.log_level),
        "database.path" => println!("{}", config.database.path),
        "report.format" => println!("{}", config.report.format),
        "report.output_dir" => println!("{}", config.report.output_dir),
        "cve.api_url" => println!("{}", config.cve.api_url),
        _ => {
            display.error(&format!("Configuration key not found: {}", key));
            display.info("Available keys: app.name, app.version, app.log_level, database.path, report.format, report.output_dir, cve.api_url");
        }
    }
    
    Ok(())
}