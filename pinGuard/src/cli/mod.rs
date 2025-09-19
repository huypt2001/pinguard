//! CLI module for PinGuard - Enhanced user interface
//! Provides a comprehensive command-line interface with ASCII logo,
//! interactive commands, and user-friendly features.

pub mod app;
pub mod commands;
pub mod display;
pub mod help;
pub mod interactive;

use crate::core::{config::Config, errors::PinGuardResult};
use clap::{Arg, ArgMatches, Command};
use display::Display;

/// Main CLI application entry point
pub struct CliApp {
    display: Display,
}

impl CliApp {
    /// Create a new CLI application instance
    pub fn new() -> Self {
        Self {
            display: Display::new(),
        }
    }

    /// Run the CLI application
    pub fn run(&self) -> PinGuardResult<()> {
        // Show logo and welcome message
        self.display.show_logo();
        
        let app = self.build_app();
        let matches = app.get_matches();

        // Load configuration
        let config = self.load_config(&matches)?;
        
        // Set up logging based on verbosity
        self.setup_logging(&matches, &config)?;

        // Handle commands
        self.handle_command(&matches, &config)
    }

    /// Build the CLI application with all commands and arguments
    fn build_app(&self) -> Command {
        app::build_cli_app()
    }

    /// Load configuration from file or environment
    fn load_config(&self, matches: &ArgMatches) -> PinGuardResult<Config> {
        let config_path = matches
            .get_one::<String>("config")
            .map(|s| s.as_str())
            .unwrap_or("config.yaml");

        match Config::load_from_file(config_path) {
            Ok(config) => {
                self.display.success(&format!("Configuration loaded: {}", config_path));
                Ok(config)
            }
            Err(_) => {
                self.display.warning("Config file not found, using defaults");
                Ok(Config::default_config())
            }
        }
    }

    /// Set up logging based on CLI arguments and config
    fn setup_logging(&self, matches: &ArgMatches, config: &Config) -> PinGuardResult<()> {
        use tracing::Level;
        use tracing_subscriber::FmtSubscriber;

        let level = if matches.get_flag("verbose") {
            Level::DEBUG
        } else if matches.get_flag("quiet") {
            Level::ERROR
        } else {
            match config.app.log_level.as_str() {
                "trace" => Level::TRACE,
                "debug" => Level::DEBUG,
                "info" => Level::INFO,
                "warn" => Level::WARN,
                "error" => Level::ERROR,
                _ => Level::INFO,
            }
        };

        let subscriber = FmtSubscriber::builder()
            .with_max_level(level)
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| crate::core::errors::PinGuardError::Config {
                message: format!("Failed to set up logging: {}", e),
                source: None,
            })?;

        Ok(())
    }

    /// Handle the main command and dispatch to appropriate handlers
    fn handle_command(&self, matches: &ArgMatches, config: &Config) -> PinGuardResult<()> {
        match matches.subcommand() {
            Some(("scan", sub_matches)) => commands::scan::handle(sub_matches, config, &self.display),
            Some(("fix", sub_matches)) => commands::fix::handle(sub_matches, config, &self.display),
            Some(("report", sub_matches)) => commands::report::handle(sub_matches, config, &self.display),
            Some(("config", sub_matches)) => commands::config::handle(sub_matches, config, &self.display),
            Some(("database", sub_matches)) => commands::database::handle(sub_matches, config, &self.display),
            Some(("cve", sub_matches)) => commands::cve::handle(sub_matches, config, &self.display),
            Some(("schedule", sub_matches)) => commands::schedule::handle(sub_matches, config, &self.display),
            Some(("backup", sub_matches)) => commands::backup::handle(sub_matches, config, &self.display),
            Some(("interactive", _)) => interactive::run_interactive_mode(config, &self.display),
            Some(("completion", sub_matches)) => commands::completion::handle(sub_matches),
            Some(("version", _)) => {
                self.display.info(&format!("PinGuard v{}", env!("CARGO_PKG_VERSION")));
                Ok(())
            }
            _ => {
                self.display.show_quick_help();
                Ok(())
            }
        }
    }
}

impl Default for CliApp {
    fn default() -> Self {
        Self::new()
    }
}