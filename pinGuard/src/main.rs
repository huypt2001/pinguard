use tracing::error;
use clap::{Arg, Command};

mod cli;
mod core;
mod cve;
mod database;
mod fixers;
mod report;
mod scanners;
mod scheduler;
mod backup;

#[cfg(feature = "tui")]
mod tui;

use cli::CliApp;

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let matches = Command::new("pinGuard")
        .version("0.1.2")
        .about("🛡️ Linux-first Vulnerability Scanner & Remediator")
        .arg(
            Arg::new("cli")
                .long("cli")
                .help("Use traditional CLI interface instead of TUI")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("mode")
                .long("mode")
                .value_name("MODE")
                .help("Interface mode: tui, cli (deprecated, use --cli instead)")
                .value_parser(["tui", "cli"])
                .hide(true), // Hide deprecated option
        )
        .get_matches();

    // Default to TUI unless --cli flag is used
    let use_cli = matches.get_flag("cli") || 
        matches.get_one::<String>("mode").map(|s| s.as_str()) == Some("cli");

    // Check if TUI is available and terminal supports it (unless CLI explicitly requested)
    #[cfg(feature = "tui")]
    let tui_available = !use_cli && atty::is(atty::Stream::Stdout);
    
    #[cfg(not(feature = "tui"))]
    let tui_available = false;

    if tui_available {
        #[cfg(feature = "tui")]
        {
            // Run TUI mode
            if let Err(e) = tui::run_tui().await {
                error!("TUI failed: {}", e);
                eprintln!("❌ TUI mode failed, falling back to CLI mode...");
                run_cli_mode();
            }
        }
    } else {
        // Run CLI mode
        run_cli_mode();
    }
}

fn run_cli_mode() {
    let cli_app = CliApp::new();
    
    if let Err(e) = cli_app.run() {
        error!("PinGuard failed: {}", e);
        std::process::exit(1);
    }
}