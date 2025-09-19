use tracing::error;

mod cli;
mod core;
mod cve;
mod database;
mod fixers;
mod report;
mod scanners;
mod scheduler;

use cli::CliApp;

fn main() {
    // Run the enhanced CLI application
    let cli_app = CliApp::new();
    
    if let Err(e) = cli_app.run() {
        error!("PinGuard failed: {}", e);
        std::process::exit(1);
    }
}