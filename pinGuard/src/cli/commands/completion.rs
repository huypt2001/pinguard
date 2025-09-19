//! Shell completion generation

use clap::ArgMatches;
use clap_complete::{generate, Shell};
use std::io;

/// Handle the completion command
pub fn handle(matches: &ArgMatches) -> crate::core::errors::PinGuardResult<()> {
    let shell = matches.get_one::<String>("shell").unwrap();
    let mut app = crate::cli::app::build_cli_app();
    let app_name = app.get_name().to_string();
    
    let shell_type = match shell.as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" => Shell::PowerShell,
        _ => {
            eprintln!("Unsupported shell: {}", shell);
            return Ok(());
        }
    };
    
    if let Some(output_file) = matches.get_one::<String>("output") {
        let mut file = std::fs::File::create(output_file)
            .map_err(|e| crate::core::errors::PinGuardError::Io {
                message: format!("Failed to create output file {}: {}", output_file, e),
                source: None,
            })?;
        generate(shell_type, &mut app, app_name, &mut file);
        println!("Completion script written to: {}", output_file);
    } else {
        generate(shell_type, &mut app, app_name, &mut io::stdout());
    }
    
    Ok(())
}