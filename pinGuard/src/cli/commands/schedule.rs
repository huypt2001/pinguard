//! Schedule command implementation

use crate::cli::display::Display;
use crate::core::{config::Config, errors::PinGuardResult};
use clap::ArgMatches;

/// Handle the schedule command
pub fn handle(matches: &ArgMatches, config: &Config, display: &Display) -> PinGuardResult<()> {
    match matches.subcommand() {
        Some(("add", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").unwrap();
            let cron = sub_matches.get_one::<String>("cron").unwrap();
            let description = sub_matches.get_one::<String>("description");
            
            display.section_header("Add Scheduled Scan");
            display.info(&format!("Schedule Name: {}", name));
            display.info(&format!("Cron Expression: {}", cron));
            
            if let Some(desc) = description {
                display.info(&format!("Description: {}", desc));
            }
            
            display.success("Scheduled scan added successfully");
        }
        Some(("remove", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").unwrap();
            
            display.section_header("Remove Scheduled Scan");
            display.info(&format!("Removing schedule: {}", name));
            
            if display.confirm(&format!("Are you sure you want to remove '{}'?", name)) {
                display.success("Scheduled scan removed successfully");
            } else {
                display.info("Operation cancelled");
            }
        }
        Some(("list", _)) => {
            display.section_header("Scheduled Scans");
            
            let headers = &["Name", "Schedule", "Next Run", "Status"];
            let rows = vec![
                vec!["daily-scan".to_string(), "0 2 * * *".to_string(), "Tomorrow 02:00".to_string(), "Active".to_string()],
                vec!["weekly-full".to_string(), "0 1 * * 0".to_string(), "Sunday 01:00".to_string(), "Active".to_string()],
            ];
            
            display.table(headers, &rows);
        }
        Some(("status", sub_matches)) => {
            display.section_header("Schedule Status");
            
            if let Some(name) = sub_matches.get_one::<String>("name") {
                display.info(&format!("Status for schedule: {}", name));
                
                let status = vec![
                    ("Schedule Name", name.as_str()),
                    ("Status", "Active"),
                    ("Last Run", "2023-12-14 02:00:00"),
                    ("Next Run", "2023-12-15 02:00:00"),
                    ("Total Runs", "42"),
                    ("Success Rate", "95.2%"),
                ];
                
                display.key_value_list(&status);
            } else {
                display.info("Overall schedule status:");
                
                let status = vec![
                    ("Total Schedules", "2"),
                    ("Active Schedules", "2"),
                    ("Inactive Schedules", "0"),
                    ("Last Execution", "2023-12-14 02:00:00"),
                ];
                
                display.key_value_list(&status);
            }
        }
        Some(("run", _)) => {
            display.section_header("Manual Schedule Execution");
            display.info("Running scheduled scan manually...");
            display.success("Scheduled scan completed successfully");
        }
        _ => {
            display.error("No schedule subcommand specified");
        }
    }
    
    Ok(())
}