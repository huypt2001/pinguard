use crate::backup::{BackupManager, BackupConfig};
use crate::core::{config::Config, errors::PinGuardResult};
use crate::cli::display::Display;
use clap::ArgMatches;
use std::path::PathBuf;

pub fn handle(matches: &ArgMatches, config: &Config, display: &Display) -> PinGuardResult<()> {
    match matches.subcommand() {
        Some(("create", sub_matches)) => handle_create_backup(sub_matches, config, display),
        Some(("list", sub_matches)) => handle_list_backups(sub_matches, config, display),
        Some(("stats", sub_matches)) => handle_backup_stats(sub_matches, config, display),
        _ => {
            display.error("Invalid backup command. Use --help for available options.");
            display.info("Available commands: create, list, stats");
            display.info("Example: pinGuard backup create --description 'Pre-update backup'");
            Ok(())
        }
    }
}

fn handle_create_backup(matches: &ArgMatches, config: &Config, display: &Display) -> PinGuardResult<()> {
    display.info("🔄 Creating system backup...");

    let description = matches
        .get_one::<String>("description")
        .map(|s| s.clone())
        .unwrap_or_else(|| "Manual backup created via CLI".to_string());

    let paths = if let Some(path_args) = matches.get_many::<String>("paths") {
        path_args.map(|p| PathBuf::from(p)).collect()
    } else {
        vec![
            PathBuf::from("/etc"),
            PathBuf::from("/usr/local"),
            PathBuf::from("/var/log"),
        ]
    };

    // Create backup configuration
    let backup_config = create_backup_config(config);

    // Create backup manager and take snapshot
    match BackupManager::new(backup_config) {
        Ok(mut backup_manager) => {
            match backup_manager.create_pre_change_snapshot(description.clone(), &paths) {
                Ok(snapshot_id) => {
                    display.success(&format!("✅ Backup created successfully: {}", snapshot_id));
                    display.info(&format!("📁 Backup location: {}", config.fixer.backup_dir));
                    display.info(&format!("📝 Description: {}", description));
                    display.info(&format!("📂 Backed up {} paths", paths.len()));
                }
                Err(e) => {
                    display.error(&format!("❌ Failed to create backup: {}", e));
                }
            }
        }
        Err(e) => {
            display.error(&format!("❌ Failed to initialize backup manager: {}", e));
        }
    }

    Ok(())
}

fn handle_list_backups(_matches: &ArgMatches, config: &Config, display: &Display) -> PinGuardResult<()> {
    display.info("📋 Listing available backups...");

    let backup_config = create_backup_config(config);
    
    match BackupManager::new(backup_config) {
        Ok(backup_manager) => {
            let snapshots = backup_manager.list_snapshots();
            
            if snapshots.is_empty() {
                display.warning("No backups found.");
                return Ok(());
            }

            display.info(&format!("Found {} backup(s):", snapshots.len()));
            display.info("");

            for snapshot in &snapshots {
                display.info(&format!("� ID: {}", snapshot.id));
                display.info(&format!("  📝 Description: {}", snapshot.description));
                display.info(&format!("  📅 Created: {}", snapshot.created_at));
                display.info(&format!("  📊 Type: {:?}", snapshot.backup_type));
                display.info("");
            }
        }
        Err(e) => {
            display.error(&format!("❌ Failed to list backups: {}", e));
        }
    }

    Ok(())
}

fn handle_backup_stats(_matches: &ArgMatches, config: &Config, display: &Display) -> PinGuardResult<()> {
    display.info("📊 Backup System Statistics");
    display.info("===========================");

    let backup_config = create_backup_config(config);
    
    match BackupManager::new(backup_config) {
        Ok(backup_manager) => {
            let stats = backup_manager.get_backup_statistics();
            
            display.info(&format!("📈 Total backups: {}", stats.total_backups));
            display.info(&format!("✅ Successful backups: {}", stats.successful_backups));
            display.info(&format!("❌ Failed backups: {}", stats.failed_backups));
            display.info(&format!("📊 Success rate: {:.1}%", stats.success_rate_percentage));
            display.info(&format!("💾 Total storage used: {:.1} MB", stats.total_size_bytes as f64 / 1024.0 / 1024.0));
            
            if stats.total_backups > 0 {
                let avg_size = stats.total_size_bytes as f64 / stats.total_backups as f64 / 1024.0 / 1024.0;
                display.info(&format!("📏 Average backup size: {:.1} MB", avg_size));
            }
            
            display.info(&format!("📁 Backup directory: {}", config.fixer.backup_dir));
            
            // Show recent activity if available
            let snapshots = backup_manager.list_snapshots();
            if !snapshots.is_empty() {
                display.info("");
                display.info("🕒 Recent Backups (last 5):");
                for snapshot in snapshots.iter().take(5) {
                    display.info(&format!("  - {} ({})", snapshot.id, snapshot.created_at));
                }
            }
        }
        Err(e) => {
            display.error(&format!("❌ Failed to get backup statistics: {}", e));
        }
    }

    Ok(())
}

fn create_backup_config(config: &Config) -> BackupConfig {
    BackupConfig {
        backup_dir: PathBuf::from(&config.fixer.backup_dir),
        max_backups: 50,
        compression_enabled: true,
        integrity_checks: true,
        auto_cleanup: true,
        retention_days: 30,
        included_paths: vec![
            PathBuf::from("/etc"),
            PathBuf::from("/usr/local"),
            PathBuf::from("/var/log"),
        ],
        excluded_paths: vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
        ],
        ..Default::default()
    }
}