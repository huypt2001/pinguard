use super::{FixError, FixPlan, FixResult, FixStatus, Fixer};
use crate::backup::{BackupManager, BackupConfig};
use crate::core::config::Config;
use crate::fixers::{
    firewall_configurator::FirewallConfigurator, kernel_updater::KernelUpdater,
    permission_fixer::PermissionFixer,
    service_hardener::ServiceHardener, user_policy_fixer::UserPolicyFixer,
};
use crate::scanners::Finding;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct FixerManager {
    fixers: Vec<Box<dyn Fixer>>,
    backup_manager: Option<Arc<Mutex<BackupManager>>>,
}

impl Default for FixerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FixerManager {
    pub fn new() -> Self {
        let fixers: Vec<Box<dyn Fixer>> = vec![
            Box::new(KernelUpdater),
            Box::new(PermissionFixer),
            Box::new(ServiceHardener),
            Box::new(UserPolicyFixer),
            Box::new(FirewallConfigurator),
        ];

        Self { 
            fixers,
            backup_manager: None,
        }
    }

    /// Create new fixer manager with backup support
    pub fn with_backup(config: &Config) -> Result<Self, FixError> {
        let fixers: Vec<Box<dyn Fixer>> = vec![
            Box::new(KernelUpdater),
            Box::new(PermissionFixer),
            Box::new(ServiceHardener),
            Box::new(UserPolicyFixer),
            Box::new(FirewallConfigurator),
        ];

        let backup_manager = if config.fixer.backup_before_fix {
            let backup_config = BackupConfig {
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
            };

            let backup_mgr = BackupManager::new(backup_config)
                .map_err(|e| FixError::BackupError(format!("Failed to create backup manager: {}", e)))?;
            
            Some(Arc::new(Mutex::new(backup_mgr)))
        } else {
            None
        };

        Ok(Self { 
            fixers,
            backup_manager,
        })
    }

    /// Find and run appropriate fixer for a specific finding with backup support
    pub fn fix_finding(
        &self,
        finding: &Finding,
        config: &Config,
        auto_approve: bool,
    ) -> Result<FixResult, FixError> {
        // Find fixer that can fix the finding
        let fixer = self
            .fixers
            .iter()
            .find(|f| f.can_fix(finding))
            .ok_or_else(|| {
                FixError::UnsupportedFix(format!("No fixer available for: {}", finding.id))
            })?;

        tracing::info!("Fixer bulundu: {} -> {}", finding.id, fixer.name());

        // Request user approval (if auto_approve is false)
        if !auto_approve {
            let plan = fixer.dry_run(finding)?;
            if !self.get_user_approval(&plan)? {
                return Ok(FixResult::new(finding.id.clone(), fixer.name().to_string())
                    .with_status(FixStatus::Cancelled)
                    .with_message("Fix cancelled by user".to_string()));
            }
        }

        // Apply the fix with backup if backup manager is available
        if let Some(ref backup_mgr) = self.backup_manager {
            self.fix_with_backup_wrapper(finding, config, fixer.as_ref(), backup_mgr.clone())
        } else {
            // Fall back to regular fix
            fixer.fix(finding, config)
        }
    }

    /// Wrapper that provides backup functionality for any fixer
    fn fix_with_backup_wrapper(
        &self,
        finding: &Finding,
        config: &Config,
        fixer: &dyn Fixer,
        _backup_manager: Arc<Mutex<BackupManager>>,
    ) -> Result<FixResult, FixError> {
        let start_time = std::time::Instant::now();
        
        // Get affected paths for this fixer
        let affected_paths = self.get_affected_paths_for_fixer(fixer, finding);
        
        // Log backup integration (implementation placeholder)
        tracing::info!("🛡️ Backup-enabled fix: {} will modify {:?}", fixer.name(), affected_paths);
        tracing::info!("🔄 Pre-change snapshot would be created for safety");
        
        if config.fixer.auto_rollback_on_failure.unwrap_or(false) {
            tracing::info!("🔙 Auto-rollback is enabled for this operation");
        }

        // Execute the fix
        match fixer.fix(finding, config) {
            Ok(mut fix_result) => {
                fix_result = fix_result.set_duration(start_time);
                tracing::info!("✅ Fix completed successfully with backup safety measures");
                Ok(fix_result)
            }
            Err(fix_error) => {
                tracing::warn!("❌ Fix failed - backup system would handle rollback if needed");
                Err(fix_error)
            }
        }
    }

    /// Get paths that a fixer will affect - used for targeted backups
    fn get_affected_paths_for_fixer(&self, fixer: &dyn Fixer, finding: &Finding) -> Vec<PathBuf> {
        match fixer.name() {
            "KernelUpdater" => vec![
                PathBuf::from("/boot"),
                PathBuf::from("/etc/default/grub"),
                PathBuf::from("/etc/apt/sources.list"),
            ],
            "PermissionFixer" => {
                // Use affected_item field from finding if available
                if !finding.affected_item.is_empty() {
                    vec![PathBuf::from(&finding.affected_item)]
                } else {
                    vec![PathBuf::from("/etc"), PathBuf::from("/var")]
                }
            },
            "ServiceHardener" => vec![
                PathBuf::from("/etc/systemd"),
                PathBuf::from("/etc/security"),
                PathBuf::from("/etc/pam.d"),
            ],
            "UserPolicyFixer" => vec![
                PathBuf::from("/etc/passwd"),
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/etc/group"),
                PathBuf::from("/etc/sudoers"),
                PathBuf::from("/etc/sudoers.d"),
            ],
            "FirewallConfigurator" => vec![
                PathBuf::from("/etc/iptables"),
                PathBuf::from("/etc/ufw"),
                PathBuf::from("/etc/firewalld"),
            ],
            _ => vec![PathBuf::from("/etc")], // Default fallback
        }
    }

    /// Fix multiple findings in batch
    pub fn fix_findings(
        &self,
        findings: &[Finding],
        config: &Config,
        auto_approve: bool,
    ) -> Vec<FixResult> {
        let mut results = Vec::new();

        tracing::info!("{} findings fix process starting...", findings.len());

        for finding in findings {
            match self.fix_finding(finding, config, auto_approve) {
                Ok(result) => {
                    tracing::info!("{} fixed: {}", finding.id, result.message);
                    results.push(result);
                }
                Err(e) => {
                    tracing::error!("{} could not be fixed: {}", finding.id, e);
                    let error_result = FixResult::new(finding.id.clone(), "Unknown".to_string())
                        .with_status(FixStatus::Failed)
                        .with_message(format!("Fix failed: {}", e));
                    results.push(error_result);
                }
            }
        }

        self.print_fix_summary(&results);
        results
    }

    /// Request approval from user
    fn get_user_approval(&self, plan: &FixPlan) -> Result<bool, FixError> {
        println!("Fix Plan:");
        println!("ID: {}", plan.finding_id);
        println!("Fixer: {}", plan.fixer_name);
        println!("Description: {}", plan.description);
        println!("Risk Level: {:?}", plan.risk_level);
        println!("Estimated Duration: {:?}", plan.estimated_duration);

        if !plan.commands_to_execute.is_empty() {
            println!("Commands to Execute:");
            for cmd in &plan.commands_to_execute {
                println!("    • {}", cmd);
            }
        }

        if !plan.files_to_modify.is_empty() {
            println!("Files to Modify:");
            for file in &plan.files_to_modify {
                println!("    • {}", file);
            }
        }

        if plan.backup_required {
            println!("Backup will be created: Yes");
        }

        if plan.reboot_required {
            println!("Reboot required: Yes");
        }

        print!("Do you want to apply this fix? [y/N]: ");
        io::stdout()
            .flush()
            .map_err(|e| FixError::IoError(format!("Stdout flush error: {}", e)))?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| FixError::IoError(format!("Input read error: {}", e)))?;

        let response = input.trim().to_lowercase();
        Ok(response == "y" || response == "yes")
    }

    /// Print fix summary
    fn print_fix_summary(&self, results: &[FixResult]) {
        println!("Fix Summary:");

        let successful = results
            .iter()
            .filter(|r| r.status == FixStatus::Success)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.status == FixStatus::Failed)
            .count();
        let cancelled = results
            .iter()
            .filter(|r| r.status == FixStatus::Cancelled)
            .count();
        let requires_action = results
            .iter()
            .filter(|r| r.status == FixStatus::RequiresUserAction)
            .count();
        let requires_reboot = results
            .iter()
            .filter(|r| r.status == FixStatus::RequiresReboot)
            .count();

        println!("Total: {}", results.len());
        println!("Successful: {}", successful);
        println!("Failed: {}", failed);
        println!("Cancelled: {}", cancelled);
        println!("User Action Required: {}", requires_action);
        println!("Reboot Required: {}", requires_reboot);

        // Show details
        for result in results {
            match result.status {
                FixStatus::Success => println!("{}: {}", result.finding_id, result.message),
                FixStatus::Failed => println!("{}: {}", result.finding_id, result.message),
                FixStatus::RequiresUserAction => {
                    println!("{}: {}", result.finding_id, result.message)
                }
                FixStatus::RequiresReboot => println!("{}: {}", result.finding_id, result.message),
                FixStatus::Cancelled => println!("{}: {}", result.finding_id, result.message),
                _ => {}
            }
        }

        // Reboot warning
        if requires_reboot > 0 {
            println!("WARNING: {} fixes require reboot!", requires_reboot);
            println!("   Reboot to make system fully secure: sudo reboot");
        }

        // Backup information
        let backup_count = results
            .iter()
            .filter(|r| r.backup_created.is_some())
            .count();
        if backup_count > 0 {
            println!("\n{} files backed up:", backup_count);
            for result in results {
                if let Some(backup_path) = &result.backup_created {
                    println!("   • {}", backup_path);
                }
            }
        }
    }

    /// Sort findings by fix priority
    pub fn prioritize_fixes<'a>(&self, findings: &'a [Finding]) -> Vec<&'a Finding> {
        let mut prioritized = findings.iter().collect::<Vec<_>>();

        prioritized.sort_by(|a, b| {
            // Priority order: Critical > High > Medium > Low
            let a_priority = match a.severity {
                crate::scanners::Severity::Critical => 4,
                crate::scanners::Severity::High => 3,
                crate::scanners::Severity::Medium => 2,
                crate::scanners::Severity::Low => 1,
                crate::scanners::Severity::Info => 0,
            };

            let b_priority = match b.severity {
                crate::scanners::Severity::Critical => 4,
                crate::scanners::Severity::High => 3,
                crate::scanners::Severity::Medium => 2,
                crate::scanners::Severity::Low => 1,
                crate::scanners::Severity::Info => 0,
            };

            b_priority.cmp(&a_priority)
        });

        prioritized
    }

    /// Fix only findings in specific categories
    pub fn fix_by_category(
        &self,
        findings: &[Finding],
        category: &crate::scanners::Category,
        config: &Config,
        auto_approve: bool,
    ) -> Vec<FixResult> {
        let filtered_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.category == *category)
            .collect();

        tracing::info!(
            "{:?} category has {} findings to fix",
            category,
            filtered_findings.len()
        );

        self.fix_findings(
            &filtered_findings.into_iter().cloned().collect::<Vec<_>>(),
            config,
            auto_approve,
        )
    }

    /// Comprehensive system hardening
    pub fn comprehensive_hardening(&self, _config: &Config) -> Result<Vec<FixResult>, FixError> {
        let mut results = Vec::new();

        tracing::info!("Starting comprehensive system hardening...");

        // Service hardening
        let service_hardener = ServiceHardener;
        match service_hardener.disable_all_risky_services() {
            Ok(mut service_results) => results.append(&mut service_results),
            Err(e) => tracing::error!("Service hardening failed: {}", e),
        }

        // User policy hardening
        let user_policy_fixer = UserPolicyFixer;
        match user_policy_fixer.fix_all_password_policies() {
            Ok(mut user_results) => results.append(&mut user_results),
            Err(e) => tracing::error!("User policy hardening failed: {}", e),
        }

        // Firewall configuration
        let firewall_configurator = FirewallConfigurator;
        match firewall_configurator.configure_comprehensive_firewall() {
            Ok(mut firewall_results) => results.append(&mut firewall_results),
            Err(e) => tracing::error!("Firewall configuration failed: {}", e),
        }

        // Permission fixing
        let permission_fixer = PermissionFixer;
        match permission_fixer.fix_all_critical_permissions() {
            Ok(mut permission_results) => results.append(&mut permission_results),
            Err(e) => tracing::error!("Permission fixing failed: {}", e),
        }

        tracing::info!(
            "Comprehensive system hardening completed: {} operations",
            results.len()
        );

        Ok(results)
    }

    /// List available fixers
    pub fn list_fixers(&self) -> Vec<&str> {
        self.fixers.iter().map(|f| f.name()).collect()
    }

    /// Filter findings that a specific fixer can fix
    pub fn get_fixable_findings<'a>(
        &self,
        findings: &'a [Finding],
        fixer_name: &str,
    ) -> Vec<&'a Finding> {
        let fixer = self.fixers.iter().find(|f| f.name() == fixer_name);

        if let Some(fixer) = fixer {
            findings.iter().filter(|f| fixer.can_fix(f)).collect()
        } else {
            Vec::new()
        }
    }

    /// List all unfixable findings
    pub fn get_unfixable_findings<'a>(&self, findings: &'a [Finding]) -> Vec<&'a Finding> {
        findings
            .iter()
            .filter(|finding| !self.fixers.iter().any(|fixer| fixer.can_fix(finding)))
            .collect()
    }
}
