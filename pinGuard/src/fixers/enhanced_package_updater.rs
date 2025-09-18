//! Enhanced package updater fixer using the new trait system

use crate::core::{
    enhanced_config::Config, Category, ErrorContext, Finding, Fixer, 
    FixResult, FixStatus, PinGuardResult,
};
use crate::core::traits::{FixAction, FixPlan};
use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Package updater fixer that can update outdated packages and apply security updates
pub struct PackageUpdaterFixer {
    version: String,
}

impl PackageUpdaterFixer {
    /// Create a new package updater fixer
    pub fn new() -> Self {
        Self {
            version: "1.0.0".to_string(),
        }
    }

    /// Detect the package manager on the system
    async fn detect_package_manager(&self) -> PinGuardResult<String> {
        let managers = vec![
            ("apt", "which apt"),
            ("dnf", "which dnf"),
            ("yum", "which yum"),
            ("zypper", "which zypper"),
            ("pacman", "which pacman"),
        ];

        for (manager, command) in managers {
            let output = Command::new("sh")
                .arg("-c")
                .arg(command)
                .output()
                .await
                .with_fixer_context("package_updater", || {
                    format!("Failed to check for {}", manager)
                })?;

            if output.status.success() {
                debug!("Detected package manager: {}", manager);
                return Ok(manager.to_string());
            }
        }

        Err(crate::core::PinGuardError::fixer(
            "package_updater",
            "No supported package manager found",
        ))
    }

    /// Extract package name from finding
    fn extract_package_name(&self, finding: &Finding) -> Option<String> {
        // Try different ways to extract package name
        if finding.id.starts_with("outdated-package-") {
            return Some(finding.id.replace("outdated-package-", ""));
        }

        if finding.category == Category::Package {
            return Some(finding.affected_item.clone());
        }

        if let Some(package_name) = finding.metadata.get("package_name") {
            return Some(package_name.clone());
        }

        // Try to extract from affected_item
        Some(finding.affected_item.clone())
    }

    /// Create fix plan for apt-based systems
    async fn create_apt_plan(&self, finding: &Finding) -> PinGuardResult<FixPlan> {
        let package_name = self
            .extract_package_name(finding)
            .unwrap_or_else(|| "unknown".to_string());

        let actions = vec![
            FixAction {
                description: "Update package lists".to_string(),
                command: Some("apt update".to_string()),
                files_modified: vec!["/var/lib/apt/lists/".to_string()],
                reversible: false,
            },
            FixAction {
                description: format!("Upgrade package: {}", package_name),
                command: Some(format!("apt install --only-upgrade -y {}", package_name)),
                files_modified: vec![format!("/var/lib/dpkg/info/{}.list", package_name)],
                reversible: false,
            },
        ];

        Ok(FixPlan {
            fixer_name: self.name().to_string(),
            finding_id: finding.id.clone(),
            actions,
            estimated_duration: Duration::from_secs(120),
            requires_reboot: false,
            backup_required: false,
            risks: vec![
                "Package upgrade may introduce breaking changes".to_string(),
                "Dependencies may be modified".to_string(),
            ],
        })
    }

    /// Create fix plan for dnf/yum-based systems
    async fn create_dnf_plan(&self, finding: &Finding, manager: &str) -> PinGuardResult<FixPlan> {
        let package_name = self
            .extract_package_name(finding)
            .unwrap_or_else(|| "unknown".to_string());

        let actions = vec![
            FixAction {
                description: "Check for available updates".to_string(),
                command: Some(format!("{} check-update", manager)),
                files_modified: vec![],
                reversible: false,
            },
            FixAction {
                description: format!("Update package: {}", package_name),
                command: Some(format!("{} update -y {}", manager, package_name)),
                files_modified: vec![format!("/var/lib/rpm/{}", package_name)],
                reversible: false,
            },
        ];

        Ok(FixPlan {
            fixer_name: self.name().to_string(),
            finding_id: finding.id.clone(),
            actions,
            estimated_duration: Duration::from_secs(180),
            requires_reboot: package_name.contains("kernel"),
            backup_required: false,
            risks: vec![
                "Package upgrade may introduce breaking changes".to_string(),
                if package_name.contains("kernel") {
                    "Kernel update requires system reboot".to_string()
                } else {
                    "Service restart may be required".to_string()
                },
            ],
        })
    }

    /// Create fix plan for pacman-based systems
    async fn create_pacman_plan(&self, finding: &Finding) -> PinGuardResult<FixPlan> {
        let package_name = self
            .extract_package_name(finding)
            .unwrap_or_else(|| "unknown".to_string());

        let actions = vec![
            FixAction {
                description: "Synchronize package databases".to_string(),
                command: Some("pacman -Sy".to_string()),
                files_modified: vec!["/var/lib/pacman/sync/".to_string()],
                reversible: false,
            },
            FixAction {
                description: format!("Update package: {}", package_name),
                command: Some(format!("pacman -S --noconfirm {}", package_name)),
                files_modified: vec![format!("/var/lib/pacman/local/{}", package_name)],
                reversible: false,
            },
        ];

        Ok(FixPlan {
            fixer_name: self.name().to_string(),
            finding_id: finding.id.clone(),
            actions,
            estimated_duration: Duration::from_secs(90),
            requires_reboot: false,
            backup_required: false,
            risks: vec![
                "Package upgrade may introduce breaking changes".to_string(),
                "System may need restart for some updates".to_string(),
            ],
        })
    }

    /// Execute fix with apt
    async fn fix_with_apt(&self, finding: &Finding) -> PinGuardResult<FixResult> {
        let start_time = Instant::now();
        let package_name = self
            .extract_package_name(finding)
            .unwrap_or_else(|| "unknown".to_string());

        info!("Updating package '{}' with apt", package_name);

        // Update package lists
        let update_output = Command::new("apt")
            .args(&["update"])
            .output()
            .await
            .with_fixer_context("package_updater", || "Failed to update package lists".to_string())?;

        if !update_output.status.success() {
            return Ok(FixResult {
                finding_id: finding.id.clone(),
                fixer_name: self.name().to_string(),
                status: FixStatus::Failed("Failed to update package lists".to_string()),
                message: String::from_utf8_lossy(&update_output.stderr).to_string(),
                actions_taken: vec![],
                duration: start_time.elapsed(),
                backup_created: None,
                requires_reboot: false,
            });
        }

        // Upgrade the specific package
        let upgrade_output = Command::new("apt")
            .args(&["install", "--only-upgrade", "-y", &package_name])
            .output()
            .await
            .with_fixer_context("package_updater", || {
                format!("Failed to upgrade package {}", package_name)
            })?;

        let status = if upgrade_output.status.success() {
            FixStatus::Success
        } else {
            FixStatus::Failed(format!(
                "Package upgrade failed: {}",
                String::from_utf8_lossy(&upgrade_output.stderr)
            ))
        };

        let actions_taken = vec![
            FixAction {
                description: "Updated package lists".to_string(),
                command: Some("apt update".to_string()),
                files_modified: vec![],
                reversible: false,
            },
            FixAction {
                description: format!("Upgraded package: {}", package_name),
                command: Some(format!("apt install --only-upgrade -y {}", package_name)),
                files_modified: vec![],
                reversible: false,
            },
        ];

        Ok(FixResult {
            finding_id: finding.id.clone(),
            fixer_name: self.name().to_string(),
            status,
            message: format!("Package '{}' update completed", package_name),
            actions_taken,
            duration: start_time.elapsed(),
            backup_created: None,
            requires_reboot: false,
        })
    }

    /// Execute fix with dnf/yum
    async fn fix_with_dnf(&self, finding: &Finding, manager: &str) -> PinGuardResult<FixResult> {
        let start_time = Instant::now();
        let package_name = self
            .extract_package_name(finding)
            .unwrap_or_else(|| "unknown".to_string());

        info!("Updating package '{}' with {}", package_name, manager);

        // Update the package
        let update_output = Command::new(manager)
            .args(&["update", "-y", &package_name])
            .output()
            .await
            .with_fixer_context("package_updater", || {
                format!("Failed to update package {} with {}", package_name, manager)
            })?;

        let status = if update_output.status.success() {
            FixStatus::Success
        } else {
            FixStatus::Failed(format!(
                "Package update failed: {}",
                String::from_utf8_lossy(&update_output.stderr)
            ))
        };

        let requires_reboot = package_name.contains("kernel");

        let actions_taken = vec![FixAction {
            description: format!("Updated package: {}", package_name),
            command: Some(format!("{} update -y {}", manager, package_name)),
            files_modified: vec![],
            reversible: false,
        }];

        Ok(FixResult {
            finding_id: finding.id.clone(),
            fixer_name: self.name().to_string(),
            status,
            message: format!("Package '{}' update completed", package_name),
            actions_taken,
            duration: start_time.elapsed(),
            backup_created: None,
            requires_reboot,
        })
    }

    /// Execute fix with pacman
    async fn fix_with_pacman(&self, finding: &Finding) -> PinGuardResult<FixResult> {
        let start_time = Instant::now();
        let package_name = self
            .extract_package_name(finding)
            .unwrap_or_else(|| "unknown".to_string());

        info!("Updating package '{}' with pacman", package_name);

        // Sync databases
        let sync_output = Command::new("pacman")
            .args(&["-Sy"])
            .output()
            .await
            .with_fixer_context("package_updater", || "Failed to sync package databases".to_string())?;

        if !sync_output.status.success() {
            return Ok(FixResult {
                finding_id: finding.id.clone(),
                fixer_name: self.name().to_string(),
                status: FixStatus::Failed("Failed to sync package databases".to_string()),
                message: String::from_utf8_lossy(&sync_output.stderr).to_string(),
                actions_taken: vec![],
                duration: start_time.elapsed(),
                backup_created: None,
                requires_reboot: false,
            });
        }

        // Update the package
        let update_output = Command::new("pacman")
            .args(&["-S", "--noconfirm", &package_name])
            .output()
            .await
            .with_fixer_context("package_updater", || {
                format!("Failed to update package {}", package_name)
            })?;

        let status = if update_output.status.success() {
            FixStatus::Success
        } else {
            FixStatus::Failed(format!(
                "Package update failed: {}",
                String::from_utf8_lossy(&update_output.stderr)
            ))
        };

        let actions_taken = vec![
            FixAction {
                description: "Synced package databases".to_string(),
                command: Some("pacman -Sy".to_string()),
                files_modified: vec![],
                reversible: false,
            },
            FixAction {
                description: format!("Updated package: {}", package_name),
                command: Some(format!("pacman -S --noconfirm {}", package_name)),
                files_modified: vec![],
                reversible: false,
            },
        ];

        Ok(FixResult {
            finding_id: finding.id.clone(),
            fixer_name: self.name().to_string(),
            status,
            message: format!("Package '{}' update completed", package_name),
            actions_taken,
            duration: start_time.elapsed(),
            backup_created: None,
            requires_reboot: false,
        })
    }
}

impl Default for PackageUpdaterFixer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Fixer for PackageUpdaterFixer {
    fn name(&self) -> &'static str {
        "package_updater"
    }

    fn description(&self) -> &'static str {
        "Updates outdated packages and applies security updates"
    }

    fn categories(&self) -> Vec<Category> {
        vec![Category::Package, Category::Vulnerability]
    }

    fn can_fix(&self, finding: &Finding) -> bool {
        // Can fix package-related findings
        finding.category == Category::Package
            || finding.id.starts_with("outdated-package-")
            || finding.id.starts_with("cve-")
            || finding.fixable
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config
            .fixer
            .enabled_modules
            .contains(&"package_updater".to_string())
    }

    async fn plan_fix(&self, finding: &Finding, _config: &Config) -> PinGuardResult<FixPlan> {
        let package_manager = self.detect_package_manager().await?;

        match package_manager.as_str() {
            "apt" => self.create_apt_plan(finding).await,
            "dnf" | "yum" => self.create_dnf_plan(finding, &package_manager).await,
            "pacman" => self.create_pacman_plan(finding).await,
            _ => Err(crate::core::PinGuardError::fixer(
                "package_updater",
                format!("Unsupported package manager: {}", package_manager),
            )),
        }
    }

    async fn fix(&self, finding: &Finding, _config: &Config) -> PinGuardResult<FixResult> {
        let package_manager = self.detect_package_manager().await?;

        match package_manager.as_str() {
            "apt" => self.fix_with_apt(finding).await,
            "dnf" | "yum" => self.fix_with_dnf(finding, &package_manager).await,
            "pacman" => self.fix_with_pacman(finding).await,
            _ => {
                let start_time = Instant::now();
                Ok(FixResult {
                    finding_id: finding.id.clone(),
                    fixer_name: self.name().to_string(),
                    status: FixStatus::Failed(format!(
                        "Unsupported package manager: {}",
                        package_manager
                    )),
                    message: "Cannot fix on this system".to_string(),
                    actions_taken: vec![],
                    duration: start_time.elapsed(),
                    backup_created: None,
                    requires_reboot: false,
                })
            }
        }
    }

    async fn validate(&self) -> PinGuardResult<()> {
        // Check if we can detect a package manager
        let _package_manager = self.detect_package_manager().await?;
        
        // Check if we have appropriate permissions (typically requires root/sudo)
        let whoami_output = Command::new("whoami")
            .output()
            .await
            .with_fixer_context("package_updater", || "Failed to check current user".to_string())?;

        let username_bytes = String::from_utf8_lossy(&whoami_output.stdout);
        let username = username_bytes.trim();
        if username != "root" {
            warn!("Package updater fixer requires root privileges to update packages");
        }

        info!("Package updater fixer validation successful");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Severity;

    #[tokio::test]
    async fn test_package_updater_fixer_creation() {
        let fixer = PackageUpdaterFixer::new();
        assert_eq!(fixer.name(), "package_updater");
        assert!(!fixer.description().is_empty());
    }

    #[test]
    fn test_can_fix() {
        let fixer = PackageUpdaterFixer::new();
        
        let finding = Finding::new(
            "outdated-package-test".to_string(),
            "Outdated package".to_string(),
            "Test package is outdated".to_string(),
            Severity::Medium,
            Category::Package,
            "test-package".to_string(),
        );

        assert!(fixer.can_fix(&finding));
    }

    #[test]
    fn test_extract_package_name() {
        let fixer = PackageUpdaterFixer::new();
        
        let finding = Finding::new(
            "outdated-package-nginx".to_string(),
            "Outdated package".to_string(),
            "Package is outdated".to_string(),
            Severity::Medium,
            Category::Package,
            "nginx".to_string(),
        );

        let package_name = fixer.extract_package_name(&finding);
        assert_eq!(package_name, Some("nginx".to_string()));
    }
}