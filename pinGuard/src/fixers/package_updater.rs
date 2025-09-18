use super::{Fixer, FixResult, FixError, FixPlan, FixStatus, RiskLevel, execute_command};
use crate::scanners::Finding;
use std::time::{Duration, Instant};
use std::process::Command;

pub struct PackageUpdater;

impl Fixer for PackageUpdater {
    fn name(&self) -> &'static str {
        "Package Updater"
    }

    fn can_fix(&self, finding: &Finding) -> bool {
        // Can fix package audit findings
        finding.id.starts_with("PKG-") || 
        finding.affected_item.contains("package") ||
        finding.title.contains("outdated") ||
        finding.title.contains("vulnerable")
    }

    fn fix(&self, finding: &Finding, _config: &crate::core::config::Config) -> Result<FixResult, FixError> {
        let start_time = Instant::now();
        let mut result = FixResult::new(finding.id.clone(), self.name().to_string());

        tracing::info!("Starting package fix: {}", finding.title);

        // Detect package manager
        let package_manager = self.detect_package_manager()?;
        tracing::info!("Package manager detected: {}", package_manager);

        match package_manager.as_str() {
            "apt" => self.fix_with_apt(finding, &mut result)?,
            "yum" => self.fix_with_yum(finding, &mut result)?,
            "dnf" => self.fix_with_dnf(finding, &mut result)?,
            "zypper" => self.fix_with_zypper(finding, &mut result)?,
            _ => return Err(FixError::UnsupportedFix(format!("Unsupported package manager: {}", package_manager))),
        }

        result = result.set_duration(start_time);
        tracing::info!("Package fix completed: {}", result.message);
        
        Ok(result)
    }

    fn dry_run(&self, finding: &Finding) -> Result<FixPlan, FixError> {
        let mut plan = FixPlan::new(
            finding.id.clone(),
            self.name().to_string(),
            format!("Update package(s) to fix: {}", finding.title)
        );

        let package_manager = self.detect_package_manager()?;
        
        match package_manager.as_str() {
            "apt" => {
                plan = plan
                    .add_command("apt update".to_string())
                    .add_command("apt upgrade -y".to_string())
                    .set_risk(RiskLevel::Medium)
                    .set_duration(Duration::from_secs(300)); // 5 minutes
            },
            "yum" => {
                plan = plan
                    .add_command("yum check-update".to_string())
                    .add_command("yum update -y".to_string())
                    .set_risk(RiskLevel::Medium)
                    .set_duration(Duration::from_secs(600)); // 10 minutes
            },
            "dnf" => {
                plan = plan
                    .add_command("dnf check-update".to_string())
                    .add_command("dnf update -y".to_string())
                    .set_risk(RiskLevel::Medium)
                    .set_duration(Duration::from_secs(300)); // 5 minutes
            },
            "zypper" => {
                plan = plan
                    .add_command("zypper refresh".to_string())
                    .add_command("zypper update -y".to_string())
                    .set_risk(RiskLevel::Medium)
                    .set_duration(Duration::from_secs(400)); // 6-7 minutes
            },
            _ => return Err(FixError::UnsupportedFix(format!("Unsupported package manager: {}", package_manager))),
        }

        // If kernel update, reboot may be required
        if finding.affected_item.contains("kernel") || finding.title.contains("kernel") {
            plan = plan.requires_reboot().set_risk(RiskLevel::High);
        }

        Ok(plan)
    }
}

impl PackageUpdater {
    /// Detect package manager
    fn detect_package_manager(&self) -> Result<String, FixError> {
        // APT (Debian/Ubuntu)
        if Command::new("which").arg("apt").output().unwrap().status.success() {
            return Ok("apt".to_string());
        }
        
        // DNF (Fedora/RHEL 8+)
        if Command::new("which").arg("dnf").output().unwrap().status.success() {
            return Ok("dnf".to_string());
        }
        
        // YUM (CentOS/RHEL 7)
        if Command::new("which").arg("yum").output().unwrap().status.success() {
            return Ok("yum".to_string());
        }
        
        // Zypper (openSUSE)
        if Command::new("which").arg("zypper").output().unwrap().status.success() {
            return Ok("zypper".to_string());
        }

        Err(FixError::DependencyError("No supported package manager found".to_string()))
    }

    /// Fix with APT
    fn fix_with_apt(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Updating APT repository...");
        
        // Repository update
        let _output = execute_command("apt", &["update"])?;
        result.commands_executed.push("apt update".to_string());

        // If specific package exists, update it, otherwise update all
        if let Some(package_name) = self.extract_package_name(&finding.affected_item) {
            tracing::info!("Updating specific package: {}", package_name);
            let _output = execute_command("apt", &["install", "--only-upgrade", "-y", &package_name])?;
            result.commands_executed.push(format!("apt install --only-upgrade -y {}", package_name));
            result.message = format!("Package '{}' updated successfully", package_name);
        } else {
            tracing::info!("Updating all packages...");
            let _output = execute_command("apt", &["upgrade", "-y"])?;
            result.commands_executed.push("apt upgrade -y".to_string());
            result.message = "All packages updated successfully".to_string();
        }

        result.status = FixStatus::Success;
        Ok(())
    }

    /// Fix with YUM
    fn fix_with_yum(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Updating YUM cache...");
        
        let _output = execute_command("yum", &["check-update"])?;
        result.commands_executed.push("yum check-update".to_string());

        if let Some(package_name) = self.extract_package_name(&finding.affected_item) {
            tracing::info!("Updating specific package: {}", package_name);
            let _output = execute_command("yum", &["update", "-y", &package_name])?;
            result.commands_executed.push(format!("yum update -y {}", package_name));
            result.message = format!("Package '{}' updated successfully", package_name);
        } else {
            tracing::info!("Updating all packages...");
            let _output = execute_command("yum", &["update", "-y"])?;
            result.commands_executed.push("yum update -y".to_string());
            result.message = "All packages updated successfully".to_string();
        }

        result.status = FixStatus::Success;
        Ok(())
    }

    /// Fix with DNF
    fn fix_with_dnf(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Updating DNF metadata...");
        
        let _output = execute_command("dnf", &["check-update"])?;
        result.commands_executed.push("dnf check-update".to_string());

        if let Some(package_name) = self.extract_package_name(&finding.affected_item) {
            tracing::info!("Updating specific package: {}", package_name);
            let _output = execute_command("dnf", &["update", "-y", &package_name])?;
            result.commands_executed.push(format!("dnf update -y {}", package_name));
            result.message = format!("Package '{}' updated successfully", package_name);
        } else {
            tracing::info!("Updating all packages...");
            let _output = execute_command("dnf", &["update", "-y"])?;
            result.commands_executed.push("dnf update -y".to_string());
            result.message = "All packages updated successfully".to_string();
        }

        result.status = FixStatus::Success;
        Ok(())
    }

    /// Fix with Zypper
    fn fix_with_zypper(&self, finding: &Finding, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Updating Zypper repositories...");
        
        let _output = execute_command("zypper", &["refresh"])?;
        result.commands_executed.push("zypper refresh".to_string());

        if let Some(package_name) = self.extract_package_name(&finding.affected_item) {
            tracing::info!("Updating specific package: {}", package_name);
            let _output = execute_command("zypper", &["update", "-y", &package_name])?;
            result.commands_executed.push(format!("zypper update -y {}", package_name));
            result.message = format!("Package '{}' updated successfully", package_name);
        } else {
            tracing::info!("Updating all packages...");
            let _output = execute_command("zypper", &["update", "-y"])?;
            result.commands_executed.push("zypper update -y".to_string());
            result.message = "All packages updated successfully".to_string();
        }

        result.status = FixStatus::Success;
        Ok(())
    }

    /// Extract package name from finding
    fn extract_package_name(&self, affected_item: &str) -> Option<String> {
        // Extract package name from "Package: packagename" format
        if affected_item.starts_with("Package: ") {
            return Some(affected_item.replace("Package: ", "").trim().to_string());
        }

        // Extract package name from "packagename (version)" format
        if affected_item.contains(" (") {
            return Some(affected_item.split(" (").next()?.trim().to_string());
        }

        // If only package name exists
        if !affected_item.contains("/") && !affected_item.contains(" ") {
            return Some(affected_item.trim().to_string());
        }

        None
    }

    /// Check security updates
    pub fn check_security_updates(&self) -> Result<Vec<String>, FixError> {
        let package_manager = self.detect_package_manager()?;
        
        match package_manager.as_str() {
            "apt" => self.check_apt_security_updates(),
            "yum" => self.check_yum_security_updates(),
            "dnf" => self.check_dnf_security_updates(),
            "zypper" => self.check_zypper_security_updates(),
            _ => Err(FixError::UnsupportedFix("Unsupported package manager".to_string())),
        }
    }

    fn check_apt_security_updates(&self) -> Result<Vec<String>, FixError> {
        let output = execute_command("apt", &["list", "--upgradable"])?;
        let mut security_updates = Vec::new();
        
        for line in output.lines() {
            if line.contains("security") || line.contains("Ubuntu-Security") {
                if let Some(package) = line.split('/').next() {
                    security_updates.push(package.to_string());
                }
            }
        }
        
        Ok(security_updates)
    }

    fn check_yum_security_updates(&self) -> Result<Vec<String>, FixError> {
        let output = execute_command("yum", &["--security", "check-update"])?;
        let mut security_updates = Vec::new();
        
        for line in output.lines() {
            if !line.trim().is_empty() && !line.starts_with("Loaded") && !line.starts_with("Last") {
                if let Some(package) = line.split_whitespace().next() {
                    security_updates.push(package.to_string());
                }
            }
        }
        
        Ok(security_updates)
    }

    fn check_dnf_security_updates(&self) -> Result<Vec<String>, FixError> {
        let output = execute_command("dnf", &["--security", "check-update"])?;
        let mut security_updates = Vec::new();
        
        for line in output.lines() {
            if !line.trim().is_empty() && !line.starts_with("Last") && !line.contains("metadata") {
                if let Some(package) = line.split_whitespace().next() {
                    if package.contains(".") { // Package format check
                        security_updates.push(package.to_string());
                    }
                }
            }
        }
        
        Ok(security_updates)
    }

    fn check_zypper_security_updates(&self) -> Result<Vec<String>, FixError> {
        let output = execute_command("zypper", &["list-updates", "--category", "security"])?;
        let mut security_updates = Vec::new();
        
        for line in output.lines() {
            if line.starts_with("v ") || line.starts_with("i ") {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() > 2 {
                    security_updates.push(parts[2].trim().to_string());
                }
            }
        }
        
        Ok(security_updates)
    }
}