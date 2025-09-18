use super::{Fixer, FixResult, FixError, FixPlan, FixStatus, RiskLevel, execute_command};
use crate::scanners::Finding;
use std::time::{Duration, Instant};
use std::process::Command;

pub struct KernelUpdater;

impl Fixer for KernelUpdater {
    fn name(&self) -> &'static str {
        "Kernel Updater"
    }

    fn can_fix(&self, finding: &Finding) -> bool {
        // Kernel ile ilgili bulguları düzeltebilir
        finding.id.starts_with("KERNEL-") || 
        finding.affected_item.contains("kernel") ||
        finding.title.contains("kernel") ||
        finding.title.contains("Kernel")
    }

    fn fix(&self, finding: &Finding, _config: &crate::core::config::Config) -> Result<FixResult, FixError> {
        let start_time = Instant::now();
        let mut result = FixResult::new(finding.id.clone(), self.name().to_string());

        tracing::info!("Kernel update başlatılıyor: {}", finding.title);

        // Package manager'ı tespit et
        let package_manager = self.detect_package_manager()?;
        tracing::info!("Package manager tespit edildi: {}", package_manager);

        // Mevcut kernel bilgisini al
        let current_kernel = self.get_current_kernel_version()?;
        tracing::info!("Mevcut kernel: {}", current_kernel);

        match package_manager.as_str() {
            "apt" => self.update_kernel_apt(&mut result)?,
            "yum" => self.update_kernel_yum(&mut result)?,
            "dnf" => self.update_kernel_dnf(&mut result)?,
            "zypper" => self.update_kernel_zypper(&mut result)?,
            _ => return Err(FixError::UnsupportedFix(format!("Unsupported package manager: {}", package_manager))),
        }

        // Reboot planlama
        self.schedule_reboot(&mut result)?;

        result = result.set_duration(start_time).requires_reboot();
        tracing::info!("Kernel update tamamlandı: {}", result.message);
        
        Ok(result)
    }

    fn dry_run(&self, finding: &Finding) -> Result<FixPlan, FixError> {
        let mut plan = FixPlan::new(
            finding.id.clone(),
            self.name().to_string(),
            format!("Update kernel to fix: {}", finding.title)
        );

        let package_manager = self.detect_package_manager()?;
        let current_kernel = self.get_current_kernel_version()?;
        
        plan = plan
            .requires_reboot()
            .requires_backup()
            .set_risk(RiskLevel::High) // Kernel update her zaman yüksek risk
            .set_duration(Duration::from_secs(1800)); // 30 dakika

        match package_manager.as_str() {
            "apt" => {
                plan = plan
                    .add_command("apt update".to_string())
                    .add_command("apt install -y linux-image-generic".to_string())
                    .add_command("apt install -y linux-headers-generic".to_string())
                    .add_command("update-grub".to_string());
            },
            "yum" => {
                plan = plan
                    .add_command("yum check-update kernel".to_string())
                    .add_command("yum update -y kernel".to_string())
                    .add_command("grub2-mkconfig -o /boot/grub2/grub.cfg".to_string());
            },
            "dnf" => {
                plan = plan
                    .add_command("dnf check-update kernel".to_string())
                    .add_command("dnf update -y kernel".to_string())
                    .add_command("grub2-mkconfig -o /boot/grub2/grub.cfg".to_string());
            },
            "zypper" => {
                plan = plan
                    .add_command("zypper refresh".to_string())
                    .add_command("zypper update -y kernel-default".to_string())
                    .add_command("grub2-mkconfig -o /boot/grub2/grub.cfg".to_string());
            },
            _ => return Err(FixError::UnsupportedFix(format!("Unsupported package manager: {}", package_manager))),
        }

        plan = plan
            .add_file("/boot/grub/grub.cfg".to_string())
            .add_command("shutdown -r +1".to_string()); // 1 dakika sonra reboot

        Ok(plan)
    }
}

impl KernelUpdater {
    /// Package manager'ı tespit et
    fn detect_package_manager(&self) -> Result<String, FixError> {
        if Command::new("which").arg("apt").output().unwrap().status.success() {
            return Ok("apt".to_string());
        }
        if Command::new("which").arg("dnf").output().unwrap().status.success() {
            return Ok("dnf".to_string());
        }
        if Command::new("which").arg("yum").output().unwrap().status.success() {
            return Ok("yum".to_string());
        }
        if Command::new("which").arg("zypper").output().unwrap().status.success() {
            return Ok("zypper".to_string());
        }

        Err(FixError::DependencyError("No supported package manager found".to_string()))
    }

    /// Mevcut kernel versiyonunu al
    fn get_current_kernel_version(&self) -> Result<String, FixError> {
        let output = execute_command("uname", &["-r"])?;
        Ok(output.trim().to_string())
    }

    /// APT ile kernel güncelleme
    fn update_kernel_apt(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("APT repository güncelleniyor...");
        
        let _output = execute_command("apt", &["update"])?;
        result.commands_executed.push("apt update".to_string());

        // Mevcut kernel sürümünü backup al
        let current_kernel = self.get_current_kernel_version()?;
        tracing::info!("Mevcut kernel backup alınıyor: {}", current_kernel);

        // En son kernel'i yükle
        tracing::info!("Latest kernel yükleniyor...");
        let _output = execute_command("apt", &["install", "-y", "linux-image-generic", "linux-headers-generic"])?;
        result.commands_executed.push("apt install -y linux-image-generic linux-headers-generic".to_string());

        // GRUB güncelle
        tracing::info!("GRUB konfigürasyonu güncelleniyor...");
        let _output = execute_command("update-grub", &[])?;
        result.commands_executed.push("update-grub".to_string());
        result.files_modified.push("/boot/grub/grub.cfg".to_string());

        result.status = FixStatus::RequiresReboot;
        result.message = "Kernel updated successfully. Reboot required.".to_string();
        
        Ok(())
    }

    /// YUM ile kernel güncelleme
    fn update_kernel_yum(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("YUM repository kontrol ediliyor...");
        
        let _output = execute_command("yum", &["check-update", "kernel"])?;
        result.commands_executed.push("yum check-update kernel".to_string());

        tracing::info!("Kernel güncelleniyor...");
        let _output = execute_command("yum", &["update", "-y", "kernel"])?;
        result.commands_executed.push("yum update -y kernel".to_string());

        // GRUB2 güncelle
        tracing::info!("GRUB2 konfigürasyonu güncelleniyor...");
        let _output = execute_command("grub2-mkconfig", &["-o", "/boot/grub2/grub.cfg"])?;
        result.commands_executed.push("grub2-mkconfig -o /boot/grub2/grub.cfg".to_string());
        result.files_modified.push("/boot/grub2/grub.cfg".to_string());

        result.status = FixStatus::RequiresReboot;
        result.message = "Kernel updated successfully. Reboot required.".to_string();
        
        Ok(())
    }

    /// DNF ile kernel güncelleme
    fn update_kernel_dnf(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("DNF repository kontrol ediliyor...");
        
        let _output = execute_command("dnf", &["check-update", "kernel"])?;
        result.commands_executed.push("dnf check-update kernel".to_string());

        tracing::info!("Kernel güncelleniyor...");
        let _output = execute_command("dnf", &["update", "-y", "kernel"])?;
        result.commands_executed.push("dnf update -y kernel".to_string());

        // GRUB2 güncelle
        tracing::info!("GRUB2 konfigürasyonu güncelleniyor...");
        let _output = execute_command("grub2-mkconfig", &["-o", "/boot/grub2/grub.cfg"])?;
        result.commands_executed.push("grub2-mkconfig -o /boot/grub2/grub.cfg".to_string());
        result.files_modified.push("/boot/grub2/grub.cfg".to_string());

        result.status = FixStatus::RequiresReboot;
        result.message = "Kernel updated successfully. Reboot required.".to_string();
        
        Ok(())
    }

    /// Zypper ile kernel güncelleme
    fn update_kernel_zypper(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Zypper repository güncelleniyor...");
        
        let _output = execute_command("zypper", &["refresh"])?;
        result.commands_executed.push("zypper refresh".to_string());

        tracing::info!("Kernel güncelleniyor...");
        let _output = execute_command("zypper", &["update", "-y", "kernel-default"])?;
        result.commands_executed.push("zypper update -y kernel-default".to_string());

        // GRUB2 güncelle
        tracing::info!("GRUB2 konfigürasyonu güncelleniyor...");
        let _output = execute_command("grub2-mkconfig", &["-o", "/boot/grub2/grub.cfg"])?;
        result.commands_executed.push("grub2-mkconfig -o /boot/grub2/grub.cfg".to_string());
        result.files_modified.push("/boot/grub2/grub.cfg".to_string());

        result.status = FixStatus::RequiresReboot;
        result.message = "Kernel updated successfully. Reboot required.".to_string();
        
        Ok(())
    }

    /// Reboot planlama
    fn schedule_reboot(&self, result: &mut FixResult) -> Result<(), FixError> {
        tracing::info!("Sistem reboot planlanıyor...");
        
        // Reboot planı oluştur
        let reboot_message = "System will reboot in 1 minute for kernel update";
        tracing::warn!("{}", reboot_message);
        
        // Kullanıcılara uyarı gönder
        let _output = execute_command("wall", &[reboot_message])?;
        result.commands_executed.push(format!("wall '{}'", reboot_message));

        // 1 dakika sonra reboot planla
        let _output = execute_command("shutdown", &["-r", "+1", "Kernel update reboot"])?;
        result.commands_executed.push("shutdown -r +1 'Kernel update reboot'".to_string());

        result.reboot_required = true;
        
        Ok(())
    }

    /// Kernel güvenlik durumunu kontrol et
    pub fn check_kernel_security_status(&self) -> Result<KernelSecurityStatus, FixError> {
        let current_version = self.get_current_kernel_version()?;
        let available_updates = self.check_kernel_updates()?;
        
        Ok(KernelSecurityStatus {
            current_version,
            updates_available: !available_updates.is_empty(),
            available_updates,
            needs_reboot: self.check_pending_reboot()?,
        })
    }

    /// Kernel güncellemelerini kontrol et
    fn check_kernel_updates(&self) -> Result<Vec<String>, FixError> {
        let package_manager = self.detect_package_manager()?;
        
        match package_manager.as_str() {
            "apt" => {
                let output = execute_command("apt", &["list", "--upgradable"])?;
                let mut updates = Vec::new();
                for line in output.lines() {
                    if line.contains("linux-image") || line.contains("linux-headers") {
                        if let Some(package) = line.split('/').next() {
                            updates.push(package.to_string());
                        }
                    }
                }
                Ok(updates)
            },
            "yum" | "dnf" => {
                let cmd = if package_manager == "dnf" { "dnf" } else { "yum" };
                let output = execute_command(cmd, &["check-update", "kernel"])?;
                let mut updates = Vec::new();
                for line in output.lines() {
                    if line.contains("kernel") && !line.starts_with("Last") {
                        if let Some(package) = line.split_whitespace().next() {
                            updates.push(package.to_string());
                        }
                    }
                }
                Ok(updates)
            },
            "zypper" => {
                let output = execute_command("zypper", &["list-updates"])?;
                let mut updates = Vec::new();
                for line in output.lines() {
                    if line.contains("kernel") {
                        let parts: Vec<&str> = line.split('|').collect();
                        if parts.len() > 2 {
                            updates.push(parts[2].trim().to_string());
                        }
                    }
                }
                Ok(updates)
            },
            _ => Err(FixError::UnsupportedFix("Unsupported package manager".to_string())),
        }
    }

    /// Bekleyen reboot kontrolü
    fn check_pending_reboot(&self) -> Result<bool, FixError> {
        // /var/run/reboot-required dosyası varsa reboot gerekiyor
        if std::path::Path::new("/var/run/reboot-required").exists() {
            return Ok(true);
        }

        // Kernel versiyon farkı kontrolü
        let running_kernel = self.get_current_kernel_version()?;
        let installed_kernels = self.get_installed_kernels()?;
        
        // En son yüklenen kernel ile çalışan kernel farklıysa reboot gerekir
        if let Some(latest) = installed_kernels.first() {
            if latest != &running_kernel {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Yüklü kernel'leri listele
    fn get_installed_kernels(&self) -> Result<Vec<String>, FixError> {
        let package_manager = self.detect_package_manager()?;
        
        match package_manager.as_str() {
            "apt" => {
                let output = execute_command("dpkg", &["--list", "linux-image-*"])?;
                let mut kernels = Vec::new();
                for line in output.lines() {
                    if line.starts_with("ii") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 2 && parts[1].starts_with("linux-image-") {
                            kernels.push(parts[2].to_string());
                        }
                    }
                }
                kernels.sort();
                kernels.reverse(); // En yeni önce
                Ok(kernels)
            },
            "yum" | "dnf" => {
                let cmd = if package_manager == "dnf" { "dnf" } else { "yum" };
                let output = execute_command(cmd, &["list", "installed", "kernel"])?;
                let mut kernels = Vec::new();
                for line in output.lines() {
                    if line.contains("kernel.") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 1 {
                            kernels.push(parts[1].to_string());
                        }
                    }
                }
                Ok(kernels)
            },
            "zypper" => {
                let output = execute_command("zypper", &["search", "--installed-only", "kernel-default"])?;
                let mut kernels = Vec::new();
                for line in output.lines() {
                    if line.starts_with("i ") {
                        let parts: Vec<&str> = line.split('|').collect();
                        if parts.len() > 3 {
                            kernels.push(parts[3].trim().to_string());
                        }
                    }
                }
                Ok(kernels)
            },
            _ => Err(FixError::UnsupportedFix("Unsupported package manager".to_string())),
        }
    }
}

/// Kernel güvenlik durumu
#[derive(Debug)]
pub struct KernelSecurityStatus {
    pub current_version: String,
    pub updates_available: bool,
    pub available_updates: Vec<String>,
    pub needs_reboot: bool,
}