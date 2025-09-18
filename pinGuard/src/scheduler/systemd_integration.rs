use super::{ScheduleConfig, SchedulerError, SchedulerResult, SystemdTimerStatus};
use chrono::{DateTime, Utc};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info, warn};

/// Systemd entegrasyonu
pub struct SystemdIntegration {
    systemd_dir: PathBuf,
    service_template: String,
    timer_template: String,
}

impl SystemdIntegration {
    /// Yeni systemd integration oluştur
    pub fn new() -> SchedulerResult<Self> {
        let systemd_dir = Self::get_systemd_user_dir()?;

        let service_template = Self::get_service_template();
        let timer_template = Self::get_timer_template();

        Ok(Self {
            systemd_dir,
            service_template,
            timer_template,
        })
    }

    /// Timer dosyası oluştur
    pub fn create_timer(&self, config: &ScheduleConfig) -> SchedulerResult<()> {
        info!("Creating timer: {}", config.name);

        let timer_content = self.generate_timer_content(config)?;
        let timer_path = self
            .systemd_dir
            .join(format!("pinGuard-{}.timer", config.name));

        fs::write(&timer_path, timer_content)?;
        info!("Timer dosyası oluşturuldu: {}", timer_path.display());

        Ok(())
    }

    /// Service dosyası oluştur
    pub fn create_service(&self, config: &ScheduleConfig) -> SchedulerResult<()> {
        info!("Service created: {}", config.name);

        let service_content = self.generate_service_content(config)?;
        let service_path = self
            .systemd_dir
            .join(format!("pinGuard-{}.service", config.name));

        fs::write(&service_path, service_content)?;
        info!("Service dosyası oluşturuldu: {}", service_path.display());

        // Systemd daemon'ını reload et
        self.reload_systemd()?;

        Ok(())
    }

    /// Enable timer
    pub fn enable_timer(&self, schedule_name: &str) -> SchedulerResult<()> {
        info!("Enabling timer: {}", schedule_name);

        let timer_name = format!("pinGuard-{}.timer", schedule_name);

        // Enable timer
        let output = Command::new("systemctl")
            .args(["--user", "enable", &timer_name])
            .output()
            .map_err(|e| SchedulerError::SystemdError(format!("Failed to enable timer: {}", e)))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(SchedulerError::SystemdError(format!(
                "Enable timer failed: {}",
                error
            )));
        }

        // Timer'ı başlat
        let output = Command::new("systemctl")
            .args(["--user", "start", &timer_name])
            .output()
            .map_err(|e| SchedulerError::SystemdError(format!("Failed to start timer: {}", e)))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(SchedulerError::SystemdError(format!(
                "Start timer failed: {}",
                error
            )));
        }

        info!("Timer enabled and started: {}", schedule_name);
        Ok(())
    }

    /// Disable timer
    pub fn disable_timer(&self, schedule_name: &str) -> SchedulerResult<()> {
        info!("Disabling timer: {}", schedule_name);

        let timer_name = format!("pinGuard-{}.timer", schedule_name);

        // Timer'ı durdur
        let output = Command::new("systemctl")
            .args(["--user", "stop", &timer_name])
            .output()
            .map_err(|e| SchedulerError::SystemdError(format!("Failed to stop timer: {}", e)))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            warn!(
                "Timer durdurulamadı (zaten durdurulmuş olabilir): {}",
                error
            );
        }

        // Disable timer
        let output = Command::new("systemctl")
            .args(["--user", "disable", &timer_name])
            .output()
            .map_err(|e| SchedulerError::SystemdError(format!("Failed to disable timer: {}", e)))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            warn!("Timer could not be disabled: {}", error);
        }

        info!("Timer disabled: {}", schedule_name);
        Ok(())
    }

    /// Get timer status
    pub fn get_timer_status(&self, schedule_name: &str) -> SchedulerResult<SystemdTimerStatus> {
        let timer_name = format!("pinGuard-{}.timer", schedule_name);

        // Timer durumunu kontrol et
        let output = Command::new("systemctl")
            .args(["--user", "is-enabled", &timer_name])
            .output()
            .map_err(|e| {
                SchedulerError::SystemdError(format!("Failed to check timer status: {}", e))
            })?;

        let enabled = output.status.success();

        // Timer aktif mi kontrol et
        let output = Command::new("systemctl")
            .args(["--user", "is-active", &timer_name])
            .output()
            .map_err(|e| {
                SchedulerError::SystemdError(format!("Failed to check timer active: {}", e))
            })?;

        let active = output.status.success();

        // Get timer information
        let next_run = self.get_next_run(&timer_name)?;
        let last_run = self.get_last_run(&timer_name)?;

        Ok(SystemdTimerStatus {
            enabled,
            active,
            next_run,
            last_run,
            unit_status: if active {
                "active".to_string()
            } else {
                "inactive".to_string()
            },
        })
    }

    /// Timer ve service dosyalarını kaldır
    pub fn remove_timer(&self, schedule_name: &str) -> SchedulerResult<()> {
        info!("Timer dosyaları kaldırılıyor: {}", schedule_name);

        let timer_path = self
            .systemd_dir
            .join(format!("pinGuard-{}.timer", schedule_name));
        if timer_path.exists() {
            fs::remove_file(&timer_path)?;
            debug!("Timer dosyası silindi: {}", timer_path.display());
        }

        Ok(())
    }

    /// Service dosyasını kaldır
    pub fn remove_service(&self, schedule_name: &str) -> SchedulerResult<()> {
        let service_path = self
            .systemd_dir
            .join(format!("pinGuard-{}.service", schedule_name));
        if service_path.exists() {
            fs::remove_file(&service_path)?;
            debug!("Service dosyası silindi: {}", service_path.display());
        }

        // Systemd daemon'ını reload et
        self.reload_systemd()?;

        Ok(())
    }

    /// Systemd user dizinini al
    fn get_systemd_user_dir() -> SchedulerResult<PathBuf> {
        let home = std::env::var("HOME").map_err(|_| {
            SchedulerError::InvalidConfig("HOME environment variable not set".to_string())
        })?;

        let systemd_dir = PathBuf::from(format!("{}/.config/systemd/user", home));

        if !systemd_dir.exists() {
            fs::create_dir_all(&systemd_dir)?;
            info!("Systemd user dizini oluşturuldu: {}", systemd_dir.display());
        }

        Ok(systemd_dir)
    }

    /// Service template'i al
    fn get_service_template() -> String {
        r#"[Unit]
Description=PinGuard Security Scanner - {schedule_name}
After=network.target

[Service]
Type=oneshot
User={user}
ExecStart={pinGuard_path} run-scheduled-scan {schedule_name}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"#
        .to_string()
    }

    /// Timer template'i al
    fn get_timer_template() -> String {
        r#"[Unit]
Description=Timer for PinGuard Security Scanner - {schedule_name}
Requires=pinGuard-{schedule_name}.service

[Timer]
OnCalendar={schedule}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"#
        .to_string()
    }

    /// Timer içeriği oluştur
    fn generate_timer_content(&self, config: &ScheduleConfig) -> SchedulerResult<String> {
        let content = self
            .timer_template
            .replace("{schedule_name}", &config.name)
            .replace(
                "{schedule}",
                &self.convert_cron_to_systemd(&config.schedule)?,
            );

        Ok(content)
    }

    /// Service içeriği oluştur
    fn generate_service_content(&self, config: &ScheduleConfig) -> SchedulerResult<String> {
        let user = std::env::var("USER").map_err(|_| {
            SchedulerError::InvalidConfig("USER environment variable not set".to_string())
        })?;

        let pin_guard_path = self.get_pin_guard_executable_path()?;

        let content = self
            .service_template
            .replace("{schedule_name}", &config.name)
            .replace("{user}", &user)
            .replace("{pinGuard_path}", &pin_guard_path);

        Ok(content)
    }

    /// Cron formatını systemd formatına çevir
    fn convert_cron_to_systemd(&self, cron: &str) -> SchedulerResult<String> {
        // Basit cron -> systemd çevirisi
        // TODO: Daha gelişmiş çeviri implementasyonu
        match cron {
            "0 2 * * *" => Ok("*-*-* 02:00:00".to_string()),
            "0 3 * * 0" => Ok("Sun *-*-* 03:00:00".to_string()),
            "0 6,12,18 * * *" => Ok("*-*-* 06,12,18:00:00".to_string()),
            _ => {
                warn!(
                    "Desteklenmeyen cron formatı, varsayılan değer kullanılıyor: {}",
                    cron
                );
                Ok("*-*-* 02:00:00".to_string())
            }
        }
    }

    /// PinGuard executable yolunu al
    fn get_pin_guard_executable_path(&self) -> SchedulerResult<String> {
        // Önce cargo binary path'ini dene
        if let Ok(current_exe) = std::env::current_exe() {
            if let Some(path_str) = current_exe.to_str() {
                return Ok(path_str.to_string());
            }
        }

        // PATH'de pinGuard'ı ara
        if let Ok(output) = Command::new("which").arg("pinGuard").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(path);
                }
            }
        }

        // Varsayılan path
        Ok("/usr/local/bin/pinGuard".to_string())
    }

    /// Systemd daemon'ını reload et
    fn reload_systemd(&self) -> SchedulerResult<()> {
        debug!("Systemd daemon reload ediliyor");

        let output = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output()
            .map_err(|e| {
                SchedulerError::SystemdError(format!("Failed to reload systemd: {}", e))
            })?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(SchedulerError::SystemdError(format!(
                "Daemon reload failed: {}",
                error
            )));
        }

        Ok(())
    }

    /// Get next run time
    fn get_next_run(&self, _timer_name: &str) -> SchedulerResult<Option<DateTime<Utc>>> {
        // Get next run information using systemctl list-timers
        // Bu karmaşık parsing gerektirdiği için şimdilik None döndürüyoruz
        Ok(None)
    }

    /// Get last run time
    fn get_last_run(&self, _timer_name: &str) -> SchedulerResult<Option<DateTime<Utc>>> {
        // Get last run information using journalctl
        // Bu karmaşık parsing gerektirdiği için şimdilik None döndürüyoruz
        Ok(None)
    }
}
