use super::{ScheduleConfig, SchedulerError, SchedulerResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn, debug};

/// Schedule yöneticisi
pub struct ScheduleManager {
    config_dir: PathBuf,
    schedules: HashMap<String, ScheduleConfig>,
}

impl ScheduleManager {
    /// Yeni schedule manager oluştur
    pub fn new(config_dir: &str) -> SchedulerResult<Self> {
        let config_dir = PathBuf::from(config_dir);
        
        // Config dizinini oluştur
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
            info!("📁 Schedule config dizini oluşturuldu: {}", config_dir.display());
        }

        let mut manager = Self {
            config_dir,
            schedules: HashMap::new(),
        };

        // Mevcut schedule'ları yükle
        manager.load_schedules()?;
        
        Ok(manager)
    }

    /// Schedule'ı kaydet
    pub fn save_schedule(&mut self, config: &ScheduleConfig) -> SchedulerResult<()> {
        debug!("💾 Schedule kaydediliyor: {}", config.name);

        // Config dosyası yolu
        let config_path = self.config_dir.join(format!("{}.json", config.name));
        
        // JSON'a serialize et
        let json = serde_json::to_string_pretty(config)
            .map_err(|e| SchedulerError::InvalidConfig(format!("JSON serialization error: {}", e)))?;

        // Dosyaya yaz
        fs::write(&config_path, json)?;

        // Memory'de sakla
        self.schedules.insert(config.name.clone(), config.clone());

        info!("✅ Schedule kaydedildi: {} -> {}", config.name, config_path.display());
        Ok(())
    }

    /// Schedule'ı yükle
    pub fn get_schedule(&self, name: &str) -> SchedulerResult<ScheduleConfig> {
        self.schedules.get(name)
            .cloned()
            .ok_or_else(|| SchedulerError::ScheduleNotFound(name.to_string()))
    }

    /// Schedule var mı kontrol et
    pub fn exists(&self, name: &str) -> SchedulerResult<bool> {
        Ok(self.schedules.contains_key(name))
    }

    /// Schedule'ı sil
    pub fn remove_schedule(&mut self, name: &str) -> SchedulerResult<()> {
        debug!("🗑️ Schedule siliniyor: {}", name);

        // Memory'den sil
        if self.schedules.remove(name).is_none() {
            return Err(SchedulerError::ScheduleNotFound(name.to_string()));
        }

        // Config dosyasını sil
        let config_path = self.config_dir.join(format!("{}.json", name));
        if config_path.exists() {
            fs::remove_file(&config_path)?;
            info!("🗑️ Schedule config dosyası silindi: {}", config_path.display());
        }

        info!("✅ Schedule silindi: {}", name);
        Ok(())
    }

    /// Tüm schedule'ları listele
    pub fn list_schedules(&self) -> SchedulerResult<Vec<ScheduleConfig>> {
        Ok(self.schedules.values().cloned().collect())
    }

    /// Schedule'ı güncelle
    pub fn update_schedule(&mut self, config: &ScheduleConfig) -> SchedulerResult<()> {
        if !self.schedules.contains_key(&config.name) {
            return Err(SchedulerError::ScheduleNotFound(config.name.clone()));
        }

        self.save_schedule(config)
    }

    /// Schedule'ı etkinleştir/devre dışı bırak
    pub fn set_schedule_enabled(&mut self, name: &str, enabled: bool) -> SchedulerResult<()> {
        let mut config = self.get_schedule(name)?;
        config.enabled = enabled;
        config.updated_at = chrono::Utc::now();
        self.update_schedule(&config)
    }

    /// Mevcut schedule'ları dosyalardan yükle
    fn load_schedules(&mut self) -> SchedulerResult<()> {
        debug!("📂 Schedule'lar yükleniyor: {}", self.config_dir.display());

        let entries = fs::read_dir(&self.config_dir)?;
        let mut loaded_count = 0;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match self.load_schedule_from_file(&path) {
                    Ok(config) => {
                        self.schedules.insert(config.name.clone(), config);
                        loaded_count += 1;
                    }
                    Err(e) => {
                        warn!("⚠️ Schedule yüklenemedi {}: {}", path.display(), e);
                    }
                }
            }
        }

        info!("📋 {} schedule yüklendi", loaded_count);
        Ok(())
    }

    /// Tek bir schedule dosyasını yükle
    fn load_schedule_from_file(&self, path: &Path) -> SchedulerResult<ScheduleConfig> {
        let content = fs::read_to_string(path)?;
        let config: ScheduleConfig = serde_json::from_str(&content)
            .map_err(|e| SchedulerError::InvalidConfig(format!("JSON parse error: {}", e)))?;
        
        debug!("📄 Schedule yüklendi: {} -> {}", config.name, path.display());
        Ok(config)
    }

    /// Schedule istatistikleri
    pub fn get_statistics(&self) -> ScheduleStatistics {
        let total = self.schedules.len();
        let enabled = self.schedules.values().filter(|s| s.enabled).count();
        let disabled = total - enabled;

        let mut by_scan_type = HashMap::new();
        for schedule in self.schedules.values() {
            let scan_type = schedule.scan_type.to_string();
            *by_scan_type.entry(scan_type).or_insert(0) += 1;
        }

        ScheduleStatistics {
            total_schedules: total,
            enabled_schedules: enabled,
            disabled_schedules: disabled,
            schedules_by_type: by_scan_type,
        }
    }

    /// Varsayılan schedule'ları oluştur
    pub fn create_default_schedules(&mut self) -> SchedulerResult<()> {
        info!("🔧 Varsayılan schedule'lar oluşturuluyor");

        // Daily full scan
        if !self.exists("daily-full")? {
            let daily = ScheduleConfig::daily(
                "daily-full".to_string(), 
                "Daily comprehensive security scan".to_string()
            );
            self.save_schedule(&daily)?;
        }

        // Weekly full scan
        if !self.exists("weekly-full")? {
            let weekly = ScheduleConfig::weekly(
                "weekly-full".to_string(),
                "Weekly comprehensive security scan".to_string()
            );
            self.save_schedule(&weekly)?;
        }

        // Quick scan 3 times a day
        if !self.exists("quick-3x")? {
            let quick = ScheduleConfig::quick_daily(
                "quick-3x".to_string(),
                "Quick security check 3 times daily".to_string()
            );
            self.save_schedule(&quick)?;
        }

        info!("✅ Varsayılan schedule'lar oluşturuldu");
        Ok(())
    }
}

/// Schedule istatistikleri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleStatistics {
    pub total_schedules: usize,
    pub enabled_schedules: usize,
    pub disabled_schedules: usize,
    pub schedules_by_type: HashMap<String, usize>,
}