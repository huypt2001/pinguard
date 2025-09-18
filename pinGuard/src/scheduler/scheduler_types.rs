use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Schedule konfigürasyonu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Schedule adı (benzersiz)
    pub name: String,
    /// Açıklama
    pub description: String,
    /// Schedule ifadesi (cron-like format)
    pub schedule: String,
    /// Çalıştırılacak tarama türü
    pub scan_type: ScanType,
    /// Tarama modülleri
    pub scan_modules: Vec<String>,
    /// Özel konfigürasyon
    pub options: HashMap<String, String>,
    /// Aktif mi
    pub enabled: bool,
    /// Oluşturulma tarihi
    pub created_at: DateTime<Utc>,
    /// Son güncelleme
    pub updated_at: DateTime<Utc>,
}

impl ScheduleConfig {
    /// Yeni schedule config oluştur
    pub fn new(name: String, description: String, schedule: String, scan_type: ScanType) -> Self {
        let now = Utc::now();
        Self {
            name,
            description,
            schedule,
            scan_type,
            scan_modules: vec![
                "package_audit".to_string(),
                "kernel_check".to_string(),
                "user_audit".to_string(),
                "service_audit".to_string(),
                "file_permissions".to_string(),
                "network_audit".to_string(),
            ],
            options: HashMap::new(),
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Daily scan için varsayılan config
    pub fn daily(name: String, description: String) -> Self {
        Self::new(name, description, "0 2 * * *".to_string(), ScanType::Full)
    }

    /// Weekly scan için varsayılan config
    pub fn weekly(name: String, description: String) -> Self {
        Self::new(name, description, "0 3 * * 0".to_string(), ScanType::Full)
    }

    /// Quick scan için varsayılan config
    pub fn quick_daily(name: String, description: String) -> Self {
        Self::new(name, description, "0 6,12,18 * * *".to_string(), ScanType::Quick)
    }
}

/// Tarama türü
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    /// Tam tarama - tüm scannerları çalıştır
    Full,
    /// Hızlı tarama - sadece package audit
    Quick,
    /// Güvenlik taraması - permission, service, user audits
    Security,
    /// Özel tarama - belirtilen modüller
    Custom { modules: Vec<String> },
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Full => write!(f, "full"),
            ScanType::Quick => write!(f, "quick"),
            ScanType::Security => write!(f, "security"),
            ScanType::Custom { modules } => write!(f, "custom({})", modules.join(",")),
        }
    }
}

/// Schedule durumu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleStatus {
    /// Schedule adı
    pub name: String,
    /// Etkin mi
    pub enabled: bool,
    /// Aktif mi (çalışıyor mu)
    pub active: bool,
    /// Son çalışma bilgisi
    pub last_run: Option<LastRunInfo>,
    /// Bir sonraki çalışma zamanı
    pub next_run: Option<DateTime<Utc>>,
    /// Schedule konfigürasyonu
    pub config: ScheduleConfig,
}

/// Son çalışma bilgisi
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastRunInfo {
    /// Çalışma zamanı
    pub run_time: DateTime<Utc>,
    /// Başarılı mı
    pub success: bool,
    /// Süre (milisaniye)
    pub duration_ms: u64,
    /// Bulunan finding sayısı
    pub findings_count: u32,
    /// Hata mesajı (varsa)
    pub error_message: Option<String>,
}

/// Systemd timer durumu
#[derive(Debug, Clone)]
pub struct SystemdTimerStatus {
    /// Timer etkin mi
    pub enabled: bool,
    /// Timer aktif mi
    pub active: bool,
    /// Bir sonraki çalışma zamanı
    pub next_run: Option<DateTime<Utc>>,
    /// Son çalışma zamanı
    pub last_run: Option<DateTime<Utc>>,
    /// Timer unit durumu
    pub unit_status: String,
}

/// Schedule öncelik seviyeleri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SchedulePriority {
    /// Yüksek öncelik - sistem kaynaklarını öncelikli kullan
    High,
    /// Normal öncelik
    Normal,
    /// Düşük öncelik - sistem yoğunken bekle
    Low,
}

impl std::fmt::Display for SchedulePriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchedulePriority::High => write!(f, "high"),
            SchedulePriority::Normal => write!(f, "normal"),
            SchedulePriority::Low => write!(f, "low"),
        }
    }
}

/// Schedule log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleLogEntry {
    pub id: u64,
    pub schedule_name: String,
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub success: bool,
    pub total_findings: u32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}