use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Schedule konfigürasyonu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Schedule adı (benzersiz)
    pub name: String,
    /// Description
    pub description: String,
    /// Schedule expression (cron-like format)
    pub schedule: String,
    /// Scan type to execute
    pub scan_type: ScanType,
    /// Scan modules
    pub scan_modules: Vec<String>,
    /// Custom configuration
    pub options: HashMap<String, String>,
    /// Is active
    pub enabled: bool,
    /// Creation date
    pub created_at: DateTime<Utc>,
    /// Last update
    pub updated_at: DateTime<Utc>,
}

impl ScheduleConfig {
    /// Create new schedule config
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

/// Scan type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    /// Full scan - run all scanners
    Full,
    /// Quick scan - only package audit
    Quick,
    /// Security scan - permission, service, user audits
    Security,
    /// Custom scan - specified modules
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
    /// Last run information
    pub last_run: Option<LastRunInfo>,
    /// Next run time
    pub next_run: Option<DateTime<Utc>>,
    /// Schedule configuration
    pub config: ScheduleConfig,
}

/// Last run information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastRunInfo {
    /// Çalışma zamanı
    pub run_time: DateTime<Utc>,
    /// Başarılı mı
    pub success: bool,
    /// Duration (milliseconds)
    pub duration_ms: u64,
    /// Number of findings found
    pub findings_count: u32,
    /// Error message (if any)
    pub error_message: Option<String>,
}

/// Systemd timer status
#[derive(Debug, Clone)]
pub struct SystemdTimerStatus {
    /// Is timer enabled
    pub enabled: bool,
    /// Is timer active
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