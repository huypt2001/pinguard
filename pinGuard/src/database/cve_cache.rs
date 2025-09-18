use rusqlite::{params, Row};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use tracing::{info, debug};
use crate::database::{DatabaseManager, DatabaseError, DatabaseResult};

/// CVE verisi yapısı (NVD API'den gelen data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveData {
    pub cve_id: String,
    pub description: String,
    pub severity: CveSeverity,
    pub score: Option<f64>,
    pub vector_string: Option<String>,
    pub published_date: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub affected_packages: Vec<String>,
    pub affected_versions: Vec<VersionRange>,
    pub references: Vec<String>,
    pub cpe_matches: Vec<CpeMatch>,
    pub raw_nvd_data: Option<String>, // Full JSON from NVD
}

/// CVE severity seviyeleri
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CveSeverity {
    Critical,
    High,
    Medium,
    Low,
    None,
    Unknown,
}

impl std::fmt::Display for CveSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CveSeverity::Critical => write!(f, "CRITICAL"),
            CveSeverity::High => write!(f, "HIGH"),
            CveSeverity::Medium => write!(f, "MEDIUM"),
            CveSeverity::Low => write!(f, "LOW"),
            CveSeverity::None => write!(f, "NONE"),
            CveSeverity::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl std::str::FromStr for CveSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Ok(CveSeverity::Critical),
            "HIGH" => Ok(CveSeverity::High),
            "MEDIUM" => Ok(CveSeverity::Medium),
            "LOW" => Ok(CveSeverity::Low),
            "NONE" => Ok(CveSeverity::None),
            "UNKNOWN" => Ok(CveSeverity::Unknown),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}

/// Version range için struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    pub version_start: Option<String>,
    pub version_end: Option<String>,
    pub version_start_including: bool,
    pub version_end_including: bool,
}

/// CPE match criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeMatch {
    pub cpe23_uri: String,
    pub version_start: Option<String>,
    pub version_end: Option<String>,
    pub vulnerable: bool,
}

/// Cache'lenmiş CVE verisi
#[derive(Debug, Clone)]
pub struct CachedCve {
    pub data: CveData,
    pub cached_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// CVE cache manager
pub struct CveCache {
    db: DatabaseManager,
    cache_ttl: Duration, // Cache geçerlilik süresi
}

impl CveCache {
    /// Yeni CVE cache oluştur
    pub fn new(db: DatabaseManager) -> Self {
        Self {
            db,
            cache_ttl: Duration::hours(24), // 24 saat cache
        }
    }

    /// Cache TTL'yi ayarla
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// CVE'yi cache'e ekle veya güncelle
    pub fn cache_cve(&self, cve_data: &CveData) -> DatabaseResult<()> {
        debug!("💾 CVE cache'e ekleniyor: {}", cve_data.cve_id);

        let expires_at = Utc::now() + self.cache_ttl;
        
        let affected_packages_json = serde_json::to_string(&cve_data.affected_packages)
            .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize packages: {}", e)))?;
        
        let affected_versions_json = serde_json::to_string(&cve_data.affected_versions)
            .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize versions: {}", e)))?;
        
        let references_json = serde_json::to_string(&cve_data.references)
            .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize references: {}", e)))?;
        
        let cpe_matches_json = serde_json::to_string(&cve_data.cpe_matches)
            .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize CPE matches: {}", e)))?;

        self.db.connection().execute(
            "INSERT OR REPLACE INTO cve_cache (
                cve_id, description, severity, score, vector_string, 
                published_date, last_modified, affected_packages, affected_versions,
                cve_references, cpe_matches, raw_nvd_data, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                cve_data.cve_id,
                cve_data.description,
                cve_data.severity.to_string(),
                cve_data.score,
                cve_data.vector_string,
                cve_data.published_date,
                cve_data.last_modified,
                affected_packages_json,
                affected_versions_json,
                references_json,
                cpe_matches_json,
                cve_data.raw_nvd_data,
                expires_at
            ],
        )?;

        debug!("✅ CVE başarıyla cache'lendi: {}", cve_data.cve_id);
        Ok(())
    }

    /// CVE'yi cache'ten al
    pub fn get_cve(&self, cve_id: &str) -> DatabaseResult<Option<CachedCve>> {
        debug!("🔍 CVE cache'ten aranıyor: {}", cve_id);

        let mut stmt = self.db.connection().prepare(
            "SELECT cve_id, description, severity, score, vector_string,
                    published_date, last_modified, affected_packages, affected_versions,
                    cve_references, cpe_matches, raw_nvd_data, cached_at, expires_at
             FROM cve_cache WHERE cve_id = ?1"
        )?;

        let result = stmt.query_row(params![cve_id], |row| {
            self.row_to_cached_cve(row)
        });

        match result {
            Ok(cached_cve) => {
                // Expire olmuş mu kontrol et
                if cached_cve.expires_at < Utc::now() {
                    debug!("⏰ CVE cache'i expire olmuş: {}", cve_id);
                    Ok(None)
                } else {
                    debug!("✅ CVE cache'ten bulundu: {}", cve_id);
                    Ok(Some(cached_cve))
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                debug!("❌ CVE cache'te bulunamadı: {}", cve_id);
                Ok(None)
            }
            Err(e) => Err(DatabaseError::SqliteError(e)),
        }
    }

    /// CVE'leri toplu olarak cache'ten al
    pub fn get_cves(&self, cve_ids: &[String]) -> DatabaseResult<Vec<CachedCve>> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }

        debug!("🔍 {} CVE cache'ten toplu aranıyor", cve_ids.len());

        let placeholders = cve_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query = format!(
            "SELECT cve_id, description, severity, score, vector_string,
                    published_date, last_modified, affected_packages, affected_versions,
                    references, cpe_matches, raw_nvd_data, cached_at, expires_at
             FROM cve_cache WHERE cve_id IN ({}) AND expires_at > ?{}",
            placeholders, cve_ids.len() + 1
        );

        let mut stmt = self.db.connection().prepare(&query)?;
        
        let mut params: Vec<&dyn rusqlite::ToSql> = cve_ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
        let now = Utc::now();
        params.push(&now);

        let cached_cves = stmt.query_map(&*params, |row| {
            self.row_to_cached_cve(row)
        })?
        .collect::<Result<Vec<_>, _>>()?;

        debug!("✅ {} CVE cache'ten bulundu", cached_cves.len());
        Ok(cached_cves)
    }

    /// Package için ilgili CVE'leri bul
    pub fn find_cves_for_package(&self, package_name: &str) -> DatabaseResult<Vec<CachedCve>> {
        debug!("🔍 Package için CVE aranıyor: {}", package_name);

        let mut stmt = self.db.connection().prepare(
            "SELECT cve_id, description, severity, score, vector_string,
                    published_date, last_modified, affected_packages, affected_versions,
                    cve_references, cpe_matches, raw_nvd_data, cached_at, expires_at
             FROM cve_cache 
             WHERE affected_packages LIKE ?1 
               AND expires_at > ?2
             ORDER BY severity DESC, published_date DESC"
        )?;

        let package_pattern = format!("%\"{}\"%" , package_name);
        let now = Utc::now();

        let cached_cves = stmt.query_map(params![package_pattern, now], |row| {
            self.row_to_cached_cve(row)
        })?
        .collect::<Result<Vec<_>, _>>()?;

        debug!("✅ {} CVE bulundu package için: {}", cached_cves.len(), package_name);
        Ok(cached_cves)
    }

    /// Severity'ye göre CVE'leri listele
    pub fn list_cves_by_severity(&self, severity: CveSeverity, limit: Option<u32>) -> DatabaseResult<Vec<CachedCve>> {
        debug!("🔍 Severity'ye göre CVE listesi: {}", severity);

        let limit_clause = match limit {
            Some(l) => format!(" LIMIT {}", l),
            None => String::new(),
        };

        let query = format!(
            "SELECT cve_id, description, severity, score, vector_string,
                    published_date, last_modified, affected_packages, affected_versions,
                    cve_references, cpe_matches, raw_nvd_data, cached_at, expires_at
             FROM cve_cache 
             WHERE severity = ?1 AND expires_at > ?2
             ORDER BY published_date DESC{}",
            limit_clause
        );

        let mut stmt = self.db.connection().prepare(&query)?;
        let now = Utc::now();

        let cached_cves = stmt.query_map(params![severity.to_string(), now], |row| {
            self.row_to_cached_cve(row)
        })?
        .collect::<Result<Vec<_>, _>>()?;

        debug!("✅ {} CVE bulundu severity için: {}", cached_cves.len(), severity);
        Ok(cached_cves)
    }

    /// Expire olmuş cache girişlerini temizle
    pub fn cleanup_expired(&self) -> DatabaseResult<usize> {
        info!("🧹 Expire olmuş CVE cache girişleri temizleniyor...");

        let now = Utc::now();
        let deleted_count = self.db.connection().execute(
            "DELETE FROM cve_cache WHERE expires_at < ?1",
            params![now],
        )?;

        if deleted_count > 0 {
            info!("✅ {} expire olmuş CVE girişi temizlendi", deleted_count);
        } else {
            debug!("ℹ️ Temizlenecek expire olmuş giriş bulunamadı");
        }

        Ok(deleted_count)
    }

    /// Cache istatistiklerini al
    pub fn get_cache_stats(&self) -> DatabaseResult<CacheStats> {
        debug!("📊 CVE cache istatistikleri hesaplanıyor...");

        let mut stats = CacheStats::default();

        // Toplam cache girişi
        let mut stmt = self.db.connection().prepare("SELECT COUNT(*) FROM cve_cache")?;
        stats.total_entries = stmt.query_row([], |row| row.get(0))?;

        // Aktif cache girişi (expire olmamış)
        let now = Utc::now();
        let mut stmt = self.db.connection().prepare("SELECT COUNT(*) FROM cve_cache WHERE expires_at > ?1")?;
        stats.active_entries = stmt.query_row(params![now], |row| row.get(0))?;

        // Expire olmuş girişler
        stats.expired_entries = stats.total_entries - stats.active_entries;

        // Severity dağılımı
        let mut stmt = self.db.connection().prepare(
            "SELECT severity, COUNT(*) FROM cve_cache WHERE expires_at > ?1 GROUP BY severity"
        )?;
        let severity_rows = stmt.query_map(params![now], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
        })?;

        for row in severity_rows {
            let (severity_str, count) = row?;
            match severity_str.as_str() {
                "CRITICAL" => stats.critical_count = count,
                "HIGH" => stats.high_count = count,
                "MEDIUM" => stats.medium_count = count,
                "LOW" => stats.low_count = count,
                "NONE" => stats.none_count = count,
                _ => {}
            }
        }

        // Cache boyutu (yaklaşık)
        let mut stmt = self.db.connection().prepare(
            "SELECT SUM(LENGTH(description) + LENGTH(raw_nvd_data)) FROM cve_cache"
        )?;
        stats.cache_size_bytes = stmt.query_row([], |row| row.get(0)).unwrap_or(0);

        debug!("✅ CVE cache istatistikleri hazırlandı");
        Ok(stats)
    }

    /// Row'dan CachedCve oluştur
    fn row_to_cached_cve(&self, row: &Row) -> rusqlite::Result<CachedCve> {
        let affected_packages_json: String = row.get("affected_packages")?;
        let affected_versions_json: String = row.get("affected_versions")?;
        let references_json: String = row.get("cve_references")?;
        let cpe_matches_json: String = row.get("cpe_matches")?;

        let affected_packages: Vec<String> = serde_json::from_str(&affected_packages_json)
            .map_err(|e| rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH), 
                Some(format!("JSON parse error: {}", e))
            ))?;

        let affected_versions: Vec<VersionRange> = serde_json::from_str(&affected_versions_json)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                0, rusqlite::types::Type::Text, Box::new(e)
            ))?;

        let references: Vec<String> = serde_json::from_str(&references_json)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                0, rusqlite::types::Type::Text, Box::new(e)
            ))?;

        let cpe_matches: Vec<CpeMatch> = serde_json::from_str(&cpe_matches_json)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                0, rusqlite::types::Type::Text, Box::new(e)
            ))?;

        let severity_str: String = row.get("severity")?;
        let severity = severity_str.parse::<CveSeverity>()
            .map_err(|e| rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH), 
                Some(format!("Parse error: {}", e))
            ))?;

        Ok(CachedCve {
            data: CveData {
                cve_id: row.get("cve_id")?,
                description: row.get("description")?,
                severity,
                score: row.get("score")?,
                vector_string: row.get("vector_string")?,
                published_date: row.get("published_date")?,
                last_modified: row.get("last_modified")?,
                affected_packages,
                affected_versions,
                references,
                cpe_matches,
                raw_nvd_data: row.get("raw_nvd_data")?,
            },
            cached_at: row.get("cached_at")?,
            expires_at: row.get("expires_at")?,
        })
    }
}

/// Cache istatistikleri
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: i32,
    pub active_entries: i32,
    pub expired_entries: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub none_count: i32,
    pub cache_size_bytes: i64,
}

impl CacheStats {
    pub fn cache_size_mb(&self) -> f64 {
        self.cache_size_bytes as f64 / 1024.0 / 1024.0
    }

    pub fn hit_rate(&self) -> f64 {
        if self.total_entries == 0 {
            0.0
        } else {
            self.active_entries as f64 / self.total_entries as f64 * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseManager;

    fn create_test_cve_data() -> CveData {
        CveData {
            cve_id: "CVE-2023-1234".to_string(),
            description: "Test vulnerability".to_string(),
            severity: CveSeverity::High,
            score: Some(7.5),
            vector_string: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
            published_date: Utc::now() - Duration::days(1),
            last_modified: Utc::now() - Duration::hours(1),
            affected_packages: vec!["openssl".to_string(), "libssl".to_string()],
            affected_versions: vec![],
            references: vec!["https://example.com/cve-2023-1234".to_string()],
            cpe_matches: vec![],
            raw_nvd_data: Some("{}".to_string()),
        }
    }

    #[test]
    fn test_cache_and_retrieve_cve() {
        let db = DatabaseManager::new_test().unwrap();
        let cache = CveCache::new(db);
        let test_cve = create_test_cve_data();

        // CVE'yi cache'le
        cache.cache_cve(&test_cve).unwrap();

        // CVE'yi geri al
        let cached = cache.get_cve(&test_cve.cve_id).unwrap();
        assert!(cached.is_some());

        let cached_cve = cached.unwrap();
        assert_eq!(cached_cve.data.cve_id, test_cve.cve_id);
        assert_eq!(cached_cve.data.description, test_cve.description);
        assert_eq!(cached_cve.data.severity, test_cve.severity);
    }

    #[test]
    fn test_find_cves_for_package() {
        let db = DatabaseManager::new_test().unwrap();
        let cache = CveCache::new(db);
        let test_cve = create_test_cve_data();

        cache.cache_cve(&test_cve).unwrap();

        let cves = cache.find_cves_for_package("openssl").unwrap();
        assert_eq!(cves.len(), 1);
        assert_eq!(cves[0].data.cve_id, test_cve.cve_id);
    }

    #[test]
    fn test_cache_stats() {
        let db = DatabaseManager::new_test().unwrap();
        let cache = CveCache::new(db);
        let test_cve = create_test_cve_data();

        cache.cache_cve(&test_cve).unwrap();

        let stats = cache.get_cache_stats().unwrap();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.active_entries, 1);
        assert_eq!(stats.high_count, 1);
    }
}