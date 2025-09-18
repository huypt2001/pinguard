use rusqlite::{params, Row};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, debug};
use crate::database::{DatabaseManager, DatabaseError, DatabaseResult};
use crate::scanners::ScanResult;
use crate::core::config::Config;

/// Scan history record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistoryRecord {
    pub id: Option<i64>,
    pub scan_id: String,
    pub scan_type: ScanType,
    pub scan_modules: Vec<String>,
    pub hostname: String,
    pub os_info: OsInfo,
    pub kernel_version: Option<String>,
    pub total_findings: i32,
    pub critical_findings: i32,
    pub high_findings: i32,
    pub medium_findings: i32,
    pub low_findings: i32,
    pub security_score: Option<i32>,
    pub risk_level: String,
    pub scan_duration_ms: i64,
    pub scan_started_at: DateTime<Utc>,
    pub scan_completed_at: DateTime<Utc>,
    pub scan_results: Vec<ScanResult>,
    pub config_snapshot: Option<Config>,
    pub created_at: DateTime<Utc>,
}

/// Scan types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    Full,           // All modules
    Partial,        // Specific modules
    SingleModule,   // Single module
    Quick,          // Quick scan
    Deep,           // Deep scan
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Full => write!(f, "full"),
            ScanType::Partial => write!(f, "partial"),
            ScanType::SingleModule => write!(f, "single_module"),
            ScanType::Quick => write!(f, "quick"),
            ScanType::Deep => write!(f, "deep"),
        }
    }
}

impl std::str::FromStr for ScanType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "full" => Ok(ScanType::Full),
            "partial" => Ok(ScanType::Partial),
            "single_module" => Ok(ScanType::SingleModule),
            "quick" => Ok(ScanType::Quick),
            "deep" => Ok(ScanType::Deep),
            _ => Err(format!("Invalid scan type: {}", s)),
        }
    }
}

/// Operating system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub distribution: Option<String>,
    pub architecture: String,
    pub kernel_version: String,
}

/// Scan history manager
pub struct ScanHistory {
    db: DatabaseManager,
}

impl ScanHistory {
    /// Create new scan history manager
    pub fn new(db: DatabaseManager) -> Self {
        Self { db }
    }

    /// Add scan history record
    pub fn add_scan_record(&self, record: &ScanHistoryRecord) -> DatabaseResult<i64> {
        debug!("💾 Adding scan history record: {}", record.scan_id);

        let scan_modules_json = serde_json::to_string(&record.scan_modules)
            .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize scan modules: {}", e)))?;

        let os_info_json = serde_json::to_string(&record.os_info)
            .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize OS info: {}", e)))?;

        let scan_results_json = serde_json::to_string(&record.scan_results)
            .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize scan results: {}", e)))?;

        let config_snapshot_json = match &record.config_snapshot {
            Some(config) => Some(serde_json::to_string(config)
                .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize config: {}", e)))?),
            None => None,
        };

        let row_id = self.db.connection().query_row(
            "INSERT INTO scan_history (
                scan_id, scan_type, scan_modules, hostname, os_info, kernel_version,
                total_findings, critical_findings, high_findings, medium_findings, low_findings,
                security_score, risk_level, scan_duration_ms, scan_started_at, scan_completed_at,
                scan_results, config_snapshot
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
            RETURNING id",
            params![
                record.scan_id,
                record.scan_type.to_string(),
                scan_modules_json,
                record.hostname,
                os_info_json,
                record.kernel_version,
                record.total_findings,
                record.critical_findings,
                record.high_findings,
                record.medium_findings,
                record.low_findings,
                record.security_score,
                record.risk_level,
                record.scan_duration_ms,
                record.scan_started_at,
                record.scan_completed_at,
                scan_results_json,
                config_snapshot_json
            ],
            |row| row.get(0)
        )?;

        // Add findings to detail table
        self.add_scan_findings(row_id, &record.scan_id, &record.scan_results)?;

        info!("✅ Scan history record added: {} (ID: {})", record.scan_id, row_id);
        Ok(row_id)
    }

    /// Add scan findings to detail table
    fn add_scan_findings(&self, _scan_history_id: i64, scan_id: &str, scan_results: &[ScanResult]) -> DatabaseResult<()> {
        let mut stmt = self.db.connection().prepare(
            "INSERT INTO scan_findings (
                scan_id, finding_id, scanner_name, title, description, severity, category,
                affected_item, current_value, recommended_value, cve_ids, finding_references, fix_available
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
        )?;

        for scan_result in scan_results {
            for finding in &scan_result.findings {
                let cve_ids_json = serde_json::to_string(&finding.cve_ids)
                    .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize CVE IDs: {}", e)))?;

                let references_json = serde_json::to_string(&finding.references)
                    .map_err(|e| DatabaseError::SerializationError(format!("Failed to serialize references: {}", e)))?;

                stmt.execute(params![
                    scan_id,
                    finding.id,
                    scan_result.scanner_name,
                    finding.title,
                    finding.description,
                    format!("{:?}", finding.severity),
                    format!("{:?}", finding.category),
                    finding.affected_item,
                    finding.current_value,
                    finding.recommended_value,
                    cve_ids_json,
                    references_json,
                    finding.fix_available
                ])?;
            }
        }

        Ok(())
    }

    /// Get scan history record by ID
    pub fn get_scan_record(&self, scan_id: &str) -> DatabaseResult<Option<ScanHistoryRecord>> {
        debug!("🔍 Searching for scan history record: {}", scan_id);

        let mut stmt = self.db.connection().prepare(
            "SELECT id, scan_id, scan_type, scan_modules, hostname, os_info, kernel_version,
                    total_findings, critical_findings, high_findings, medium_findings, low_findings,
                    security_score, risk_level, scan_duration_ms, scan_started_at, scan_completed_at,
                    scan_results, config_snapshot, created_at
             FROM scan_history WHERE scan_id = ?1"
        )?;

        let result = stmt.query_row(params![scan_id], |row| {
            self.row_to_scan_record(row)
        });

        match result {
            Ok(record) => {
                debug!("✅ Scan history record found: {}", scan_id);
                Ok(Some(record))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                debug!("❌ Scan history record not found: {}", scan_id);
                Ok(None)
            }
            Err(e) => Err(DatabaseError::SqliteError(e)),
        }
    }

    /// Get last N scan records
    pub fn get_recent_scans(&self, limit: u32) -> DatabaseResult<Vec<ScanHistoryRecord>> {
        debug!("🔍 Getting last {} scan records", limit);

        let mut stmt = self.db.connection().prepare(
            "SELECT id, scan_id, scan_type, scan_modules, hostname, os_info, kernel_version,
                    total_findings, critical_findings, high_findings, medium_findings, low_findings,
                    security_score, risk_level, scan_duration_ms, scan_started_at, scan_completed_at,
                    scan_results, config_snapshot, created_at
             FROM scan_history 
             ORDER BY scan_started_at DESC 
             LIMIT ?1"
        )?;

        let records = stmt.query_map(params![limit], |row| {
            self.row_to_scan_record(row)
        })?
        .collect::<Result<Vec<_>, _>>()?;

        debug!("✅ {} scan records found", records.len());
        Ok(records)
    }

    /// Get scan history for hostname
    pub fn get_scans_by_hostname(&self, hostname: &str, limit: Option<u32>) -> DatabaseResult<Vec<ScanHistoryRecord>> {
        debug!("🔍 Scan history for hostname: {}", hostname);

        let limit_clause = match limit {
            Some(l) => format!(" LIMIT {}", l),
            None => String::new(),
        };

        let query = format!(
            "SELECT id, scan_id, scan_type, scan_modules, hostname, os_info, kernel_version,
                    total_findings, critical_findings, high_findings, medium_findings, low_findings,
                    security_score, risk_level, scan_duration_ms, scan_started_at, scan_completed_at,
                    scan_results, config_snapshot, created_at
             FROM scan_history 
             WHERE hostname = ?1 
             ORDER BY scan_started_at DESC{}",
            limit_clause
        );

        let mut stmt = self.db.connection().prepare(&query)?;
        let records = stmt.query_map(params![hostname], |row| {
            self.row_to_scan_record(row)
        })?
        .collect::<Result<Vec<_>, _>>()?;

        debug!("✅ {} scan records found for hostname: {}", records.len(), hostname);
        Ok(records)
    }

    /// Get scans in specific date range
    pub fn get_scans_by_date_range(
        &self, 
        start_date: DateTime<Utc>, 
        end_date: DateTime<Utc>
    ) -> DatabaseResult<Vec<ScanHistoryRecord>> {
        debug!("🔍 Scan history for date range: {} - {}", start_date, end_date);

        let mut stmt = self.db.connection().prepare(
            "SELECT id, scan_id, scan_type, scan_modules, hostname, os_info, kernel_version,
                    total_findings, critical_findings, high_findings, medium_findings, low_findings,
                    security_score, risk_level, scan_duration_ms, scan_started_at, scan_completed_at,
                    scan_results, config_snapshot, created_at
             FROM scan_history 
             WHERE scan_started_at BETWEEN ?1 AND ?2 
             ORDER BY scan_started_at DESC"
        )?;

        let records = stmt.query_map(params![start_date, end_date], |row| {
            self.row_to_scan_record(row)
        })?
        .collect::<Result<Vec<_>, _>>()?;

        debug!("✅ {} scan records found for date range", records.len());
        Ok(records)
    }

    /// Get security score trend
    pub fn get_security_score_trend(&self, hostname: &str, days: u32) -> DatabaseResult<Vec<SecurityScoreTrend>> {
        debug!("📈 Getting security score trend: {} (last {} days)", hostname, days);

        let since_date = Utc::now() - chrono::Duration::days(days as i64);

        let mut stmt = self.db.connection().prepare(
            "SELECT scan_started_at, security_score, total_findings, risk_level
             FROM scan_history 
             WHERE hostname = ?1 AND scan_started_at >= ?2 AND security_score IS NOT NULL
             ORDER BY scan_started_at ASC"
        )?;

        let trends = stmt.query_map(params![hostname, since_date], |row| {
            Ok(SecurityScoreTrend {
                date: row.get("scan_started_at")?,
                security_score: row.get("security_score")?,
                total_findings: row.get("total_findings")?,
                risk_level: row.get("risk_level")?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

        debug!("✅ {} trend records found", trends.len());
        Ok(trends)
    }

    /// Get findings by scan ID
    pub fn get_scan_findings(&self, scan_id: &str) -> DatabaseResult<Vec<ScanFinding>> {
        debug!("🔍 Getting scan findings: {}", scan_id);

        let mut stmt = self.db.connection().prepare(
            "SELECT finding_id, scanner_name, title, description, severity, category,
                    affected_item, current_value, recommended_value, cve_ids, finding_references, 
                    fix_available, created_at
             FROM scan_findings 
             WHERE scan_id = ?1 
             ORDER BY severity DESC, created_at ASC"
        )?;

        let findings = stmt.query_map(params![scan_id], |row| {
            let cve_ids_json: String = row.get("cve_ids")?;
            let references_json: String = row.get("finding_references")?;

            let cve_ids: Vec<String> = serde_json::from_str(&cve_ids_json)
                .map_err(|e| rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH), 
                    Some(format!("JSON parse error: {}", e))
                ))?;

            let references: Vec<String> = serde_json::from_str(&references_json)
                .map_err(|e| rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH), 
                    Some(format!("JSON parse error: {}", e))
                ))?;

            Ok(ScanFinding {
                finding_id: row.get("finding_id")?,
                scanner_name: row.get("scanner_name")?,
                title: row.get("title")?,
                description: row.get("description")?,
                severity: row.get("severity")?,
                category: row.get("category")?,
                affected_item: row.get("affected_item")?,
                current_value: row.get("current_value")?,
                recommended_value: row.get("recommended_value")?,
                cve_ids,
                references,
                fix_available: row.get("fix_available")?,
                created_at: row.get("created_at")?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

        debug!("✅ {} findings found", findings.len());
        Ok(findings)
    }

    /// Get scan history statistics
    pub fn get_history_stats(&self) -> DatabaseResult<HistoryStats> {
        debug!("📊 Calculating scan history statistics...");

        let mut stats = HistoryStats::default();

        // Total scan count
        let mut stmt = self.db.connection().prepare("SELECT COUNT(*) FROM scan_history")?;
        stats.total_scans = stmt.query_row([], |row| row.get(0))?;

        // Scan count last 30 days
        let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
        let mut stmt = self.db.connection().prepare("SELECT COUNT(*) FROM scan_history WHERE scan_started_at >= ?1")?;
        stats.scans_last_30_days = stmt.query_row(params![thirty_days_ago], |row| row.get(0))?;

        // Unique hostname count
        let mut stmt = self.db.connection().prepare("SELECT COUNT(DISTINCT hostname) FROM scan_history")?;
        stats.unique_hostnames = stmt.query_row([], |row| row.get(0))?;

        // Average security score
        let mut stmt = self.db.connection().prepare("SELECT AVG(security_score) FROM scan_history WHERE security_score IS NOT NULL")?;
        stats.average_security_score = stmt.query_row([], |row| row.get(0)).unwrap_or(0.0);

        // Total finding count
        let mut stmt = self.db.connection().prepare("SELECT SUM(total_findings) FROM scan_history")?;
        stats.total_findings = stmt.query_row([], |row| row.get(0)).unwrap_or(0);

        // Scan type distribution
        let mut stmt = self.db.connection().prepare(
            "SELECT scan_type, COUNT(*) FROM scan_history GROUP BY scan_type"
        )?;
        let type_rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
        })?;

        for row in type_rows {
            let (scan_type, count) = row?;
            match scan_type.as_str() {
                "full" => stats.full_scans = count,
                "partial" => stats.partial_scans = count,
                "single_module" => stats.single_module_scans = count,
                "quick" => stats.quick_scans = count,
                "deep" => stats.deep_scans = count,
                _ => {}
            }
        }

        debug!("✅ Scan history statistics prepared");
        Ok(stats)
    }

    /// Clean up old scan records
    pub fn cleanup_old_scans(&self, days_to_keep: u32) -> DatabaseResult<usize> {
        info!("🧹 Cleaning up scan records older than {} days...", days_to_keep);

        let cutoff_date = Utc::now() - chrono::Duration::days(days_to_keep as i64);
        
        let deleted_count = self.db.connection().execute(
            "DELETE FROM scan_history WHERE scan_started_at < ?1",
            params![cutoff_date],
        )?;

        if deleted_count > 0 {
            info!("{} old scan records cleaned", deleted_count);
        } else {
            debug!("No old scan records to clean found");
        }

        Ok(deleted_count)
    }

    /// Create ScanHistoryRecord from row
    fn row_to_scan_record(&self, row: &Row) -> rusqlite::Result<ScanHistoryRecord> {
        let scan_modules_json: String = row.get("scan_modules")?;
        let os_info_json: String = row.get("os_info")?;
        let scan_results_json: String = row.get("scan_results")?;
        let config_snapshot_json: Option<String> = row.get("config_snapshot")?;

        let scan_modules: Vec<String> = serde_json::from_str(&scan_modules_json)
            .map_err(|e| rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH), 
                Some(format!("JSON parse error: {}", e))
            ))?;

        let os_info: OsInfo = serde_json::from_str(&os_info_json)
            .map_err(|e| rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH), 
                Some(format!("JSON parse error: {}", e))
            ))?;

        let scan_results: Vec<ScanResult> = serde_json::from_str(&scan_results_json)
            .map_err(|e| rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH), 
                Some(format!("JSON parse error: {}", e))
            ))?;

        let config_snapshot: Option<Config> = match config_snapshot_json {
            Some(json) => Some(serde_json::from_str(&json)
                .map_err(|e| rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH), 
                    Some(format!("JSON parse error: {}", e))
                ))?),
            None => None,
        };

        let scan_type_str: String = row.get("scan_type")?;
        let scan_type = scan_type_str.parse::<ScanType>()
            .map_err(|e| rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH), 
                Some(format!("Parse error: {}", e))
            ))?;

        Ok(ScanHistoryRecord {
            id: Some(row.get("id")?),
            scan_id: row.get("scan_id")?,
            scan_type,
            scan_modules,
            hostname: row.get("hostname")?,
            os_info,
            kernel_version: row.get("kernel_version")?,
            total_findings: row.get("total_findings")?,
            critical_findings: row.get("critical_findings")?,
            high_findings: row.get("high_findings")?,
            medium_findings: row.get("medium_findings")?,
            low_findings: row.get("low_findings")?,
            security_score: row.get("security_score")?,
            risk_level: row.get("risk_level")?,
            scan_duration_ms: row.get("scan_duration_ms")?,
            scan_started_at: row.get("scan_started_at")?,
            scan_completed_at: row.get("scan_completed_at")?,
            scan_results,
            config_snapshot,
            created_at: row.get("created_at")?,
        })
    }
}

/// Security score trend data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScoreTrend {
    pub date: DateTime<Utc>,
    pub security_score: i32,
    pub total_findings: i32,
    pub risk_level: String,
}

/// Scan finding (from detail table)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub finding_id: String,
    pub scanner_name: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub affected_item: String,
    pub current_value: Option<String>,
    pub recommended_value: Option<String>,
    pub cve_ids: Vec<String>,
    pub references: Vec<String>,
    pub fix_available: bool,
    pub created_at: DateTime<Utc>,
}

/// History statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HistoryStats {
    pub total_scans: i32,
    pub scans_last_30_days: i32,
    pub unique_hostnames: i32,
    pub average_security_score: f64,
    pub total_findings: i64,
    pub full_scans: i32,
    pub partial_scans: i32,
    pub single_module_scans: i32,
    pub quick_scans: i32,
    pub deep_scans: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseManager;
    use crate::scanners::{ScanResult, ScanStatus, ScanMetadata};

    fn create_test_scan_record() -> ScanHistoryRecord {
        ScanHistoryRecord {
            id: None,
            scan_id: "scan-123".to_string(),
            scan_type: ScanType::Full,
            scan_modules: vec!["package".to_string(), "kernel".to_string()],
            hostname: "test-host".to_string(),
            os_info: OsInfo {
                name: "Ubuntu".to_string(),
                version: "22.04".to_string(),
                distribution: Some("ubuntu".to_string()),
                architecture: "x86_64".to_string(),
                kernel_version: "5.15.0".to_string(),
            },
            kernel_version: Some("5.15.0".to_string()),
            total_findings: 5,
            critical_findings: 0,
            high_findings: 2,
            medium_findings: 2,
            low_findings: 1,
            security_score: Some(75),
            risk_level: "MEDIUM".to_string(),
            scan_duration_ms: 30000,
            scan_started_at: Utc::now() - chrono::Duration::minutes(1),
            scan_completed_at: Utc::now(),
            scan_results: vec![
                ScanResult {
                    scanner_name: "Test Scanner".to_string(),
                    scan_time: Utc::now().to_rfc3339(),
                    status: ScanStatus::Success,
                    findings: vec![],
                    metadata: ScanMetadata {
                        duration_ms: 1000,
                        items_scanned: 100,
                        issues_found: 5,
                        scan_timestamp: Utc::now().to_rfc3339(),
                        scanner_version: "1.0.0".to_string(),
                    },
                    raw_data: None,
                }
            ],
            config_snapshot: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_add_and_get_scan_record() {
        let db = DatabaseManager::new_test().unwrap();
        let history = ScanHistory::new(db);
        let test_record = create_test_scan_record();

        // Add scan record
        let record_id = history.add_scan_record(&test_record).unwrap();
        assert!(record_id > 0);

        // Retrieve scan record
        let retrieved = history.get_scan_record(&test_record.scan_id).unwrap();
        assert!(retrieved.is_some());

        let retrieved_record = retrieved.unwrap();
        assert_eq!(retrieved_record.scan_id, test_record.scan_id);
        assert_eq!(retrieved_record.hostname, test_record.hostname);
        assert_eq!(retrieved_record.total_findings, test_record.total_findings);
    }

    #[test]
    fn test_get_recent_scans() {
        let db = DatabaseManager::new_test().unwrap();
        let history = ScanHistory::new(db);
        let test_record = create_test_scan_record();

        history.add_scan_record(&test_record).unwrap();

        let recent_scans = history.get_recent_scans(5).unwrap();
        assert_eq!(recent_scans.len(), 1);
        assert_eq!(recent_scans[0].scan_id, test_record.scan_id);
    }

    #[test]
    fn test_history_stats() {
        let db = DatabaseManager::new_test().unwrap();
        let history = ScanHistory::new(db);
        let test_record = create_test_scan_record();

        history.add_scan_record(&test_record).unwrap();

        let stats = history.get_history_stats().unwrap();
        assert_eq!(stats.total_scans, 1);
        assert_eq!(stats.unique_hostnames, 1);
        assert_eq!(stats.full_scans, 1);
    }
}