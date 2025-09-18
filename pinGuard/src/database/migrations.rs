use rusqlite::Connection;
use crate::database::DatabaseError;

type MigrationResult = Result<(), DatabaseError>;

/// CVE cache tablosunu oluştur
pub fn create_cve_cache_table(conn: &mut Connection) -> MigrationResult {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cve_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL UNIQUE, description TEXT NOT NULL, severity TEXT NOT NULL, score REAL, vector_string TEXT, published_date DATETIME, last_modified DATETIME, affected_packages TEXT, affected_versions TEXT, cve_references TEXT, cpe_matches TEXT, raw_nvd_data TEXT, cached_at DATETIME DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
        [],
    )?;

    // CVE cache için trigger oluştur (updated_at otomatik güncelleme)
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS update_cve_cache_timestamp AFTER UPDATE ON cve_cache BEGIN UPDATE cve_cache SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id; END",
        [],
    )?;

    Ok(())
}

/// Scan history tablosunu oluştur
pub fn create_scan_history_table(conn: &mut Connection) -> MigrationResult {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_history (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL UNIQUE, scan_type TEXT NOT NULL, scan_modules TEXT NOT NULL, hostname TEXT NOT NULL, os_info TEXT NOT NULL, kernel_version TEXT, total_findings INTEGER NOT NULL DEFAULT 0, critical_findings INTEGER NOT NULL DEFAULT 0, high_findings INTEGER NOT NULL DEFAULT 0, medium_findings INTEGER NOT NULL DEFAULT 0, low_findings INTEGER NOT NULL DEFAULT 0, security_score INTEGER, risk_level TEXT, scan_duration_ms INTEGER NOT NULL, scan_started_at DATETIME NOT NULL, scan_completed_at DATETIME NOT NULL, scan_results TEXT NOT NULL, config_snapshot TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
        [],
    )?;

    // Scan findings detay tablosu (normalleştirilmiş)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, scanner_name TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL, affected_item TEXT NOT NULL, current_value TEXT, recommended_value TEXT, cve_ids TEXT, finding_references TEXT, fix_available BOOLEAN DEFAULT FALSE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id) ON DELETE CASCADE)",
        [],
    )?;

    Ok(())
}

/// Schedule logs tablosunu oluştur
pub fn create_schedule_logs_table(conn: &mut Connection) -> MigrationResult {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schedule_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, schedule_name TEXT NOT NULL, scan_id TEXT NOT NULL, started_at DATETIME NOT NULL, completed_at DATETIME, success BOOLEAN NOT NULL DEFAULT FALSE, total_findings INTEGER DEFAULT 0, critical_findings INTEGER DEFAULT 0, high_findings INTEGER DEFAULT 0, medium_findings INTEGER DEFAULT 0, low_findings INTEGER DEFAULT 0, security_score INTEGER, scan_duration_ms INTEGER, error_message TEXT, log_data TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
        [],
    )?;

    Ok(())
}

/// Performans için indeksler oluştur
pub fn create_indexes(conn: &mut Connection) -> MigrationResult {
    // CVE cache indeksleri
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_cve_id ON cve_cache(cve_id)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_severity ON cve_cache(severity)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_published_date ON cve_cache(published_date)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_expires_at ON cve_cache(expires_at)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_packages ON cve_cache(affected_packages)", [])?;

    // Scan history indeksleri
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_scan_id ON scan_history(scan_id)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_hostname ON scan_history(hostname)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_scan_type ON scan_history(scan_type)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_scan_started_at ON scan_history(scan_started_at)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_security_score ON scan_history(security_score)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_risk_level ON scan_history(risk_level)", [])?;

    // Scan findings indeksleri
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id ON scan_findings(scan_id)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_findings_finding_id ON scan_findings(finding_id)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_findings_scanner_name ON scan_findings(scanner_name)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_findings_severity ON scan_findings(severity)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_findings_category ON scan_findings(category)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_findings_cve_ids ON scan_findings(cve_ids)", [])?;

    // Schedule logs indeksleri
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schedule_logs_schedule_name ON schedule_logs(schedule_name)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schedule_logs_scan_id ON schedule_logs(scan_id)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schedule_logs_started_at ON schedule_logs(started_at)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schedule_logs_success ON schedule_logs(success)", [])?;

    // Composite indeksler
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_severity_published ON cve_cache(severity, published_date)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_hostname_date ON scan_history(hostname, scan_started_at)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_severity ON scan_findings(scan_id, severity)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schedule_logs_name_date ON schedule_logs(schedule_name, started_at)", [])?;

    Ok(())
}

/// Veritabanı schema versiyonunu kontrol et ve upgrade et
pub fn check_and_upgrade_schema(conn: &mut Connection) -> MigrationResult {
    // Schema version tablosunu oluştur
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // Mevcut schema version'ını al
    let current_version: i32 = conn
        .prepare("SELECT COALESCE(MAX(version), 0) FROM schema_version")?
        .query_row([], |row| row.get(0))
        .unwrap_or(0);

    const LATEST_VERSION: i32 = 1;

    if current_version < LATEST_VERSION {
        // Upgrade gerekli
        for version in (current_version + 1)..=LATEST_VERSION {
            match version {
                1 => {
                    // Version 1 upgrade'leri
                    apply_version_1_upgrades(conn)?;
                }
                _ => {
                    return Err(DatabaseError::MigrationError(
                        format!("Unknown schema version: {}", version)
                    ));
                }
            }

            // Version'ı kaydet
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [version],
            )?;
        }
    }

    Ok(())
}

/// Version 1 için upgrade'ler
fn apply_version_1_upgrades(_conn: &mut Connection) -> MigrationResult {
    // İleride schema değişiklikleri burada yapılacak
    
    // Örnek: Yeni kolon eklemek
    // conn.execute("ALTER TABLE cve_cache ADD COLUMN new_column TEXT", [])?;
    
    // Örnek: Yeni tablo eklemek
    // conn.execute("CREATE TABLE new_table (...)", [])?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_create_cve_cache_table() {
        let mut conn = Connection::open(":memory:").unwrap();
        create_cve_cache_table(&mut conn).unwrap();
        
        // Tablo oluşturuldu mu kontrol et
        let table_exists: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_cache'")
            .unwrap()
            .exists([])
            .unwrap();
        assert!(table_exists);
    }

    #[test]
    fn test_create_scan_history_table() {
        let mut conn = Connection::open(":memory:").unwrap();
        create_scan_history_table(&mut conn).unwrap();
        
        // Tabloların oluşturulduğunu kontrol et
        let history_exists: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
            .unwrap()
            .exists([])
            .unwrap();
        assert!(history_exists);

        let findings_exists: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_findings'")
            .unwrap()
            .exists([])
            .unwrap();
        assert!(findings_exists);
    }

    #[test]
    fn test_create_indexes() {
        let mut conn = Connection::open(":memory:").unwrap();
        create_cve_cache_table(&mut conn).unwrap();
        create_scan_history_table(&mut conn).unwrap();
        create_schedule_logs_table(&mut conn).unwrap();
        create_indexes(&mut conn).unwrap();
        
        // En az bir indeks oluşturuldu mu kontrol et
        let index_count: i32 = conn
            .prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
            .unwrap()
            .query_row([], |row| row.get(0))
            .unwrap();
        assert!(index_count > 0);
    }
}