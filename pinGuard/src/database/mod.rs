use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, error, info};

pub mod cve_cache;
pub mod migrations;
pub mod scan_history;

/// Database error types
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub enum DatabaseError {
    #[error("SQLite error: {0}")]
    SqliteError(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Migration error: {0}")]
    MigrationError(String),
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Data validation error: {0}")]
    ValidationError(String),
}

pub type DatabaseResult<T> = Result<T, DatabaseError>;

/// Database manager
pub struct DatabaseManager {
    connection: Connection,
    db_path: String,
}

#[allow(dead_code)]
impl DatabaseManager {
    /// Create new database manager
    pub fn new(db_path: &str) -> DatabaseResult<Self> {
        let conn = Connection::open(db_path)?;

        // Enable WAL mode (for performance)
        info!("🔧 Configuring PRAGMA settings...");

        // PRAGMA journal_mode=WAL returns results, so we use query instead of execute
        let _ = conn
            .prepare("PRAGMA journal_mode=WAL")?
            .query_row([], |row| {
                info!("Journal mode: {}", row.get::<_, String>(0)?);
                Ok(())
            });

        conn.execute("PRAGMA foreign_keys=ON", [])?;
        info!("Foreign keys enabled");

        let mut db = Self {
            connection: conn,
            db_path: db_path.to_string(),
        };
        db.run_migrations()?;

        Ok(db)
    }

    /// In-memory database for testing
    #[cfg(test)]
    pub fn new_test() -> DatabaseResult<Self> {
        Self::new(":memory:")
    }

    /// Create database with default path
    pub fn new_default() -> DatabaseResult<Self> {
        Self::new("pinGuard.db")
    }

    /// Run migrations
    pub fn run_migrations(&mut self) -> DatabaseResult<()> {
        info!("Running database migrations...");

        // Create migration table
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Table creation migrations
        type MigrationFn = fn(&mut Connection) -> DatabaseResult<()>;
        let migrations: Vec<(&str, MigrationFn)> = vec![
            ("create_cve_cache_table", |conn| {
                migrations::create_cve_cache_table(conn)
            }),
            ("create_scan_history_table", |conn| {
                migrations::create_scan_history_table(conn)
            }),
            ("create_schedule_logs_table", |conn| {
                migrations::create_schedule_logs_table(conn)
            }),
            ("create_indexes", |conn| migrations::create_indexes(conn)),
        ];

        for (name, migration_fn) in migrations {
            // Check if migration has been applied before
            let applied = self
                .connection
                .prepare("SELECT COUNT(*) FROM migrations WHERE name = ?1")?
                .query_row([name], |row| row.get::<_, i32>(0))?;

            if applied == 0 {
                info!("Applying migration: {}", name);
                match migration_fn(&mut self.connection) {
                    Ok(_) => {
                        // Save the migration
                        self.connection
                            .execute("INSERT INTO migrations (name) VALUES (?1)", [name])?;
                        info!("Migration completed: {}", name);
                    }
                    Err(e) => {
                        error!("Migration '{}' error: {}", name, e);
                        return Err(e);
                    }
                }
            } else {
                debug!("Migration already applied: {}", name);
            }
        }

        info!("All migrations completed");
        Ok(())
    }

    /// Get database connection
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Execute SQL command
    pub fn execute(&self, sql: &str, params: impl rusqlite::Params) -> DatabaseResult<usize> {
        self.connection
            .execute(sql, params)
            .map_err(DatabaseError::from)
    }

    /// Execute SQL with prepared statement
    pub fn execute_prepared(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> DatabaseResult<usize> {
        let mut stmt = self.connection.prepare(sql)?;
        stmt.execute(params).map_err(DatabaseError::from)
    }

    /// Get database path
    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    /// Check database status
    pub fn health_check(&self) -> DatabaseResult<DatabaseHealth> {
        let mut health = DatabaseHealth::default();

        // Basic SQLite functionality test
        let test_query = self.connection.prepare("SELECT 1");
        health.connection_ok = test_query.is_ok();

        if !health.connection_ok {
            return Ok(health);
        }

        // Get table count
        let mut stmt = self.connection.prepare(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )?;
        health.table_count = stmt.query_row([], |row| row.get(0))?;

        // Get CVE cache count
        if let Ok(mut stmt) = self.connection.prepare("SELECT COUNT(*) FROM cve_cache") {
            if let Ok(count) = stmt.query_row([], |row| row.get(0)) {
                health.cve_cache_count = count;
            }
        }

        // Get scan history count
        if let Ok(mut stmt) = self.connection.prepare("SELECT COUNT(*) FROM scan_history") {
            if let Ok(count) = stmt.query_row([], |row| row.get(0)) {
                health.scan_history_count = count;
            }
        }

        // Calculate database size
        if let Ok(metadata) = std::fs::metadata(&self.db_path) {
            health.database_size_bytes = metadata.len();
        }

        health.last_check = Utc::now();
        Ok(health)
    }

    /// Optimize database
    pub fn optimize(&self) -> DatabaseResult<()> {
        info!("Starting database optimization...");

        // VACUUM - clean unused space
        self.connection.execute("VACUUM", [])?;

        // ANALYZE - update query planner statistics
        self.connection.execute("ANALYZE", [])?;

        info!("Database optimization completed");
        Ok(())
    }

    /// Create database backup
    pub fn backup(&self, backup_path: &str) -> DatabaseResult<()> {
        info!("Creating database backup: {}", backup_path);

        if self.db_path == ":memory:" {
            return Err(DatabaseError::ValidationError(
                "Cannot backup in-memory database".to_string(),
            ));
        }

        // Create backup directory
        if let Some(parent) = Path::new(backup_path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                DatabaseError::ConnectionError(format!("Backup directory creation failed: {}", e))
            })?;
        }

        // Simple file copy
        std::fs::copy(&self.db_path, backup_path)
            .map_err(|e| DatabaseError::ConnectionError(format!("Backup failed: {}", e)))?;

        info!("Backup created successfully");
        Ok(())
    }
}

/// Database health status
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DatabaseHealth {
    pub connection_ok: bool,
    pub table_count: i32,
    pub cve_cache_count: i32,
    pub scan_history_count: i32,
    pub database_size_bytes: u64,
    pub last_check: DateTime<Utc>,
}

impl DatabaseHealth {
    pub fn is_healthy(&self) -> bool {
        self.connection_ok && self.table_count > 0
    }

    pub fn database_size_mb(&self) -> f64 {
        self.database_size_bytes as f64 / 1024.0 / 1024.0
    }
}

/// Trait for database connection pool
#[allow(dead_code)]
pub trait DatabaseConnection {
    fn execute_query(&self, query: &str, params: &[&dyn rusqlite::ToSql]) -> DatabaseResult<usize>;
    fn fetch_one<T>(
        &self,
        query: &str,
        params: &[&dyn rusqlite::ToSql],
        mapper: fn(&rusqlite::Row) -> rusqlite::Result<T>,
    ) -> DatabaseResult<Option<T>>;
    fn fetch_all<T>(
        &self,
        query: &str,
        params: &[&dyn rusqlite::ToSql],
        mapper: fn(&rusqlite::Row) -> rusqlite::Result<T>,
    ) -> DatabaseResult<Vec<T>>;
}

impl DatabaseConnection for DatabaseManager {
    fn execute_query(&self, query: &str, params: &[&dyn rusqlite::ToSql]) -> DatabaseResult<usize> {
        Ok(self.connection.execute(query, params)?)
    }

    fn fetch_one<T>(
        &self,
        query: &str,
        params: &[&dyn rusqlite::ToSql],
        mapper: fn(&rusqlite::Row) -> rusqlite::Result<T>,
    ) -> DatabaseResult<Option<T>> {
        let mut stmt = self.connection.prepare(query)?;
        let mut rows = stmt.query_map(params, mapper)?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    fn fetch_all<T>(
        &self,
        query: &str,
        params: &[&dyn rusqlite::ToSql],
        mapper: fn(&rusqlite::Row) -> rusqlite::Result<T>,
    ) -> DatabaseResult<Vec<T>> {
        let mut stmt = self.connection.prepare(query)?;
        let rows = stmt.query_map(params, mapper)?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let db = DatabaseManager::new_test().unwrap();
        let health = db.health_check().unwrap();
        assert!(health.is_healthy());
        assert!(health.table_count > 0);
    }

    #[test]
    fn test_migrations() {
        let db = DatabaseManager::new_test().unwrap();

        // Check if migrations table exists
        let mut stmt = db
            .connection
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='migrations'")
            .unwrap();
        let table_exists: bool = stmt.exists([]).unwrap();
        assert!(table_exists);
    }
}
