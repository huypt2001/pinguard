use chrono::{DateTime, Duration, Utc};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::cve::{nvd_client::NvdClient, CveApiError, CveApiResult};
use crate::database::{
    cve_cache::{CachedCve, CveCache, CveData},
    DatabaseManager,
};

/// CVE manager - coordinates cache and NVD API
#[allow(dead_code)]
pub struct CveManager {
    nvd_client: NvdClient,
    cve_cache: CveCache,
    cache_ttl: Duration,
    auto_refresh: bool,
    max_cache_size: Option<usize>,
    fallback_enabled: bool,
}

#[allow(dead_code)]
impl CveManager {
    /// Create a new CVE manager
    pub fn new(db: DatabaseManager) -> CveApiResult<Self> {
        let nvd_client = NvdClient::new()?;
        let cve_cache = CveCache::new(db);

        Ok(Self {
            nvd_client,
            cve_cache,
            cache_ttl: Duration::hours(24), // 24-hour cache
            auto_refresh: true,
            max_cache_size: Some(10000), // Max 10K CVE cache
            fallback_enabled: true,
        })
    }

    /// Create a CVE manager with an API key
    pub fn with_api_key(db: DatabaseManager, api_key: String) -> CveApiResult<Self> {
        let nvd_client = NvdClient::with_api_key(api_key)?;
        let cve_cache = CveCache::new(db);

        Ok(Self {
            nvd_client,
            cve_cache,
            cache_ttl: Duration::hours(12), // More frequent refresh with API key
            auto_refresh: true,
            max_cache_size: Some(50000), // Larger cache with API key
            fallback_enabled: true,
        })
    }

    /// Set cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self.cve_cache = self.cve_cache.with_ttl(ttl);
        self
    }

    /// Enable/disable auto-refresh
    pub fn with_auto_refresh(mut self, enabled: bool) -> Self {
        self.auto_refresh = enabled;
        self
    }

    /// Enable/disable fallback
    pub fn with_fallback(mut self, enabled: bool) -> Self {
        self.fallback_enabled = enabled;
        self
    }

    /// Set max cache size
    pub fn with_max_cache_size(mut self, size: usize) -> Self {
        self.max_cache_size = Some(size);
        self
    }

    /// Get a single CVE (cache-first approach)
    pub async fn get_cve(&self, cve_id: &str) -> CveApiResult<CveData> {
        info!("Fetching CVE: {}", cve_id);

        // Check cache first
        match self.cve_cache.get_cve(cve_id) {
            Ok(Some(cached_cve)) => {
                info!("CVE found in cache: {}", cve_id);
                return Ok(cached_cve.data);
            }
            Ok(None) => {
                debug!("CVE not found in cache: {}", cve_id);
            }
            Err(e) => {
                warn!("Cache read error: {}", e);
                if !self.fallback_enabled {
                    return Err(CveApiError::CacheError(e.to_string()));
                }
            }
        }

        // If not in cache, fetch from NVD
        match self.nvd_client.get_cve(cve_id).await {
            Ok(cve_data) => {
                info!("CVE fetched from NVD: {}", cve_id);

                // Save to cache
                if let Err(e) = self.cve_cache.cache_cve(&cve_data) {
                    warn!("Failed to cache CVE: {}", e);
                }

                Ok(cve_data)
            }
            Err(e) => {
                error!("Failed to fetch CVE from NVD: {}", e);

                // Fallback: fetch from expired cache
                if self.fallback_enabled {
                    if let Ok(Some(_cached_cve)) = self.try_fallback_cache(cve_id) {
                        warn!("Fallback to expired cache: {}", cve_id);
                        // return Ok(cached_cve.data); // Optionally return expired data
                    }
                }

                Err(e)
            }
        }
    }

    /// Fetch multiple CVEs (with parallel processing)
    pub async fn get_cves(&self, cve_ids: &[String]) -> CveApiResult<Vec<CveData>> {
        info!("Fetching {} CVEs in bulk", cve_ids.len());

        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let mut missing_cves = Vec::new();

        // Check cache first
        for cve_id in cve_ids {
            match self.cve_cache.get_cve(cve_id) {
                Ok(Some(cached_cve)) => {
                    debug!("Cache hit: {}", cve_id);
                    results.push(cached_cve.data);
                }
                Ok(None) => {
                    debug!("Cache miss: {}", cve_id);
                    missing_cves.push(cve_id.clone());
                }
                Err(e) => {
                    warn!("Cache read error {}: {}", cve_id, e);
                    missing_cves.push(cve_id.clone());
                }
            }
        }

        info!(
            "Found {} CVEs in cache, {} will be fetched from NVD",
            results.len(),
            missing_cves.len()
        );

        // Fetch missing CVEs from NVD
        if !missing_cves.is_empty() {
            match self.nvd_client.get_cves(&missing_cves).await {
                Ok(nvd_cves) => {
                    info!("Fetched {} CVEs from NVD", nvd_cves.len());

                    // Save to cache
                    for cve_data in &nvd_cves {
                        if let Err(e) = self.cve_cache.cache_cve(cve_data) {
                            warn!("Failed to cache CVE {}: {}", cve_data.cve_id, e);
                        }
                    }

                    results.extend(nvd_cves);
                }
                Err(e) => {
                    warn!("Failed to fetch CVEs from NVD: {}", e);

                    // Fallback: fetch from expired cache
                    if self.fallback_enabled {
                        for cve_id in &missing_cves {
                            if let Ok(Some(cached_cve)) = self.try_fallback_cache(cve_id) {
                                warn!("Fallback to expired cache: {}", cve_id);
                                results.push(cached_cve.data);
                            }
                        }
                    }
                }
            }
        }

        info!("Fetched a total of {} CVEs", results.len());
        Ok(results)
    }

    /// Find CVEs for a package
    pub async fn find_cves_for_package(&self, package_name: &str) -> CveApiResult<Vec<CveData>> {
        info!("🔍 Searching for CVEs for package: {}", package_name);

        // First, search in cache
        let cached_cves = match self.cve_cache.find_cves_for_package(package_name) {
            Ok(cves) => {
                info!(
                    "{} CVEs found in cache for package: {}",
                    cves.len(),
                    package_name
                );
                cves.into_iter().map(|cached| cached.data).collect()
            }
            Err(e) => {
                warn!("Cache search error for package: {}", e);
                Vec::new()
            }
        };

        // If enough data is in cache, return it
        if !cached_cves.is_empty() && !self.should_refresh_package_cache(package_name).await {
            return Ok(cached_cves);
        }

        // Otherwise, fetch fresh data from NVD
        match self
            .nvd_client
            .search_by_keyword(package_name, Some(100))
            .await
        {
            Ok(nvd_cves) => {
                info!(
                    "{} CVEs found in NVD for package: {}",
                    nvd_cves.len(),
                    package_name
                );

                // Save to cache
                for cve_data in &nvd_cves {
                    if let Err(e) = self.cve_cache.cache_cve(cve_data) {
                        warn!("Failed to cache CVE {}: {}", cve_data.cve_id, e);
                    }
                }

                // Combine cache and NVD data (deduplicate)
                let mut all_cves = cached_cves;
                for nvd_cve in nvd_cves {
                    if !all_cves
                        .iter()
                        .any(|cached| cached.cve_id == nvd_cve.cve_id)
                    {
                        all_cves.push(nvd_cve);
                    }
                }

                Ok(all_cves)
            }
            Err(e) => {
                error!("Error searching package in NVD: {}", e);

                if self.fallback_enabled && !cached_cves.is_empty() {
                    warn!("Fallback: returning {} CVEs from cache", cached_cves.len());
                    Ok(cached_cves)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Sync recent CVEs and cache them
    pub async fn sync_recent_cves(&self, days: u32) -> CveApiResult<usize> {
        info!("Synchronizing CVEs from the last {} days", days);

        match self.nvd_client.get_recent_cves(days, Some(1000)).await {
            Ok(recent_cves) => {
                info!("Fetched {} recent CVEs from NVD", recent_cves.len());

                let mut cached_count = 0;
                for cve_data in recent_cves {
                    if self.cve_cache.cache_cve(&cve_data).is_ok() {
                        cached_count += 1;
                    }
                }

                info!("{} CVEs added to cache", cached_count);
                Ok(cached_count)
            }
            Err(e) => {
                error!("Error syncing recent CVEs: {}", e);
                Err(e)
            }
        }
    }

    /// CVE enrichment - update an existing CVE with detailed information
    pub async fn enrich_cve(&self, cve_id: &str) -> CveApiResult<CveData> {
        info!("Enriching CVE: {}", cve_id);

        // Fetch fresh data from NVD
        let nvd_cve = self.nvd_client.get_cve(cve_id).await?;

        // Save to cache
        self.cve_cache
            .cache_cve(&nvd_cve)
            .map_err(|e| CveApiError::CacheError(e.to_string()))?;

        info!("CVE enriched: {}", cve_id);
        Ok(nvd_cve)
    }

    /// Batch CVE enrichment
    pub async fn enrich_cves(&self, cve_ids: &[String]) -> CveApiResult<Vec<CveData>> {
        info!("Batch CVE enrichment: {} CVEs", cve_ids.len());

        let mut enriched_cves = Vec::new();

        for cve_id in cve_ids {
            match self.enrich_cve(cve_id).await {
                Ok(cve_data) => enriched_cves.push(cve_data),
                Err(e) => {
                    warn!("CVE enrichment error {}: {}", cve_id, e);
                    // Continue with other CVEs
                }
            }

            // Rate limiting
            sleep(tokio::time::Duration::from_millis(100)).await;
        }

        info!("{} CVEs enriched", enriched_cves.len());
        Ok(enriched_cves)
    }

    /// Cache maintenance
    pub async fn maintain_cache(&self) -> CveApiResult<CacheMaintenanceResult> {
        info!("Starting CVE cache maintenance...");

        let mut result = CacheMaintenanceResult::default();

        // Clean up expired entries
        match self.cve_cache.cleanup_expired() {
            Ok(expired_count) => {
                result.expired_entries_cleaned = expired_count;
                info!("🗑️ Cleaned up {} expired entries", expired_count);
            }
            Err(e) => {
                warn!("Error cleaning up expired entries: {}", e);
            }
        }

        // Cache stats
        match self.cve_cache.get_cache_stats() {
            Ok(stats) => {
                result.total_entries = stats.total_entries;
                result.cache_size_mb = stats.cache_size_mb();

                // Check cache size
                if let Some(max_size) = self.max_cache_size {
                    if stats.total_entries > max_size as i32 {
                        warn!(
                            "Cache size limit exceeded: {} > {}",
                            stats.total_entries, max_size
                        );
                        result.needs_size_reduction = true;
                    }
                }
            }
            Err(e) => {
                warn!("Cache stats error: {}", e);
            }
        }

        // Check if auto refresh is needed
        if self.auto_refresh {
            match self.sync_recent_cves(1).await {
                Ok(synced_count) => {
                    result.synced_recent_cves = synced_count;
                    info!("{} recent CVEs synchronized", synced_count);
                }
                Err(e) => {
                    warn!("Auto refresh error: {}", e);
                }
            }
        }

        info!("Cache maintenance completed");
        Ok(result)
    }

    /// CVE manager health check
    pub async fn health_check(&self) -> CveApiResult<CveManagerHealth> {
        info!("🔍 Performing CVE manager health check...");

        // NVD API health check
        let nvd_health = self.nvd_client.health_check().await?;

        // Cache health check
        let cache_stats = self
            .cve_cache
            .get_cache_stats()
            .map_err(|e| CveApiError::CacheError(e.to_string()))?;

        let health = CveManagerHealth {
            nvd_api_healthy: nvd_health.is_healthy,
            nvd_response_time_ms: nvd_health.response_time_ms,
            cache_healthy: cache_stats.total_entries > 0,
            cache_entries: cache_stats.total_entries,
            cache_hit_rate: cache_stats.hit_rate(),
            cache_size_mb: cache_stats.cache_size_mb(),
            auto_refresh_enabled: self.auto_refresh,
            fallback_enabled: self.fallback_enabled,
            last_check: Utc::now(),
        };

        if health.is_healthy() {
            info!("CVE manager is healthy");
        } else {
            warn!("CVE manager has health issues");
        }

        Ok(health)
    }

    /// Attempt to fallback from expired cache
    fn try_fallback_cache(
        &self,
        cve_id: &str,
    ) -> Result<Option<CachedCve>, crate::database::DatabaseError> {
        // This function attempts to fetch data from cache, bypassing the expire check
        // Normal get_cve performs expire check, this can be used for raw SQL query
        debug!("Attempting fallback cache: {}", cve_id);

        // For now, use normal cache get, expire bypass can be added in the future
        self.cve_cache.get_cve(cve_id)
    }

    /// Check if package cache needs to be refreshed
    async fn should_refresh_package_cache(&self, _package_name: &str) -> bool {
        // This function determines when the cache for a package should be refreshed
        // For now, simple logic: return true if auto_refresh is enabled
        self.auto_refresh
    }
}

/// Cache maintenance result
#[derive(Debug, Default)]
pub struct CacheMaintenanceResult {
    pub expired_entries_cleaned: usize,
    pub total_entries: i32,
    pub cache_size_mb: f64,
    pub needs_size_reduction: bool,
    pub synced_recent_cves: usize,
}

/// CVE manager health status
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CveManagerHealth {
    pub nvd_api_healthy: bool,
    pub nvd_response_time_ms: u64,
    pub cache_healthy: bool,
    pub cache_entries: i32,
    pub cache_hit_rate: f64,
    pub cache_size_mb: f64,
    pub auto_refresh_enabled: bool,
    pub fallback_enabled: bool,
    pub last_check: DateTime<Utc>,
}

impl CveManagerHealth {
    pub fn is_healthy(&self) -> bool {
        self.nvd_api_healthy && self.cache_healthy && self.cache_entries > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseManager;

    #[tokio::test]
    async fn test_cve_manager_creation() {
        let db = DatabaseManager::new_test().unwrap();
        let manager = CveManager::new(db).unwrap();

        assert!(manager.auto_refresh);
        assert!(manager.fallback_enabled);
        assert_eq!(manager.cache_ttl, Duration::hours(24));
    }

    #[test]
    fn test_cve_manager_builder() {
        let db = DatabaseManager::new_test().unwrap();
        let manager = CveManager::new(db)
            .unwrap()
            .with_cache_ttl(Duration::hours(12))
            .with_auto_refresh(false)
            .with_fallback(false)
            .with_max_cache_size(5000);

        assert_eq!(manager.cache_ttl, Duration::hours(12));
        assert!(!manager.auto_refresh);
        assert!(!manager.fallback_enabled);
        assert_eq!(manager.max_cache_size, Some(5000));
    }
}
