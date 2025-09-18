use chrono::{DateTime, Utc, Duration};
use tracing::{info, debug, warn, error};
use tokio::time::sleep;

use crate::cve::{CveApiError, CveApiResult, nvd_client::NvdClient};
use crate::database::{
    DatabaseManager, 
    cve_cache::{CveData, CveCache, CachedCve}
};

/// CVE manager - cache ve NVD API'yi koordine eder
pub struct CveManager {
    nvd_client: NvdClient,
    cve_cache: CveCache,
    cache_ttl: Duration,
    auto_refresh: bool,
    max_cache_size: Option<usize>,
    fallback_enabled: bool,
}

impl CveManager {
    /// Yeni CVE manager oluştur
    pub fn new(db: DatabaseManager) -> CveApiResult<Self> {
        let nvd_client = NvdClient::new()?;
        let cve_cache = CveCache::new(db);

        Ok(Self {
            nvd_client,
            cve_cache,
            cache_ttl: Duration::hours(24), // 24 saat cache
            auto_refresh: true,
            max_cache_size: Some(10000), // Max 10K CVE cache
            fallback_enabled: true,
        })
    }

    /// API key ile CVE manager oluştur
    pub fn with_api_key(db: DatabaseManager, api_key: String) -> CveApiResult<Self> {
        let nvd_client = NvdClient::with_api_key(api_key)?;
        let cve_cache = CveCache::new(db);

        Ok(Self {
            nvd_client,
            cve_cache,
            cache_ttl: Duration::hours(12), // API key ile daha sık refresh
            auto_refresh: true,
            max_cache_size: Some(50000), // API key ile daha büyük cache
            fallback_enabled: true,
        })
    }

    /// Cache TTL'yi ayarla
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self.cve_cache = self.cve_cache.with_ttl(ttl);
        self
    }

    /// Auto refresh'i etkinleştir/devre dışı bırak
    pub fn with_auto_refresh(mut self, enabled: bool) -> Self {
        self.auto_refresh = enabled;
        self
    }

    /// Fallback'i etkinleştir/devre dışı bırak
    pub fn with_fallback(mut self, enabled: bool) -> Self {
        self.fallback_enabled = enabled;
        self
    }

    /// Max cache boyutunu ayarla
    pub fn with_max_cache_size(mut self, size: usize) -> Self {
        self.max_cache_size = Some(size);
        self
    }

    /// Tekil CVE al (cache-first approach)
    pub async fn get_cve(&self, cve_id: &str) -> CveApiResult<CveData> {
        info!("CVE alınıyor: {}", cve_id);

        // Önce cache'ten kontrol et
        match self.cve_cache.get_cve(cve_id) {
            Ok(Some(cached_cve)) => {
                info!("CVE cache'ten bulundu: {}", cve_id);
                return Ok(cached_cve.data);
            }
            Ok(None) => {
                debug!("CVE cache'te bulunamadı: {}", cve_id);
            }
            Err(e) => {
                warn!("Cache okuma hatası: {}", e);
                if !self.fallback_enabled {
                    return Err(CveApiError::CacheError(e.to_string()));
                }
            }
        }

        // Cache'te yoksa NVD'den al
        match self.nvd_client.get_cve(cve_id).await {
            Ok(cve_data) => {
                info!("CVE NVD'den alındı: {}", cve_id);

                // Cache'e kaydet
                if let Err(e) = self.cve_cache.cache_cve(&cve_data) {
                    warn!("CVE cache'lenemedi: {}", e);
                }

                Ok(cve_data)
            }
            Err(e) => {
                error!("NVD'den CVE alınamadı: {}", e);

                // Fallback: expire olmuş cache'ten al
                if self.fallback_enabled {
                    if let Ok(Some(_cached_cve)) = self.try_fallback_cache(cve_id) {
                        warn!("Expire olmuş cache'ten fallback: {}", cve_id);
                        // return Ok(cached_cve.data); // Bu durumda expire olmuş veriyi döndürebiliriz
                    }
                }

                Err(e)
            }
        }
    }

    /// Çoklu CVE al (paralel processing ile)
    pub async fn get_cves(&self, cve_ids: &[String]) -> CveApiResult<Vec<CveData>> {
        info!("{} CVE toplu alınıyor", cve_ids.len());

        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let mut missing_cves = Vec::new();

        // Önce cache'ten kontrol et
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
                    warn!("Cache okuma hatası {}: {}", cve_id, e);
                    missing_cves.push(cve_id.clone());
                }
            }
        }

        info!("Cache'ten {} CVE bulundu, {} CVE NVD'den alınacak", 
              results.len(), missing_cves.len());

        // Missing CVE'leri NVD'den al
        if !missing_cves.is_empty() {
            match self.nvd_client.get_cves(&missing_cves).await {
                Ok(nvd_cves) => {
                    info!("NVD'den {} CVE alındı", nvd_cves.len());

                    // Cache'e kaydet
                    for cve_data in &nvd_cves {
                        if let Err(e) = self.cve_cache.cache_cve(cve_data) {
                            warn!("CVE cache'lenemedi {}: {}", cve_data.cve_id, e);
                        }
                    }

                    results.extend(nvd_cves);
                }
                Err(e) => {
                    warn!("NVD'den CVE'ler alınamadı: {}", e);

                    // Fallback: expire olmuş cache'lerden al
                    if self.fallback_enabled {
                        for cve_id in &missing_cves {
                            if let Ok(Some(cached_cve)) = self.try_fallback_cache(cve_id) {
                                warn!("Expire olmuş cache'ten fallback: {}", cve_id);
                                results.push(cached_cve.data);
                            }
                        }
                    }
                }
            }
        }

        info!("Toplam {} CVE alındı", results.len());
        Ok(results)
    }

    /// Package için CVE'leri bul
    pub async fn find_cves_for_package(&self, package_name: &str) -> CveApiResult<Vec<CveData>> {
        info!("🔍 Package için CVE aranıyor: {}", package_name);

        // Önce cache'ten ara
        let cached_cves = match self.cve_cache.find_cves_for_package(package_name) {
            Ok(cves) => {
                info!("Cache'te {} CVE bulundu package için: {}", cves.len(), package_name);
                cves.into_iter().map(|cached| cached.data).collect()
            }
            Err(e) => {
                warn!("Cache'te package arama hatası: {}", e);
                Vec::new()
            }
        };

        // Cache'te yeterli veri varsa döndür
        if !cached_cves.is_empty() && !self.should_refresh_package_cache(package_name).await {
            return Ok(cached_cves);
        }

        // NVD'den fresh data al
        match self.nvd_client.search_by_keyword(package_name, Some(100)).await {
            Ok(nvd_cves) => {
                info!("NVD'den {} CVE bulundu package için: {}", nvd_cves.len(), package_name);

                // Cache'e kaydet
                for cve_data in &nvd_cves {
                    if let Err(e) = self.cve_cache.cache_cve(cve_data) {
                        warn!("CVE cache'lenemedi {}: {}", cve_data.cve_id, e);
                    }
                }

                // Cache ile NVD verilerini birleştir (deduplicate)
                let mut all_cves = cached_cves;
                for nvd_cve in nvd_cves {
                    if !all_cves.iter().any(|cached| cached.cve_id == nvd_cve.cve_id) {
                        all_cves.push(nvd_cve);
                    }
                }

                Ok(all_cves)
            }
            Err(e) => {
                error!("NVD'den package arama hatası: {}", e);

                if self.fallback_enabled && !cached_cves.is_empty() {
                    warn!("Fallback: Cache'teki {} CVE döndürülüyor", cached_cves.len());
                    Ok(cached_cves)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Recent CVE'leri al ve cache'le
    pub async fn sync_recent_cves(&self, days: u32) -> CveApiResult<usize> {
        info!("Son {} gün içindeki CVE'ler senkronize ediliyor", days);

        match self.nvd_client.get_recent_cves(days, Some(1000)).await {
            Ok(recent_cves) => {
                info!("NVD'den {} recent CVE alındı", recent_cves.len());

                let mut cached_count = 0;
                for cve_data in recent_cves {
                    if let Ok(_) = self.cve_cache.cache_cve(&cve_data) {
                        cached_count += 1;
                    }
                }

                info!("{} CVE cache'e eklendi", cached_count);
                Ok(cached_count)
            }
            Err(e) => {
                error!("Recent CVE sync hatası: {}", e);
                Err(e)
            }
        }
    }

    /// CVE enrichment - var olan CVE'yi detaylı bilgilerle güncelle
    pub async fn enrich_cve(&self, cve_id: &str) -> CveApiResult<CveData> {
        info!("CVE enrichment: {}", cve_id);

        // NVD'den fresh data al
        let nvd_cve = self.nvd_client.get_cve(cve_id).await?;
        
        // Cache'e kaydet
        self.cve_cache.cache_cve(&nvd_cve)
            .map_err(|e| CveApiError::CacheError(e.to_string()))?;

        info!("CVE enriched: {}", cve_id);
        Ok(nvd_cve)
    }

    /// Batch CVE enrichment
    pub async fn enrich_cves(&self, cve_ids: &[String]) -> CveApiResult<Vec<CveData>> {
        info!("Batch CVE enrichment: {} CVE", cve_ids.len());

        let mut enriched_cves = Vec::new();

        for cve_id in cve_ids {
            match self.enrich_cve(cve_id).await {
                Ok(cve_data) => enriched_cves.push(cve_data),
                Err(e) => {
                    warn!("CVE enrichment hatası {}: {}", cve_id, e);
                    // Continue with other CVEs
                }
            }

            // Rate limiting
            sleep(tokio::time::Duration::from_millis(100)).await;
        }

        info!("{} CVE enriched", enriched_cves.len());
        Ok(enriched_cves)
    }

    /// Cache maintenance
    pub async fn maintain_cache(&self) -> CveApiResult<CacheMaintenanceResult> {
        info!("CVE cache maintenance başlatılıyor...");

        let mut result = CacheMaintenanceResult::default();

        // Expire olmuş girişleri temizle
        match self.cve_cache.cleanup_expired() {
            Ok(expired_count) => {
                result.expired_entries_cleaned = expired_count;
                info!("🗑️ {} expire olmuş giriş temizlendi", expired_count);
            }
            Err(e) => {
                warn!("Expire cleanup hatası: {}", e);
            }
        }

        // Cache stats
        match self.cve_cache.get_cache_stats() {
            Ok(stats) => {
                result.total_entries = stats.total_entries;
                result.cache_size_mb = stats.cache_size_mb();
                
                // Cache boyutu kontrolü
                if let Some(max_size) = self.max_cache_size {
                    if stats.total_entries > max_size as i32 {
                        warn!("Cache boyutu limit aştı: {} > {}", stats.total_entries, max_size);
                        result.needs_size_reduction = true;
                    }
                }
            }
            Err(e) => {
                warn!("Cache stats hatası: {}", e);
            }
        }

        // Auto refresh gerekli mi kontrol et
        if self.auto_refresh {
            match self.sync_recent_cves(1).await {
                Ok(synced_count) => {
                    result.synced_recent_cves = synced_count;
                    info!("{} recent CVE senkronize edildi", synced_count);
                }
                Err(e) => {
                    warn!("Auto refresh hatası: {}", e);
                }
            }
        }

        info!("Cache maintenance tamamlandı");
        Ok(result)
    }

    /// CVE manager health check
    pub async fn health_check(&self) -> CveApiResult<CveManagerHealth> {
        info!("🔍 CVE manager health check yapılıyor...");

        // NVD API health check
        let nvd_health = self.nvd_client.health_check().await?;

        // Cache health check
        let cache_stats = self.cve_cache.get_cache_stats()
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
            info!("CVE manager sağlıklı");
        } else {
            warn!("CVE manager sağlık sorunları tespit edildi");
        }

        Ok(health)
    }

    /// Expire olmuş cache'ten fallback deneme
    fn try_fallback_cache(&self, cve_id: &str) -> Result<Option<CachedCve>, crate::database::DatabaseError> {
        // Bu fonksiyon expire check'i bypass ederek cache'ten veri almaya çalışır
        // Normal get_cve expire check yapar, burada ham SQL query ile alabilir
        debug!("Fallback cache denemesi: {}", cve_id);
        
        // Şimdilik normal cache get'i kullan, gelecekte expire bypass eklenebilir
        self.cve_cache.get_cve(cve_id)
    }

    /// Package cache'inin refresh edilmesi gerekip gerekmediğini kontrol et
    async fn should_refresh_package_cache(&self, _package_name: &str) -> bool {
        // Bu fonksiyon package için cache'in ne zaman refresh edilmesi gerektiğini belirler
        // Şimdilik basit mantık: auto_refresh etkinse true döndür
        self.auto_refresh
    }
}

/// Cache maintenance sonucu
#[derive(Debug, Default)]
pub struct CacheMaintenanceResult {
    pub expired_entries_cleaned: usize,
    pub total_entries: i32,
    pub cache_size_mb: f64,
    pub needs_size_reduction: bool,
    pub synced_recent_cves: usize,
}

/// CVE manager sağlık durumu
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
        let manager = CveManager::new(db).unwrap()
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