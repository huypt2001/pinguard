use reqwest::{Client, header::{HeaderMap, HeaderValue, USER_AGENT}};
use serde_json;
use tokio::time::{sleep, Duration};
use tracing::{info, debug, warn, error};
use chrono::Utc;
use std::collections::HashMap;

use crate::cve::{
    CveApiError, CveApiResult, NvdApiResponse, CveSearchCriteria,
    nvd_to_cve_data
};
use crate::database::cve_cache::CveData;

/// NVD API client
pub struct NvdClient {
    client: Client,
    api_key: Option<String>,
    base_url: String,
    rate_limit_delay: Duration,
    max_retries: u32,
}

impl NvdClient {
    /// NVD API endpoint
    const NVD_API_BASE_URL: &'static str = "https://services.nvd.nist.gov/rest/json";
    
    /// API rate limiting (1 request per 6 seconds for public API)
    const PUBLIC_RATE_LIMIT_DELAY: Duration = Duration::from_secs(6);
    
    /// Faster for API key usage (0.6 seconds)
    const API_KEY_RATE_LIMIT_DELAY: Duration = Duration::from_millis(600);

    /// Create a new NVD client
    pub fn new() -> CveApiResult<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("pinGuard/1.0"));
        headers.insert("Accept", HeaderValue::from_static("application/json"));

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .default_headers(headers)
            .build()?;

        Ok(Self {
            client,
            api_key: None,
            base_url: Self::NVD_API_BASE_URL.to_string(),
            rate_limit_delay: Self::PUBLIC_RATE_LIMIT_DELAY,
            max_retries: 3,
        })
    }

    /// Create NVD client with API key
    pub fn with_api_key(api_key: String) -> CveApiResult<Self> {
        let mut client = Self::new()?;
        client.api_key = Some(api_key);
        client.rate_limit_delay = Self::API_KEY_RATE_LIMIT_DELAY;
        Ok(client)
    }

    /// Customize rate limit delay
    pub fn with_rate_limit(mut self, delay_ms: u64) -> Self {
        self.rate_limit_delay = Duration::from_millis(delay_ms);
        self
    }

    /// Set max retry count
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Get a single CVE
    pub async fn get_cve(&self, cve_id: &str) -> CveApiResult<CveData> {
        info!("🔍 Fetching CVE from NVD: {}", cve_id);

        crate::cve::validate_cve_id(cve_id)?;

        let criteria = CveSearchCriteria::new()
            .with_cve_id(cve_id.to_string())
            .with_pagination(1, 0);

        let response = self.search_cves(criteria).await?;

        if response.vulnerabilities.is_empty() {
            return Err(CveApiError::CveNotFound(cve_id.to_string()));
        }

        let nvd_vuln = &response.vulnerabilities[0];
        let cve_data = nvd_to_cve_data(nvd_vuln)?;

        info!("CVE successfully fetched: {}", cve_id);
        Ok(cve_data)
    }

    /// Get multiple CVEs
    pub async fn get_cves(&self, cve_ids: &[String]) -> CveApiResult<Vec<CveData>> {
        info!("🔍 Fetching {} CVEs in bulk from NVD", cve_ids.len());

        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_cves = Vec::new();

        // Fetch CVEs one by one for rate limiting
        for cve_id in cve_ids {
            match self.get_cve(cve_id).await {
                Ok(cve_data) => {
                    all_cves.push(cve_data);
                }
                Err(CveApiError::CveNotFound(_)) => {
                    warn!("CVE not found: {}", cve_id);
                    // Continue with next CVE
                }
                Err(e) => {
                    error!("Failed to fetch CVE {}: {}", cve_id, e);
                    return Err(e);
                }
            }

            // Rate limiting
            sleep(self.rate_limit_delay).await;
        }

        info!("{} CVEs fetched in bulk", all_cves.len());
        Ok(all_cves)
    }

    /// CVE search
    pub async fn search_cves(&self, criteria: CveSearchCriteria) -> CveApiResult<NvdApiResponse> {
        debug!("Searching CVEs in NVD: {:?}", criteria.cve_id);

        let url = format!("{}/cves/2.0", self.base_url);
        let params = criteria.to_query_params();

        self.make_request(&url, params).await
    }

    /// CVE search by keyword
    pub async fn search_by_keyword(&self, keyword: &str, limit: Option<u32>) -> CveApiResult<Vec<CveData>> {
        info!("Searching CVEs by keyword: {}", keyword);

        let criteria = CveSearchCriteria::new()
            .with_keyword(keyword.to_string())
            .with_pagination(limit.unwrap_or(20), 0);

        let response = self.search_cves(criteria).await?;
        let mut cves = Vec::new();

        for nvd_vuln in response.vulnerabilities {
            match nvd_to_cve_data(&nvd_vuln) {
                Ok(cve_data) => cves.push(cve_data),
                Err(e) => {
                    warn!("CVE conversion error: {}", e);
                    continue;
                }
            }
        }

        info!("{} CVEs found for keyword: {}", cves.len(), keyword);
        Ok(cves)
    }

    /// CVE search by CPE
    pub async fn search_by_cpe(&self, cpe_name: &str, limit: Option<u32>) -> CveApiResult<Vec<CveData>> {
        info!("🔍 Searching CVEs by CPE: {}", cpe_name);

        let criteria = CveSearchCriteria::new()
            .with_cpe_name(cpe_name.to_string())
            .with_pagination(limit.unwrap_or(20), 0);

        let response = self.search_cves(criteria).await?;
        let mut cves = Vec::new();

        for nvd_vuln in response.vulnerabilities {
            match nvd_to_cve_data(&nvd_vuln) {
                Ok(cve_data) => cves.push(cve_data),
                Err(e) => {
                    warn!("CVE conversion error: {}", e);
                    continue;
                }
            }
        }

        info!("{} CVEs found for CPE: {}", cves.len(), cpe_name);
        Ok(cves)
    }

    /// Get CVEs updated in the last N days
    pub async fn get_recent_cves(&self, days: u32, limit: Option<u32>) -> CveApiResult<Vec<CveData>> {
        info!("Fetching CVEs from the last {} days", days);

        let end_date = Utc::now();
        let start_date = end_date - chrono::Duration::days(days as i64);

        let criteria = CveSearchCriteria::new()
            .with_published_date_range(Some(start_date), Some(end_date))
            .with_pagination(limit.unwrap_or(100), 0);

        let response = self.search_cves(criteria).await?;
        let mut cves = Vec::new();

        for nvd_vuln in response.vulnerabilities {
            match nvd_to_cve_data(&nvd_vuln) {
                Ok(cve_data) => cves.push(cve_data),
                Err(e) => {
                    warn!("CVE conversion error: {}", e);
                    continue;
                }
            }
        }

        info!("{} CVEs found for the last {} days", cves.len(), days);
        Ok(cves)
    }

    /// Make request to NVD API
    async fn make_request(&self, url: &str, params: HashMap<String, String>) -> CveApiResult<NvdApiResponse> {
        let mut attempt = 0;

        while attempt < self.max_retries {
            attempt += 1;
            debug!("NVD API request (attempt {}): {}", attempt, url);

            let mut request = self.client.get(url);

            // Add API key to header if available
            if let Some(ref api_key) = self.api_key {
                request = request.header("apiKey", api_key);
            }

            // Add query parameters
            if !params.is_empty() {
                request = request.query(&params);
            }

            let response = match request.send().await {
                Ok(response) => response,
                Err(e) => {
                    if attempt == self.max_retries {
                        return Err(CveApiError::RequestError(e));
                    }
                    warn!("Request error (attempt {}): {}", attempt, e);
                    sleep(Duration::from_secs(attempt as u64 * 2)).await; // Exponential backoff
                    continue;
                }
            };

            let status = response.status();
            debug!("NVD API response status: {}", status);

            if status.is_success() {
                let response_text = response.text().await?;
                
                match serde_json::from_str::<NvdApiResponse>(&response_text) {
                    Ok(nvd_response) => {
                        debug!("NVD API response successfully parsed");
                        
                        // Rate limiting
                        sleep(self.rate_limit_delay).await;
                        
                        return Ok(nvd_response);
                    }
                    Err(e) => {
                        error!("JSON parse error: {}", e);
                        error!("Response text: {}", response_text);
                        return Err(CveApiError::ParseError(e.to_string()));
                    }
                }
            } else if status.as_u16() == 429 {
                // Rate limit exceeded
                warn!("Rate limit exceeded, waiting...");
                sleep(Duration::from_secs(60)).await; // Wait 1 minute
                continue;
            } else if status.as_u16() == 404 {
                return Err(CveApiError::CveNotFound("CVE not found in NVD".to_string()));
            } else {
                let error_text = response.text().await.unwrap_or_default();
                if attempt == self.max_retries {
                    return Err(CveApiError::ApiResponseError(
                        format!("HTTP {}: {}", status, error_text)
                    ));
                }
                warn!("API error (attempt {}): HTTP {} - {}", attempt, status, error_text);
                sleep(Duration::from_secs(attempt as u64 * 2)).await;
            }
        }

        Err(CveApiError::ApiResponseError("Max retries exceeded".to_string()))
    }

    /// Check API status
    pub async fn health_check(&self) -> CveApiResult<NvdHealthStatus> {
        info!("Performing NVD API health check...");

        let start_time = std::time::Instant::now();
        
        // Perform a simple CVE search
        let test_criteria = CveSearchCriteria::new()
            .with_pagination(1, 0);

        match self.search_cves(test_criteria).await {
            Ok(response) => {
                let response_time = start_time.elapsed();
                
                info!("NVD API healthy ({}ms)", response_time.as_millis());
                
                Ok(NvdHealthStatus {
                    is_healthy: true,
                    response_time_ms: response_time.as_millis() as u64,
                    has_api_key: self.api_key.is_some(),
                    rate_limit_delay_ms: self.rate_limit_delay.as_millis() as u64,
                    total_results: response.total_results,
                    error_message: None,
                })
            }
            Err(e) => {
                let response_time = start_time.elapsed();
                
                error!("NVD API unhealthy: {}", e);
                
                Ok(NvdHealthStatus {
                    is_healthy: false,
                    response_time_ms: response_time.as_millis() as u64,
                    has_api_key: self.api_key.is_some(),
                    rate_limit_delay_ms: self.rate_limit_delay.as_millis() as u64,
                    total_results: None,
                    error_message: Some(e.to_string()),
                })
            }
        }
    }
}

/// NVD API health status
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NvdHealthStatus {
    pub is_healthy: bool,
    pub response_time_ms: u64,
    pub has_api_key: bool,
    pub rate_limit_delay_ms: u64,
    pub total_results: Option<i32>,
    pub error_message: Option<String>,
}

impl Default for NvdClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default NVD client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nvd_client_creation() {
        let client = NvdClient::new().unwrap();
        assert!(client.api_key.is_none());
        assert_eq!(client.rate_limit_delay, NvdClient::PUBLIC_RATE_LIMIT_DELAY);
    }

    #[tokio::test]
    async fn test_nvd_client_with_api_key() {
        let client = NvdClient::with_api_key("test-key".to_string()).unwrap();
        assert!(client.api_key.is_some());
        assert_eq!(client.rate_limit_delay, NvdClient::API_KEY_RATE_LIMIT_DELAY);
    }

    #[tokio::test]
    async fn test_search_criteria_to_params() {
        let criteria = CveSearchCriteria::new()
            .with_cve_id("CVE-2023-1234".to_string())
            .with_pagination(50, 0);

        let params = criteria.to_query_params();
        assert_eq!(params.get("cveId"), Some(&"CVE-2023-1234".to_string()));
        assert_eq!(params.get("resultsPerPage"), Some(&"50".to_string()));
        assert_eq!(params.get("startIndex"), Some(&"0".to_string()));
    }

    // Note: Real API tests require an API key and are slow due to rate limiting
    // These tests should be done as integration tests in a separate file
}