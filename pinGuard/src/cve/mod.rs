use crate::database::cve_cache::{CpeMatch, CveData, CveSeverity};
use chrono::{DateTime, Utc};
use reqwest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::error;

pub mod cve_manager;
pub mod nvd_client;

// Re-export için
pub use cve_manager::CveManager;

/// CVE API error types
#[derive(Debug, thiserror::Error)]
pub enum CveApiError {
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("JSON parsing failed: {0}")]
    ParseError(String),
    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Rate limit exceeded. Please wait {0} seconds")]
    RateLimitError(u64),
    #[error("API key required but not provided")]
    ApiKeyRequired,
    #[error("Invalid CVE ID format: {0}")]
    InvalidCveId(String),
    #[error("CVE not found: {0}")]
    CveNotFound(String),
    #[error("API response error: {0}")]
    ApiResponseError(String),
    #[error("Network timeout")]
    TimeoutError,
    #[error("Cache error: {0}")]
    CacheError(String),
}

pub type CveApiResult<T> = Result<T, CveApiError>;

/// NVD API response structures
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdApiResponse {
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: Option<i32>,
    #[serde(rename = "startIndex")]
    pub start_index: Option<i32>,
    #[serde(rename = "totalResults")]
    pub total_results: Option<i32>,
    pub format: Option<String>,
    pub version: Option<String>,
    pub timestamp: Option<String>,
    pub vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdCve {
    pub id: String,
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: Option<String>,
    #[serde(rename = "published")]
    pub published: Option<String>,
    #[serde(rename = "lastModified")]
    pub last_modified: Option<String>,
    #[serde(rename = "vulnStatus")]
    pub vuln_status: Option<String>,
    pub descriptions: Vec<NvdDescription>,
    pub metrics: Option<NvdMetrics>,
    pub weaknesses: Option<Vec<NvdWeakness>>,
    pub configurations: Option<Vec<NvdConfiguration>>,
    pub references: Option<Vec<NvdReference>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    pub cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    pub cvss_metric_v30: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    pub cvss_metric_v2: Option<Vec<NvdCvssMetric>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdCvssMetric {
    pub source: Option<String>,
    pub type_field: Option<String>,
    #[serde(rename = "cvssData")]
    pub cvss_data: Option<NvdCvssData>,
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: Option<f64>,
    #[serde(rename = "impactScore")]
    pub impact_score: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdCvssData {
    pub version: Option<String>,
    #[serde(rename = "vectorString")]
    pub vector_string: Option<String>,
    #[serde(rename = "accessVector")]
    pub access_vector: Option<String>,
    #[serde(rename = "accessComplexity")]
    pub access_complexity: Option<String>,
    pub authentication: Option<String>,
    #[serde(rename = "confidentialityImpact")]
    pub confidentiality_impact: Option<String>,
    #[serde(rename = "integrityImpact")]
    pub integrity_impact: Option<String>,
    #[serde(rename = "availabilityImpact")]
    pub availability_impact: Option<String>,
    #[serde(rename = "baseScore")]
    pub base_score: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdWeakness {
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub weakness_type: Option<String>,
    pub description: Option<Vec<NvdDescription>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdConfiguration {
    pub nodes: Option<Vec<NvdConfigNode>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdConfigNode {
    pub operator: Option<String>,
    pub negate: Option<bool>,
    #[serde(rename = "cpeMatch")]
    pub cpe_match: Option<Vec<NvdCpeMatch>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdCpeMatch {
    pub vulnerable: Option<bool>,
    pub criteria: Option<String>,
    #[serde(rename = "matchCriteriaId")]
    pub match_criteria_id: Option<String>,
    #[serde(rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdReference {
    pub url: Option<String>,
    pub source: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// CVE search criteria
#[derive(Debug, Clone)]
pub struct CveSearchCriteria {
    pub cve_id: Option<String>,
    pub keyword: Option<String>,
    pub published_start_date: Option<DateTime<Utc>>,
    pub published_end_date: Option<DateTime<Utc>>,
    pub last_modified_start_date: Option<DateTime<Utc>>,
    pub last_modified_end_date: Option<DateTime<Utc>>,
    pub cpe_name: Option<String>,
    pub cvss_severity: Option<CveSeverity>,
    pub cvss_score_min: Option<f64>,
    pub cvss_score_max: Option<f64>,
    pub has_cert_alerts: Option<bool>,
    pub has_cert_notes: Option<bool>,
    pub has_kev: Option<bool>,
    pub has_oval: Option<bool>,
    pub is_vulnerable: Option<bool>,
    pub results_per_page: Option<u32>,
    pub start_index: Option<u32>,
}

impl Default for CveSearchCriteria {
    fn default() -> Self {
        Self {
            cve_id: None,
            keyword: None,
            published_start_date: None,
            published_end_date: None,
            last_modified_start_date: None,
            last_modified_end_date: None,
            cpe_name: None,
            cvss_severity: None,
            cvss_score_min: None,
            cvss_score_max: None,
            has_cert_alerts: None,
            has_cert_notes: None,
            has_kev: None,
            has_oval: None,
            is_vulnerable: None,
            results_per_page: Some(20),
            start_index: Some(0),
        }
    }
}

impl CveSearchCriteria {
    /// Create new criteria for builder pattern
    pub fn new() -> Self {
        Self::default()
    }

    /// Search by CVE ID
    pub fn with_cve_id(mut self, cve_id: String) -> Self {
        self.cve_id = Some(cve_id);
        self
    }

    /// Search by keyword
    pub fn with_keyword(mut self, keyword: String) -> Self {
        self.keyword = Some(keyword);
        self
    }

    /// Search by CPE name
    pub fn with_cpe_name(mut self, cpe_name: String) -> Self {
        self.cpe_name = Some(cpe_name);
        self
    }

    /// Search by CVSS severity
    pub fn with_severity(mut self, severity: CveSeverity) -> Self {
        self.cvss_severity = Some(severity);
        self
    }

    /// Search by CVSS score range
    pub fn with_score_range(mut self, min: Option<f64>, max: Option<f64>) -> Self {
        self.cvss_score_min = min;
        self.cvss_score_max = max;
        self
    }

    /// Search by date range (published)
    pub fn with_published_date_range(
        mut self,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> Self {
        self.published_start_date = start;
        self.published_end_date = end;
        self
    }

    /// Page settings
    pub fn with_pagination(mut self, results_per_page: u32, start_index: u32) -> Self {
        self.results_per_page = Some(results_per_page);
        self.start_index = Some(start_index);
        self
    }

    /// Create query parameters
    pub fn to_query_params(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();

        if let Some(ref cve_id) = self.cve_id {
            params.insert("cveId".to_string(), cve_id.clone());
        }

        if let Some(ref keyword) = self.keyword {
            params.insert("keywordSearch".to_string(), keyword.clone());
        }

        if let Some(ref cpe_name) = self.cpe_name {
            params.insert("cpeName".to_string(), cpe_name.clone());
        }

        if let Some(ref severity) = self.cvss_severity {
            params.insert("cvssV3Severity".to_string(), severity.to_string());
        }

        if let Some(score_min) = self.cvss_score_min {
            params.insert("cvssV3ScoreMin".to_string(), score_min.to_string());
        }

        if let Some(score_max) = self.cvss_score_max {
            params.insert("cvssV3ScoreMax".to_string(), score_max.to_string());
        }

        if let Some(date) = self.published_start_date {
            params.insert(
                "pubStartDate".to_string(),
                date.format("%Y-%m-%dT%H:%M:%S%.3f").to_string(),
            );
        }

        if let Some(date) = self.published_end_date {
            params.insert(
                "pubEndDate".to_string(),
                date.format("%Y-%m-%dT%H:%M:%S%.3f").to_string(),
            );
        }

        if let Some(date) = self.last_modified_start_date {
            params.insert(
                "lastModStartDate".to_string(),
                date.format("%Y-%m-%dT%H:%M:%S%.3f").to_string(),
            );
        }

        if let Some(date) = self.last_modified_end_date {
            params.insert(
                "lastModEndDate".to_string(),
                date.format("%Y-%m-%dT%H:%M:%S%.3f").to_string(),
            );
        }

        if let Some(results_per_page) = self.results_per_page {
            params.insert("resultsPerPage".to_string(), results_per_page.to_string());
        }

        if let Some(start_index) = self.start_index {
            params.insert("startIndex".to_string(), start_index.to_string());
        }

        if let Some(has_cert_alerts) = self.has_cert_alerts {
            params.insert("hasCertAlerts".to_string(), has_cert_alerts.to_string());
        }

        if let Some(has_cert_notes) = self.has_cert_notes {
            params.insert("hasCertNotes".to_string(), has_cert_notes.to_string());
        }

        if let Some(has_kev) = self.has_kev {
            params.insert("hasKev".to_string(), has_kev.to_string());
        }

        if let Some(has_oval) = self.has_oval {
            params.insert("hasOval".to_string(), has_oval.to_string());
        }

        if let Some(is_vulnerable) = self.is_vulnerable {
            params.insert("isVulnerable".to_string(), is_vulnerable.to_string());
        }

        params
    }
}

/// Convert NVD API response to CveData
pub fn nvd_to_cve_data(nvd_vuln: &NvdVulnerability) -> CveApiResult<CveData> {
    let cve = &nvd_vuln.cve;

    // Description'ı al (İngilizce tercih et)
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .or_else(|| cve.descriptions.first())
        .map(|d| d.value.clone())
        .unwrap_or_else(|| "No description available".to_string());

    // Severity ve score'u hesapla
    let (severity, score, vector_string) = extract_cvss_info(&cve.metrics);

    // Published ve last modified tarihlerini parse et
    let published_date = parse_nvd_date(&cve.published)?;
    let last_modified = parse_nvd_date(&cve.last_modified)?;

    // Affected packages'i CPE'den çıkar
    let (affected_packages, cpe_matches) = extract_affected_packages(&cve.configurations);

    // References'i çıkar
    let references = cve
        .references
        .as_ref()
        .map(|refs| refs.iter().filter_map(|r| r.url.clone()).collect())
        .unwrap_or_default();

    // Raw NVD data'yı serialize et
    let raw_nvd_data =
        serde_json::to_string(nvd_vuln).map_err(|e| CveApiError::ParseError(e.to_string()))?;

    Ok(CveData {
        cve_id: cve.id.clone(),
        description,
        severity,
        score,
        vector_string,
        published_date,
        last_modified,
        affected_packages,
        affected_versions: vec![], // Version range'leri ayrı bir fonksiyonla işlenecek
        references,
        cpe_matches,
        raw_nvd_data: Some(raw_nvd_data),
    })
}

/// Extract CVSS information
fn extract_cvss_info(metrics: &Option<NvdMetrics>) -> (CveSeverity, Option<f64>, Option<String>) {
    if let Some(metrics) = metrics {
        // CVSS v3.1'i tercih et
        if let Some(ref cvss_v31) = metrics.cvss_metric_v31 {
            if let Some(metric) = cvss_v31.first() {
                let severity = metric
                    .base_severity
                    .as_ref()
                    .and_then(|s| s.parse::<CveSeverity>().ok())
                    .unwrap_or(CveSeverity::None);

                let score = metric.cvss_data.as_ref().and_then(|data| data.base_score);

                let vector = metric
                    .cvss_data
                    .as_ref()
                    .and_then(|data| data.vector_string.clone());

                return (severity, score, vector);
            }
        }

        // CVSS v3.0'ı dene
        if let Some(ref cvss_v30) = metrics.cvss_metric_v30 {
            if let Some(metric) = cvss_v30.first() {
                let severity = metric
                    .base_severity
                    .as_ref()
                    .and_then(|s| s.parse::<CveSeverity>().ok())
                    .unwrap_or(CveSeverity::None);

                let score = metric.cvss_data.as_ref().and_then(|data| data.base_score);

                let vector = metric
                    .cvss_data
                    .as_ref()
                    .and_then(|data| data.vector_string.clone());

                return (severity, score, vector);
            }
        }

        // CVSS v2'yi son çare olarak dene
        if let Some(ref cvss_v2) = metrics.cvss_metric_v2 {
            if let Some(metric) = cvss_v2.first() {
                let score = metric.cvss_data.as_ref().and_then(|data| data.base_score);

                // CVSS v2 için severity'yi score'dan hesapla
                let severity = score
                    .map(|s| {
                        if s >= 9.0 {
                            CveSeverity::Critical
                        } else if s >= 7.0 {
                            CveSeverity::High
                        } else if s >= 4.0 {
                            CveSeverity::Medium
                        } else {
                            CveSeverity::Low
                        }
                    })
                    .unwrap_or(CveSeverity::None);

                let vector = metric
                    .cvss_data
                    .as_ref()
                    .and_then(|data| data.vector_string.clone());

                return (severity, score, vector);
            }
        }
    }

    (CveSeverity::None, None, None)
}

/// Extract affected packages from CPE configuration
fn extract_affected_packages(
    configurations: &Option<Vec<NvdConfiguration>>,
) -> (Vec<String>, Vec<CpeMatch>) {
    let mut packages = Vec::new();
    let mut cpe_matches = Vec::new();

    if let Some(configs) = configurations {
        for config in configs {
            if let Some(ref nodes) = config.nodes {
                for node in nodes {
                    if let Some(ref cpe_match_list) = node.cpe_match {
                        for cpe_match in cpe_match_list {
                            if let Some(ref criteria) = cpe_match.criteria {
                                // CPE'den package name'i çıkar
                                if let Some(package_name) = extract_package_name_from_cpe(criteria)
                                {
                                    if !packages.contains(&package_name) {
                                        packages.push(package_name);
                                    }
                                }

                                // CpeMatch struct'ı oluştur
                                cpe_matches.push(CpeMatch {
                                    cpe23_uri: criteria.clone(),
                                    version_start: cpe_match
                                        .version_start_including
                                        .clone()
                                        .or_else(|| cpe_match.version_start_excluding.clone()),
                                    version_end: cpe_match
                                        .version_end_including
                                        .clone()
                                        .or_else(|| cpe_match.version_end_excluding.clone()),
                                    vulnerable: cpe_match.vulnerable.unwrap_or(false),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    (packages, cpe_matches)
}

/// Extract package name from CPE string
fn extract_package_name_from_cpe(cpe: &str) -> Option<String> {
    // CPE format: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() >= 5 && parts[0] == "cpe" && parts[2] == "a" {
        // Product name'i al (4. index)
        Some(parts[4].to_string())
    } else {
        None
    }
}

/// Convert NVD date string to DateTime
fn parse_nvd_date(date_str: &Option<String>) -> CveApiResult<DateTime<Utc>> {
    match date_str {
        Some(date) => {
            // NVD tarih formatı: 2023-12-06T18:15:08.000Z
            DateTime::parse_from_rfc3339(date)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|_| CveApiError::ParseError("Invalid date format".to_string()))
        }
        None => Ok(Utc::now()), // Default olarak şu anki zaman
    }
}

/// CVE ID format'ını validate et
pub fn validate_cve_id(cve_id: &str) -> CveApiResult<()> {
    // CVE ID format: CVE-YYYY-NNNNN
    let cve_regex = regex::Regex::new(r"^CVE-\d{4}-\d{4,}$")
        .map_err(|_| CveApiError::InvalidCveId("Regex compilation failed".to_string()))?;

    if cve_regex.is_match(cve_id) {
        Ok(())
    } else {
        Err(CveApiError::InvalidCveId(cve_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cve_search_criteria_builder() {
        let criteria = CveSearchCriteria::new()
            .with_cve_id("CVE-2023-1234".to_string())
            .with_severity(CveSeverity::High)
            .with_pagination(50, 0);

        assert_eq!(criteria.cve_id, Some("CVE-2023-1234".to_string()));
        assert_eq!(criteria.cvss_severity, Some(CveSeverity::High));
        assert_eq!(criteria.results_per_page, Some(50));

        let params = criteria.to_query_params();
        assert!(params.contains_key("cveId"));
        assert!(params.contains_key("cvssV3Severity"));
    }

    #[test]
    fn test_validate_cve_id() {
        assert!(validate_cve_id("CVE-2023-1234").is_ok());
        assert!(validate_cve_id("CVE-2021-12345").is_ok());
        assert!(validate_cve_id("CVE-2020-123456").is_ok());

        assert!(validate_cve_id("invalid-id").is_err());
        assert!(validate_cve_id("CVE-23-1234").is_err());
        assert!(validate_cve_id("CVE-2023-123").is_err());
    }

    #[test]
    fn test_extract_package_name_from_cpe() {
        let cpe = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*";
        let package_name = extract_package_name_from_cpe(cpe);
        assert_eq!(package_name, Some("http_server".to_string()));

        let invalid_cpe = "invalid:cpe:string";
        let no_package = extract_package_name_from_cpe(invalid_cpe);
        assert_eq!(no_package, None);
    }
}
