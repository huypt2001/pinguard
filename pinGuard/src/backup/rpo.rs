use crate::backup::{BackupResult, BackupError, Priority, RPOSettings};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc, Duration};

/// RPO (Recovery Point Objective) manager for backup scheduling and policies
#[derive(Debug)]
pub struct RPOManager {
    policies: HashMap<String, BackupPolicy>,
    schedules: HashMap<String, BackupSchedule>,
    settings: RPOSettings,
    backup_dir: PathBuf,
}

/// Backup policy for RPO management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: Priority,
    pub rpo_minutes: u32,
    pub rto_minutes: u32, // Recovery Time Objective
    pub backup_frequency: BackupFrequency,
    pub retention_policy: RetentionPolicy,
    pub monitoring: MonitoringConfig,
    pub triggers: Vec<BackupTrigger>,
    pub targets: Vec<BackupTarget>,
}

/// Backup frequency configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFrequency {
    pub frequency_type: FrequencyType,
    pub interval_minutes: u32,
    pub cron_expression: Option<String>,
    pub time_windows: Vec<TimeWindow>,
    pub exclude_weekends: bool,
    pub exclude_holidays: bool,
}

/// Types of backup frequency
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FrequencyType {
    Continuous,    // Real-time backups
    Interval,      // Fixed interval
    Scheduled,     // Cron-based
    OnChange,      // Triggered by file changes
    Manual,        // Manual only
    Adaptive,      // Adaptive based on change frequency
}

/// Retention policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub daily_retention_days: u32,
    pub weekly_retention_weeks: u32,
    pub monthly_retention_months: u32,
    pub yearly_retention_years: u32,
    pub max_total_backups: Option<u32>,
    pub max_total_size_gb: Option<u32>,
    pub compress_old_backups: bool,
    pub archive_old_backups: bool,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub alert_on_failure: bool,
    pub alert_on_rpo_breach: bool,
    pub alert_on_rto_breach: bool,
    pub notification_emails: Vec<String>,
    pub webhook_urls: Vec<String>,
    pub slack_channels: Vec<String>,
    pub monitor_disk_space: bool,
    pub min_free_space_gb: u32,
}

/// Backup triggers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupTrigger {
    TimeInterval(u32),                    // Minutes
    FileChange(PathBuf),                  // File path to monitor
    DirectoryChange(PathBuf),             // Directory to monitor
    ServiceStart(String),                 // Service name
    ServiceStop(String),                  // Service name
    SystemEvent(String),                  // System event name
    CustomCommand(String),                // Custom command to check
    CriticalFileAccess(PathBuf),         // Critical file accessed
    SecurityEvent(String),                // Security event type
}

/// Backup targets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupTarget {
    pub name: String,
    pub target_type: TargetType,
    pub paths: Vec<PathBuf>,
    pub exclude_patterns: Vec<String>,
    pub include_patterns: Vec<String>,
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
}

/// Types of backup targets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TargetType {
    FileSystem,
    Database,
    Configuration,
    Application,
    System,
    UserData,
    Logs,
}

/// Time window for backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start_time: String,  // Format: "HH:MM"
    pub end_time: String,    // Format: "HH:MM"
    pub days_of_week: Vec<u8>, // 0-6 (Sunday-Saturday)
    pub timezone: String,
}

/// Backup schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSchedule {
    pub policy_name: String,
    pub next_backup_time: DateTime<Utc>,
    pub last_backup_time: Option<DateTime<Utc>>,
    pub backup_count: u32,
    pub consecutive_failures: u32,
    pub total_failures: u32,
    pub average_duration_seconds: f64,
    pub status: ScheduleStatus,
}

/// Schedule status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScheduleStatus {
    Active,
    Paused,
    Failed,
    Completed,
    Disabled,
}

/// RPO violation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RPOViolation {
    pub policy_name: String,
    pub violation_time: DateTime<Utc>,
    pub expected_rpo_minutes: u32,
    pub actual_gap_minutes: u32,
    pub severity: ViolationSeverity,
    pub description: String,
    pub resolved: bool,
}

/// Severity levels for RPO violations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ViolationSeverity {
    Low,      // Minor breach
    Medium,   // Moderate breach
    High,     // Significant breach
    Critical, // Major breach requiring immediate attention
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            name: "default_rpo".to_string(),
            description: "Default RPO policy".to_string(),
            enabled: true,
            priority: Priority::Medium,
            rpo_minutes: 60,  // 1 hour RPO
            rto_minutes: 30,  // 30 minutes RTO
            backup_frequency: BackupFrequency {
                frequency_type: FrequencyType::Interval,
                interval_minutes: 30,
                cron_expression: None,
                time_windows: Vec::new(),
                exclude_weekends: false,
                exclude_holidays: false,
            },
            retention_policy: RetentionPolicy {
                daily_retention_days: 7,
                weekly_retention_weeks: 4,
                monthly_retention_months: 12,
                yearly_retention_years: 5,
                max_total_backups: Some(100),
                max_total_size_gb: Some(50),
                compress_old_backups: true,
                archive_old_backups: false,
            },
            monitoring: MonitoringConfig {
                alert_on_failure: true,
                alert_on_rpo_breach: true,
                alert_on_rto_breach: true,
                notification_emails: Vec::new(),
                webhook_urls: Vec::new(),
                slack_channels: Vec::new(),
                monitor_disk_space: true,
                min_free_space_gb: 5,
            },
            triggers: vec![
                BackupTrigger::TimeInterval(30),
                BackupTrigger::DirectoryChange(PathBuf::from("/etc")),
            ],
            targets: vec![
                BackupTarget {
                    name: "system_configs".to_string(),
                    target_type: TargetType::Configuration,
                    paths: vec![PathBuf::from("/etc")],
                    exclude_patterns: vec!["*.tmp".to_string(), "*.log".to_string()],
                    include_patterns: vec!["*.conf".to_string(), "*.yaml".to_string()],
                    compression_enabled: true,
                    encryption_enabled: false,
                },
            ],
        }
    }
}

impl RPOManager {
    /// Create a new RPO manager
    pub fn new(backup_dir: PathBuf, settings: RPOSettings) -> BackupResult<Self> {
        fs::create_dir_all(&backup_dir)?;
        
        let manager = Self {
            policies: HashMap::new(),
            schedules: HashMap::new(),
            settings,
            backup_dir,
        };
        
        Ok(manager)
    }
    
    /// Add a backup policy
    pub fn add_policy(&mut self, policy: BackupPolicy) -> BackupResult<()> {
        // Validate policy
        self.validate_policy(&policy)?;
        
        // Create schedule for the policy
        let schedule = BackupSchedule {
            policy_name: policy.name.clone(),
            next_backup_time: self.calculate_next_backup_time(&policy.backup_frequency)?,
            last_backup_time: None,
            backup_count: 0,
            consecutive_failures: 0,
            total_failures: 0,
            average_duration_seconds: 0.0,
            status: if policy.enabled {
                ScheduleStatus::Active
            } else {
                ScheduleStatus::Disabled
            },
        };
        
        self.policies.insert(policy.name.clone(), policy);
        self.schedules.insert(schedule.policy_name.clone(), schedule);
        
        self.save_policies()?;
        
        println!("Added backup policy: {}", self.policies.len());
        
        Ok(())
    }
    
    /// Remove a backup policy
    pub fn remove_policy(&mut self, policy_name: &str) -> BackupResult<()> {
        self.policies.remove(policy_name);
        self.schedules.remove(policy_name);
        self.save_policies()?;
        
        println!("Removed backup policy: {}", policy_name);
        
        Ok(())
    }
    
    /// Check for due backups and return policies that need execution
    pub fn check_due_backups(&mut self) -> BackupResult<Vec<String>> {
        let now = Utc::now();
        let mut due_policies = Vec::new();
        
        // Collect policy names that need updates to avoid borrowing issues
        let policies_to_update: Vec<_> = self.schedules.iter()
            .filter_map(|(policy_name, schedule)| {
                if schedule.status == ScheduleStatus::Active && schedule.next_backup_time <= now {
                    Some(policy_name.clone())
                } else {
                    None
                }
            })
            .collect();
        
        for policy_name in &policies_to_update {
            due_policies.push(policy_name.clone());
            
            // Update next backup time
            if let Some(policy) = self.policies.get(policy_name) {
                let next_time = self.calculate_next_backup_time(&policy.backup_frequency)?;
                if let Some(schedule) = self.schedules.get_mut(policy_name) {
                    schedule.next_backup_time = next_time;
                }
            }
        }
        
        Ok(due_policies)
    }
    
    /// Record backup completion
    pub fn record_backup_completion(
        &mut self,
        policy_name: &str,
        success: bool,
        duration_seconds: f64,
    ) -> BackupResult<()> {
        if let Some(schedule) = self.schedules.get_mut(policy_name) {
            schedule.last_backup_time = Some(Utc::now());
            schedule.backup_count += 1;
            
            if success {
                schedule.consecutive_failures = 0;
                schedule.status = ScheduleStatus::Active;
            } else {
                schedule.consecutive_failures += 1;
                schedule.total_failures += 1;
                
                // Disable policy after too many consecutive failures
                if schedule.consecutive_failures >= 5 {
                    schedule.status = ScheduleStatus::Failed;
                    println!("Policy {} disabled due to consecutive failures", policy_name);
                }
            }
            
            // Update average duration
            let total_duration = schedule.average_duration_seconds * (schedule.backup_count as f64 - 1.0);
            schedule.average_duration_seconds = (total_duration + duration_seconds) / schedule.backup_count as f64;
        }
        
        self.save_schedules()?;
        
        Ok(())
    }
    
    /// Check for RPO violations
    pub fn check_rpo_violations(&self) -> BackupResult<Vec<RPOViolation>> {
        let mut violations = Vec::new();
        let now = Utc::now();
        
        for (policy_name, policy) in &self.policies {
            if let Some(schedule) = self.schedules.get(policy_name) {
                if let Some(last_backup) = schedule.last_backup_time {
                    let gap_minutes = (now - last_backup).num_minutes() as u32;
                    
                    if gap_minutes > policy.rpo_minutes {
                        let severity = match gap_minutes {
                            m if m > policy.rpo_minutes * 3 => ViolationSeverity::Critical,
                            m if m > policy.rpo_minutes * 2 => ViolationSeverity::High,
                            m if m > policy.rpo_minutes + 30 => ViolationSeverity::Medium,
                            _ => ViolationSeverity::Low,
                        };
                        
                        violations.push(RPOViolation {
                            policy_name: policy_name.clone(),
                            violation_time: now,
                            expected_rpo_minutes: policy.rpo_minutes,
                            actual_gap_minutes: gap_minutes,
                            severity,
                            description: format!(
                                "RPO violation: {} minutes gap exceeds {} minutes target",
                                gap_minutes, policy.rpo_minutes
                            ),
                            resolved: false,
                        });
                    }
                }
            }
        }
        
        Ok(violations)
    }
    
    /// Get backup statistics
    pub fn get_rpo_statistics(&self) -> BackupResult<RPOStatistics> {
        let active_policies = self.policies.values().filter(|p| p.enabled).count();
        let total_policies = self.policies.len();
        
        let mut total_backups = 0;
        let mut total_failures = 0;
        let mut average_rpo_minutes = 0.0;
        let mut average_backup_time = 0.0;
        
        for schedule in self.schedules.values() {
            total_backups += schedule.backup_count;
            total_failures += schedule.total_failures;
            average_backup_time += schedule.average_duration_seconds;
        }
        
        if !self.policies.is_empty() {
            average_rpo_minutes = self.policies.values()
                .map(|p| p.rpo_minutes as f64)
                .sum::<f64>() / self.policies.len() as f64;
            
            average_backup_time /= self.schedules.len() as f64;
        }
        
        let success_rate = if total_backups > 0 {
            ((total_backups - total_failures) as f64 / total_backups as f64) * 100.0
        } else {
            0.0
        };
        
        Ok(RPOStatistics {
            active_policies,
            total_policies,
            total_backups,
            total_failures,
            success_rate_percentage: success_rate,
            average_rpo_minutes,
            average_backup_time_seconds: average_backup_time,
            rpo_violations: self.check_rpo_violations()?.len() as u32,
        })
    }
    
    /// Optimize backup schedules based on system usage patterns
    pub fn optimize_schedules(&mut self) -> BackupResult<Vec<String>> {
        let mut optimized_policies = Vec::new();
        
        for (policy_name, policy) in &mut self.policies {
            if let Some(schedule) = self.schedules.get(policy_name) {
                // Check if policy needs optimization
                if schedule.consecutive_failures > 2 || schedule.average_duration_seconds > 300.0 {
                    // Increase backup interval for problematic policies
                    if policy.backup_frequency.interval_minutes < 120 {
                        policy.backup_frequency.interval_minutes += 30;
                        optimized_policies.push(policy_name.clone());
                        
                        println!("Optimized backup interval for policy {}: {} minutes",
                            policy_name, policy.backup_frequency.interval_minutes);
                    }
                }
                
                // Optimize based on change frequency
                if schedule.backup_count > 10 {
                    let avg_changes_per_backup = 1.0; // Would calculate from actual data
                    
                    if avg_changes_per_backup < 0.1 {
                        // Very few changes, reduce frequency
                        if policy.backup_frequency.interval_minutes < 240 {
                            policy.backup_frequency.interval_minutes += 60;
                            optimized_policies.push(policy_name.clone());
                        }
                    } else if avg_changes_per_backup > 10.0 {
                        // Many changes, increase frequency
                        if policy.backup_frequency.interval_minutes > 15 {
                            policy.backup_frequency.interval_minutes -= 15;
                            optimized_policies.push(policy_name.clone());
                        }
                    }
                }
            }
        }
        
        if !optimized_policies.is_empty() {
            self.save_policies()?;
            println!("Optimized {} backup policies", optimized_policies.len());
        }
        
        Ok(optimized_policies)
    }
    
    /// Apply retention policies and cleanup old backups
    pub fn apply_retention_policies(&self) -> BackupResult<RetentionResult> {
        let mut result = RetentionResult {
            policies_processed: 0,
            backups_deleted: 0,
            space_freed_bytes: 0,
            errors: Vec::new(),
        };
        
        for (policy_name, policy) in &self.policies {
            result.policies_processed += 1;
            
            match self.apply_single_retention_policy(policy) {
                Ok((deleted, freed)) => {
                    result.backups_deleted += deleted;
                    result.space_freed_bytes += freed;
                }
                Err(e) => {
                    result.errors.push(format!("Policy {}: {}", policy_name, e));
                }
            }
        }
        
        println!("Retention policies applied: {} backups deleted, {} MB freed",
            result.backups_deleted, result.space_freed_bytes / 1024 / 1024);
        
        Ok(result)
    }
    
    // Private helper methods
    
    fn validate_policy(&self, policy: &BackupPolicy) -> BackupResult<()> {
        if policy.name.is_empty() {
            return Err(BackupError::ConfigError("Policy name cannot be empty".to_string()));
        }
        
        if policy.rpo_minutes == 0 {
            return Err(BackupError::ConfigError("RPO cannot be zero".to_string()));
        }
        
        if policy.backup_frequency.interval_minutes == 0 && 
           policy.backup_frequency.frequency_type == FrequencyType::Interval {
            return Err(BackupError::ConfigError("Interval cannot be zero".to_string()));
        }
        
        Ok(())
    }
    
    fn calculate_next_backup_time(&self, frequency: &BackupFrequency) -> BackupResult<DateTime<Utc>> {
        let now = Utc::now();
        
        match frequency.frequency_type {
            FrequencyType::Interval => {
                Ok(now + Duration::minutes(frequency.interval_minutes as i64))
            }
            FrequencyType::Continuous => {
                Ok(now + Duration::minutes(1)) // Check every minute for continuous
            }
            FrequencyType::Scheduled => {
                // Would parse cron expression here
                Ok(now + Duration::hours(1)) // Simplified
            }
            FrequencyType::OnChange => {
                Ok(now + Duration::minutes(5)) // Check for changes every 5 minutes
            }
            FrequencyType::Manual => {
                Ok(now + Duration::days(365)) // Far in the future
            }
            FrequencyType::Adaptive => {
                // Would calculate based on change patterns
                Ok(now + Duration::minutes(frequency.interval_minutes as i64))
            }
        }
    }
    
    fn apply_single_retention_policy(&self, policy: &BackupPolicy) -> BackupResult<(u32, u64)> {
        let cutoff_date = Utc::now() - Duration::days(policy.retention_policy.daily_retention_days as i64);
        let mut deleted_count = 0;
        let mut freed_bytes = 0;
        
        // This is simplified - in reality, you'd scan backup files and apply retention
        // For now, return dummy values
        Ok((deleted_count, freed_bytes))
    }
    
    fn save_policies(&self) -> BackupResult<()> {
        let policies_file = self.backup_dir.join("rpo_policies.json");
        let content = serde_json::to_string_pretty(&self.policies)?;
        fs::write(policies_file, content)?;
        Ok(())
    }
    
    fn save_schedules(&self) -> BackupResult<()> {
        let schedules_file = self.backup_dir.join("backup_schedules.json");
        let content = serde_json::to_string_pretty(&self.schedules)?;
        fs::write(schedules_file, content)?;
        Ok(())
    }
    
    /// Get policy by name
    pub fn get_policy(&self, name: &str) -> Option<&BackupPolicy> {
        self.policies.get(name)
    }
    
    /// List all policies
    pub fn list_policies(&self) -> Vec<&BackupPolicy> {
        self.policies.values().collect()
    }
    
    /// Get schedule by policy name
    pub fn get_schedule(&self, policy_name: &str) -> Option<&BackupSchedule> {
        self.schedules.get(policy_name)
    }
}

/// RPO statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RPOStatistics {
    pub active_policies: usize,
    pub total_policies: usize,
    pub total_backups: u32,
    pub total_failures: u32,
    pub success_rate_percentage: f64,
    pub average_rpo_minutes: f64,
    pub average_backup_time_seconds: f64,
    pub rpo_violations: u32,
}

/// Retention policy application result
#[derive(Debug, Clone)]
pub struct RetentionResult {
    pub policies_processed: u32,
    pub backups_deleted: u32,
    pub space_freed_bytes: u64,
    pub errors: Vec<String>,
}