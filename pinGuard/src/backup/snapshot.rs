use crate::backup::{BackupResult, BackupError, BackupMetadata, BackupType, FileChange, ChangeType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

/// System snapshot for capturing complete system state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub metadata: BackupMetadata,
    pub file_states: HashMap<PathBuf, FileState>,
    pub service_states: HashMap<String, ServiceState>,
    pub package_states: HashMap<String, PackageState>,
    pub network_config: NetworkConfig,
    pub user_accounts: Vec<UserAccount>,
    pub security_settings: SecuritySettings,
    pub kernel_info: KernelInfo,
    pub created_at: DateTime<Utc>,
}

/// Types of snapshots
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SnapshotType {
    PreChange,
    PostChange,
    Scheduled,
    Manual,
    Emergency,
}

/// File state information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileState {
    pub path: PathBuf,
    pub size: u64,
    pub permissions: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub modified_time: DateTime<Utc>,
    pub checksum: String,
    pub content_backup: Option<Vec<u8>>,
    pub is_symlink: bool,
    pub link_target: Option<PathBuf>,
}

/// Service state information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceState {
    pub name: String,
    pub enabled: bool,
    pub active: bool,
    pub status: String,
    pub pid: Option<u32>,
    pub memory_usage: Option<u64>,
    pub cpu_usage: Option<f64>,
}

/// Package state information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageState {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub installed: bool,
    pub description: String,
    pub dependencies: Vec<String>,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub interfaces: Vec<NetworkInterface>,
    pub routes: Vec<NetworkRoute>,
    pub dns_servers: Vec<String>,
    pub firewall_rules: Vec<FirewallRule>,
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: String,
    pub mtu: u32,
    pub state: String,
}

/// Network route information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRoute {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: u32,
}

/// Firewall rule information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub chain: String,
    pub target: String,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub port: Option<String>,
}

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home_dir: PathBuf,
    pub shell: String,
    pub groups: Vec<String>,
    pub last_login: Option<DateTime<Utc>>,
    pub password_hash: Option<String>,
}

/// Security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub selinux_status: String,
    pub apparmor_status: String,
    pub sudo_rules: Vec<String>,
    pub ssh_config: HashMap<String, String>,
    pub pam_config: Vec<String>,
    pub auditd_rules: Vec<String>,
}

/// Kernel information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelInfo {
    pub version: String,
    pub release: String,
    pub architecture: String,
    pub modules: Vec<String>,
    pub parameters: HashMap<String, String>,
}

impl SystemSnapshot {
    /// Create a new system snapshot
    pub fn create(snapshot_type: SnapshotType, description: String, include_paths: &[PathBuf]) -> BackupResult<Self> {
        let created_at = Utc::now();
        let id = format!("snapshot_{}", created_at.timestamp());
        
        println!("Creating system snapshot: {}", description);
        
        // Capture file states
        let file_states = Self::capture_file_states(include_paths)?;
        
        // Capture service states
        let service_states = Self::capture_service_states()?;
        
        // Capture package states
        let package_states = Self::capture_package_states()?;
        
        // Capture network configuration
        let network_config = Self::capture_network_config()?;
        
        // Capture user accounts
        let user_accounts = Self::capture_user_accounts()?;
        
        // Capture security settings
        let security_settings = Self::capture_security_settings()?;
        
        // Capture kernel information
        let kernel_info = Self::capture_kernel_info()?;
        
        let total_size = Self::calculate_snapshot_size(&file_states);
        
        let metadata = BackupMetadata {
            id: id.clone(),
            created_at,
            backup_type: BackupType::Snapshot,
            description,
            size_bytes: total_size,
            checksum: String::new(), // Will be calculated when saved
            version: env!("CARGO_PKG_VERSION").to_string(),
            tags: vec![format!("type:{:?}", snapshot_type)],
            files_included: include_paths.to_vec(),
            compression_ratio: 1.0,
            pre_change_snapshot: matches!(snapshot_type, SnapshotType::PreChange),
        };
        
        let snapshot = SystemSnapshot {
            metadata,
            file_states,
            service_states,
            package_states,
            network_config,
            user_accounts,
            security_settings,
            kernel_info,
            created_at,
        };
        
        println!("System snapshot created successfully with {} files", snapshot.file_states.len());
        
        Ok(snapshot)
    }
    
    /// Capture file states for specified paths
    fn capture_file_states(include_paths: &[PathBuf]) -> BackupResult<HashMap<PathBuf, FileState>> {
        let mut file_states = HashMap::new();
        
        for path in include_paths {
            if path.exists() {
                Self::walk_directory(path, &mut file_states)?;
            }
        }
        
        Ok(file_states)
    }
    
    /// Recursively walk directory and capture file states
    fn walk_directory(dir: &Path, file_states: &mut HashMap<PathBuf, FileState>) -> BackupResult<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_dir() {
                    Self::walk_directory(&path, file_states)?;
                } else {
                    let file_state = Self::capture_file_state(&path)?;
                    file_states.insert(path, file_state);
                }
            }
        } else {
            let file_state = Self::capture_file_state(dir)?;
            file_states.insert(dir.to_path_buf(), file_state);
        }
        
        Ok(())
    }
    
    /// Capture state of a single file
    fn capture_file_state(path: &Path) -> BackupResult<FileState> {
        let metadata = fs::metadata(path)?;
        let modified_time = DateTime::from(metadata.modified()?);
        
        let mut hasher = Sha256::new();
        let mut content_backup = None;
        
        if metadata.is_file() && metadata.len() < 1024 * 1024 { // Only backup files < 1MB
            let mut file = File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            hasher.update(&buffer);
            content_backup = Some(buffer);
        } else if metadata.is_file() {
            let mut file = File::open(path)?;
            std::io::copy(&mut file, &mut hasher)?;
        }
        
        let checksum = format!("{:x}", hasher.finalize());
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            
            Ok(FileState {
                path: path.to_path_buf(),
                size: metadata.len(),
                permissions: metadata.mode(),
                owner_uid: metadata.uid(),
                owner_gid: metadata.gid(),
                modified_time,
                checksum,
                content_backup,
                is_symlink: metadata.file_type().is_symlink(),
                link_target: if metadata.file_type().is_symlink() {
                    fs::read_link(path).ok()
                } else {
                    None
                },
            })
        }
        
        #[cfg(not(unix))]
        {
            Ok(FileState {
                path: path.to_path_buf(),
                size: metadata.len(),
                permissions: 0o644,
                owner_uid: 0,
                owner_gid: 0,
                modified_time,
                checksum,
                content_backup,
                is_symlink: false,
                link_target: None,
            })
        }
    }
    
    /// Capture service states using systemctl
    fn capture_service_states() -> BackupResult<HashMap<String, ServiceState>> {
        let mut service_states = HashMap::new();
        
        // Get list of all services
        let output = Command::new("systemctl")
            .args(&["list-units", "--type=service", "--all", "--no-pager", "--plain"])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to list services: {}", e)))?;
        
        if !output.status.success() {
            return Ok(service_states); // Continue without services if systemctl fails
        }
        
        let services_list = String::from_utf8_lossy(&output.stdout);
        
        for line in services_list.lines().skip(1) { // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let service_name = parts[0].replace(".service", "");
                
                if let Ok(service_state) = Self::capture_service_state(&service_name) {
                    service_states.insert(service_name, service_state);
                }
            }
        }
        
        Ok(service_states)
    }
    
    /// Capture state of a single service
    fn capture_service_state(service_name: &str) -> BackupResult<ServiceState> {
        let status_output = Command::new("systemctl")
            .args(&["is-active", service_name])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to get service status: {}", e)))?;
        
        let enabled_output = Command::new("systemctl")
            .args(&["is-enabled", service_name])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to get service enabled status: {}", e)))?;
        
        let active = String::from_utf8_lossy(&status_output.stdout).trim() == "active";
        let enabled = String::from_utf8_lossy(&enabled_output.stdout).trim() == "enabled";
        let status = String::from_utf8_lossy(&status_output.stdout).trim().to_string();
        
        Ok(ServiceState {
            name: service_name.to_string(),
            enabled,
            active,
            status,
            pid: None, // Could be enhanced to capture PID
            memory_usage: None,
            cpu_usage: None,
        })
    }
    
    /// Capture package states
    fn capture_package_states() -> BackupResult<HashMap<String, PackageState>> {
        let mut package_states = HashMap::new();
        
        // Try different package managers
        if let Ok(packages) = Self::capture_dpkg_packages() {
            package_states.extend(packages);
        } else if let Ok(packages) = Self::capture_rpm_packages() {
            package_states.extend(packages);
        }
        
        Ok(package_states)
    }
    
    /// Capture packages using dpkg (Debian/Ubuntu)
    fn capture_dpkg_packages() -> BackupResult<HashMap<String, PackageState>> {
        let output = Command::new("dpkg-query")
            .args(&["-W", "-f=${Package}\t${Version}\t${Architecture}\t${Status}\t${Description}\n"])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to query dpkg: {}", e)))?;
        
        if !output.status.success() {
            return Err(BackupError::SnapshotError("dpkg query failed".to_string()));
        }
        
        let mut packages = HashMap::new();
        let packages_list = String::from_utf8_lossy(&output.stdout);
        
        for line in packages_list.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 5 {
                let package_state = PackageState {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: parts[2].to_string(),
                    installed: parts[3].contains("installed"),
                    description: parts[4].to_string(),
                    dependencies: Vec::new(), // Could be enhanced
                };
                
                packages.insert(parts[0].to_string(), package_state);
            }
        }
        
        Ok(packages)
    }
    
    /// Capture packages using rpm (RedHat/CentOS/Fedora)
    fn capture_rpm_packages() -> BackupResult<HashMap<String, PackageState>> {
        let output = Command::new("rpm")
            .args(&["-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{ARCH}\tinstalled\t%{SUMMARY}\n"])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to query rpm: {}", e)))?;
        
        if !output.status.success() {
            return Err(BackupError::SnapshotError("rpm query failed".to_string()));
        }
        
        let mut packages = HashMap::new();
        let packages_list = String::from_utf8_lossy(&output.stdout);
        
        for line in packages_list.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 5 {
                let package_state = PackageState {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: parts[2].to_string(),
                    installed: true,
                    description: parts[4].to_string(),
                    dependencies: Vec::new(),
                };
                
                packages.insert(parts[0].to_string(), package_state);
            }
        }
        
        Ok(packages)
    }
    
    /// Capture network configuration
    fn capture_network_config() -> BackupResult<NetworkConfig> {
        Ok(NetworkConfig {
            interfaces: Self::capture_network_interfaces()?,
            routes: Self::capture_network_routes()?,
            dns_servers: Self::capture_dns_servers()?,
            firewall_rules: Self::capture_firewall_rules()?,
        })
    }
    
    /// Capture network interfaces
    fn capture_network_interfaces() -> BackupResult<Vec<NetworkInterface>> {
        let mut interfaces = Vec::new();
        
        let output = Command::new("ip")
            .args(&["addr", "show"])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to get network interfaces: {}", e)))?;
        
        if output.status.success() {
            // Parse ip addr output (simplified)
            let output_str = String::from_utf8_lossy(&output.stdout);
            // This is a simplified parser - could be enhanced
            for line in output_str.lines() {
                if line.contains("mtu") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 1 {
                        let name = parts[1].trim_end_matches(':').to_string();
                        interfaces.push(NetworkInterface {
                            name,
                            ip_addresses: Vec::new(),
                            mac_address: String::new(),
                            mtu: 1500,
                            state: "up".to_string(),
                        });
                    }
                }
            }
        }
        
        Ok(interfaces)
    }
    
    /// Capture network routes
    fn capture_network_routes() -> BackupResult<Vec<NetworkRoute>> {
        let mut routes = Vec::new();
        
        let output = Command::new("ip")
            .args(&["route", "show"])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to get routes: {}", e)))?;
        
        if output.status.success() {
            // Parse route output (simplified)
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    routes.push(NetworkRoute {
                        destination: parts[0].to_string(),
                        gateway: parts.get(2).unwrap_or(&"").to_string(),
                        interface: parts.last().unwrap_or(&"").to_string(),
                        metric: 0,
                    });
                }
            }
        }
        
        Ok(routes)
    }
    
    /// Capture DNS servers
    fn capture_dns_servers() -> BackupResult<Vec<String>> {
        let mut dns_servers = Vec::new();
        
        if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                if line.starts_with("nameserver") {
                    if let Some(server) = line.split_whitespace().nth(1) {
                        dns_servers.push(server.to_string());
                    }
                }
            }
        }
        
        Ok(dns_servers)
    }
    
    /// Capture firewall rules
    fn capture_firewall_rules() -> BackupResult<Vec<FirewallRule>> {
        let mut rules = Vec::new();
        
        // Try iptables first
        if let Ok(output) = Command::new("iptables").args(&["-L", "-n"]).output() {
            if output.status.success() {
                // Parse iptables output (simplified)
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if !line.starts_with("Chain") && !line.starts_with("target") && !line.is_empty() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            rules.push(FirewallRule {
                                chain: "INPUT".to_string(), // Simplified
                                target: parts[0].to_string(),
                                protocol: parts.get(1).unwrap_or(&"").to_string(),
                                source: parts.get(2).unwrap_or(&"").to_string(),
                                destination: parts.get(3).unwrap_or(&"").to_string(),
                                port: None,
                            });
                        }
                    }
                }
            }
        }
        
        Ok(rules)
    }
    
    /// Capture user accounts
    fn capture_user_accounts() -> BackupResult<Vec<UserAccount>> {
        let mut accounts = Vec::new();
        
        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 7 {
                    let uid = parts[2].parse().unwrap_or(0);
                    let gid = parts[3].parse().unwrap_or(0);
                    
                    accounts.push(UserAccount {
                        username: parts[0].to_string(),
                        uid,
                        gid,
                        home_dir: PathBuf::from(parts[5]),
                        shell: parts[6].to_string(),
                        groups: Vec::new(), // Could be enhanced
                        last_login: None,
                        password_hash: None, // Security - don't include passwords
                    });
                }
            }
        }
        
        Ok(accounts)
    }
    
    /// Capture security settings
    fn capture_security_settings() -> BackupResult<SecuritySettings> {
        let selinux_status = Self::get_selinux_status();
        let apparmor_status = Self::get_apparmor_status();
        let sudo_rules = Self::get_sudo_rules();
        let ssh_config = Self::get_ssh_config();
        let pam_config = Self::get_pam_config();
        let auditd_rules = Self::get_auditd_rules();
        
        Ok(SecuritySettings {
            selinux_status,
            apparmor_status,
            sudo_rules,
            ssh_config,
            pam_config,
            auditd_rules,
        })
    }
    
    /// Get SELinux status
    fn get_selinux_status() -> String {
        Command::new("getenforce")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }
    
    /// Get AppArmor status
    fn get_apparmor_status() -> String {
        Command::new("aa-status")
            .output()
            .map(|output| if output.status.success() { "Enabled" } else { "Disabled" }.to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }
    
    /// Get sudo rules
    fn get_sudo_rules() -> Vec<String> {
        fs::read_to_string("/etc/sudoers")
            .map(|content| content.lines().map(|line| line.to_string()).collect())
            .unwrap_or_default()
    }
    
    /// Get SSH configuration
    fn get_ssh_config() -> HashMap<String, String> {
        let mut config = HashMap::new();
        
        if let Ok(content) = fs::read_to_string("/etc/ssh/sshd_config") {
            for line in content.lines() {
                if !line.starts_with('#') && line.contains(' ') {
                    let parts: Vec<&str> = line.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        config.insert(parts[0].to_string(), parts[1].to_string());
                    }
                }
            }
        }
        
        config
    }
    
    /// Get PAM configuration
    fn get_pam_config() -> Vec<String> {
        let mut config = Vec::new();
        
        if let Ok(entries) = fs::read_dir("/etc/pam.d") {
            for entry in entries.flatten() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    config.extend(content.lines().map(|line| line.to_string()));
                }
            }
        }
        
        config
    }
    
    /// Get auditd rules
    fn get_auditd_rules() -> Vec<String> {
        fs::read_to_string("/etc/audit/rules.d/audit.rules")
            .map(|content| content.lines().map(|line| line.to_string()).collect())
            .unwrap_or_default()
    }
    
    /// Capture kernel information
    fn capture_kernel_info() -> BackupResult<KernelInfo> {
        let version_output = Command::new("uname")
            .args(&["-r"])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to get kernel version: {}", e)))?;
        
        let release_output = Command::new("uname")
            .args(&["-a"])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to get kernel release: {}", e)))?;
        
        let arch_output = Command::new("uname")
            .args(&["-m"])
            .output()
            .map_err(|e| BackupError::SnapshotError(format!("Failed to get architecture: {}", e)))?;
        
        let version = String::from_utf8_lossy(&version_output.stdout).trim().to_string();
        let release = String::from_utf8_lossy(&release_output.stdout).trim().to_string();
        let architecture = String::from_utf8_lossy(&arch_output.stdout).trim().to_string();
        
        let modules = Self::get_loaded_modules();
        let parameters = Self::get_kernel_parameters();
        
        Ok(KernelInfo {
            version,
            release,
            architecture,
            modules,
            parameters,
        })
    }
    
    /// Get loaded kernel modules
    fn get_loaded_modules() -> Vec<String> {
        fs::read_to_string("/proc/modules")
            .map(|content| {
                content.lines()
                    .map(|line| line.split_whitespace().next().unwrap_or("").to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Get kernel parameters
    fn get_kernel_parameters() -> HashMap<String, String> {
        let mut params = HashMap::new();
        
        if let Ok(content) = fs::read_to_string("/proc/cmdline") {
            for param in content.split_whitespace() {
                if let Some((key, value)) = param.split_once('=') {
                    params.insert(key.to_string(), value.to_string());
                } else {
                    params.insert(param.to_string(), "true".to_string());
                }
            }
        }
        
        params
    }
    
    /// Calculate total size of snapshot
    fn calculate_snapshot_size(file_states: &HashMap<PathBuf, FileState>) -> u64 {
        file_states.values().map(|state| state.size).sum()
    }
    
    /// Save snapshot to file
    pub fn save(&mut self, backup_dir: &Path, compress: bool) -> BackupResult<PathBuf> {
        let filename = format!("{}.snapshot", self.metadata.id);
        let mut file_path = backup_dir.join(&filename);
        
        if compress {
            file_path.set_extension("snapshot.gz");
        }
        
        // Ensure backup directory exists
        fs::create_dir_all(backup_dir)?;
        
        let serialized = serde_json::to_string_pretty(self)?;
        
        if compress {
            let file = File::create(&file_path)?;
            let mut encoder = GzEncoder::new(BufWriter::new(file), Compression::default());
            encoder.write_all(serialized.as_bytes())?;
            encoder.finish()?;
        } else {
            fs::write(&file_path, &serialized)?;
        }
        
        // Calculate and update checksum
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        self.metadata.checksum = format!("{:x}", hasher.finalize());
        
        println!("Snapshot saved to: {}", file_path.display());
        
        Ok(file_path)
    }
    
    /// Load snapshot from file
    pub fn load(file_path: &Path) -> BackupResult<Self> {
        let is_compressed = file_path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.contains("gz"))
            .unwrap_or(false);
        
        let content = if is_compressed {
            let file = File::open(file_path)?;
            let mut decoder = GzDecoder::new(BufReader::new(file));
            let mut content = String::new();
            decoder.read_to_string(&mut content)?;
            content
        } else {
            fs::read_to_string(file_path)?
        };
        
        let snapshot: SystemSnapshot = serde_json::from_str(&content)?;
        
        println!("Snapshot loaded from: {}", file_path.display());
        
        Ok(snapshot)
    }
    
    /// Compare this snapshot with another to find differences
    pub fn compare_with(&self, other: &SystemSnapshot) -> Vec<FileChange> {
        let mut changes = Vec::new();
        
        // Find modified files
        for (path, current_state) in &self.file_states {
            if let Some(other_state) = other.file_states.get(path) {
                if current_state.checksum != other_state.checksum {
                    changes.push(FileChange {
                        path: path.clone(),
                        change_type: ChangeType::Modified,
                        old_content: other_state.content_backup.clone(),
                        new_content: current_state.content_backup.clone(),
                        old_permissions: Some(other_state.permissions),
                        new_permissions: Some(current_state.permissions),
                        timestamp: self.created_at,
                        checksum_before: Some(other_state.checksum.clone()),
                        checksum_after: Some(current_state.checksum.clone()),
                    });
                }
            } else {
                // File was created
                changes.push(FileChange {
                    path: path.clone(),
                    change_type: ChangeType::Created,
                    old_content: None,
                    new_content: current_state.content_backup.clone(),
                    old_permissions: None,
                    new_permissions: Some(current_state.permissions),
                    timestamp: self.created_at,
                    checksum_before: None,
                    checksum_after: Some(current_state.checksum.clone()),
                });
            }
        }
        
        // Find deleted files
        for (path, other_state) in &other.file_states {
            if !self.file_states.contains_key(path) {
                changes.push(FileChange {
                    path: path.clone(),
                    change_type: ChangeType::Deleted,
                    old_content: other_state.content_backup.clone(),
                    new_content: None,
                    old_permissions: Some(other_state.permissions),
                    new_permissions: None,
                    timestamp: self.created_at,
                    checksum_before: Some(other_state.checksum.clone()),
                    checksum_after: None,
                });
            }
        }
        
        changes
    }
}