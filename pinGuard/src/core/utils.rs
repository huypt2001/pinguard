// Core error types and common utilities

use std::fmt;

/// Main error type for PinGuard
#[derive(Debug)]
pub enum PinGuardError {
    ConfigError(String),
    ScanError(String),
    FixError(String),
    ReportError(String),
    PermissionError(String),
    IoError(std::io::Error),
}

impl fmt::Display for PinGuardError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PinGuardError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            PinGuardError::ScanError(msg) => write!(f, "Scan error: {}", msg),
            PinGuardError::FixError(msg) => write!(f, "Fix error: {}", msg),
            PinGuardError::ReportError(msg) => write!(f, "Report error: {}", msg),
            PinGuardError::PermissionError(msg) => write!(f, "Permission error: {}", msg),
            PinGuardError::IoError(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl std::error::Error for PinGuardError {}

impl From<std::io::Error> for PinGuardError {
    fn from(error: std::io::Error) -> Self {
        PinGuardError::IoError(error)
    }
}

/// Result type for PinGuard operations
pub type PinGuardResult<T> = Result<T, PinGuardError>;

/// Helper functions for collecting system information
pub mod system {
    use super::PinGuardResult;
    use std::process::Command;

    /// Get OS information
    pub fn get_os_info() -> PinGuardResult<String> {
        let output = Command::new("lsb_release").arg("-d").arg("-s").output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            // Fallback: Read the /etc/os-release file
            match std::fs::read_to_string("/etc/os-release") {
                Ok(content) => {
                    for line in content.lines() {
                        if line.starts_with("PRETTY_NAME=") {
                            return Ok(line
                                .split('=')
                                .nth(1)
                                .unwrap_or("Unknown")
                                .trim_matches('"')
                                .to_string());
                        }
                    }
                    Ok("Unknown Linux".to_string())
                }
                Err(_) => Ok("Unknown".to_string()),
            }
        }
    }

    /// Get kernel version
    pub fn get_kernel_version() -> PinGuardResult<String> {
        let output = Command::new("uname").arg("-r").output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(super::PinGuardError::ScanError(
                "Failed to retrieve kernel version".to_string(),
            ))
        }
    }

    /// Check for root privileges
    pub fn check_root_privileges() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    /// Get system uptime information
    pub fn get_uptime() -> PinGuardResult<String> {
        let output = Command::new("uptime").arg("-p").output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(super::PinGuardError::ScanError(
                "Failed to retrieve uptime information".to_string(),
            ))
        }
    }
}

/// File and directory utilities
pub mod file_utils {
    use super::PinGuardResult;
    use std::path::Path;

    /// Check if a directory exists, create it if it doesn't
    pub fn ensure_directory_exists<P: AsRef<Path>>(path: P) -> PinGuardResult<()> {
        if !path.as_ref().exists() {
            std::fs::create_dir_all(&path)?;
        }
        Ok(())
    }

    /// Check file permissions
    pub fn check_file_permissions<P: AsRef<Path>>(path: P) -> PinGuardResult<u32> {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(&path)?;
        let permissions = metadata.permissions();
        Ok(permissions.mode())
    }

    /// Safe file writing (atomic write)
    pub fn write_file_atomic<P: AsRef<Path>>(path: P, content: &str) -> PinGuardResult<()> {
        let temp_path = format!("{}.tmp", path.as_ref().display());
        std::fs::write(&temp_path, content)?;
        std::fs::rename(&temp_path, &path)?;
        Ok(())
    }
}
