// Core error types and common utilities

use std::fmt;

/// PinGuard için ana hata tipi
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
            PinGuardError::ConfigError(msg) => write!(f, "Konfigürasyon hatası: {}", msg),
            PinGuardError::ScanError(msg) => write!(f, "Tarama hatası: {}", msg),
            PinGuardError::FixError(msg) => write!(f, "Düzeltme hatası: {}", msg),
            PinGuardError::ReportError(msg) => write!(f, "Rapor hatası: {}", msg),
            PinGuardError::PermissionError(msg) => write!(f, "Yetki hatası: {}", msg),
            PinGuardError::IoError(err) => write!(f, "IO hatası: {}", err),
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

/// System bilgilerini toplayan yardımcı fonksiyonlar
pub mod system {
    use super::PinGuardResult;
    use std::process::Command;
    
    /// OS bilgisini al
    pub fn get_os_info() -> PinGuardResult<String> {
        let output = Command::new("lsb_release")
            .arg("-d")
            .arg("-s")
            .output()?;
            
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            // Fallback: /etc/os-release dosyasını oku
            match std::fs::read_to_string("/etc/os-release") {
                Ok(content) => {
                    for line in content.lines() {
                        if line.starts_with("PRETTY_NAME=") {
                            return Ok(line.split('=').nth(1).unwrap_or("Unknown").trim_matches('"').to_string());
                        }
                    }
                    Ok("Unknown Linux".to_string())
                },
                Err(_) => Ok("Unknown".to_string()),
            }
        }
    }
    
    /// Kernel versiyonunu al
    pub fn get_kernel_version() -> PinGuardResult<String> {
        let output = Command::new("uname")
            .arg("-r")
            .output()?;
            
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(super::PinGuardError::ScanError("Kernel version alınamadı".to_string()))
        }
    }
    
    /// Root yetki kontrolü
    pub fn check_root_privileges() -> bool {
        unsafe { libc::geteuid() == 0 }
    }
    
    /// Sistem uptime bilgisi
    pub fn get_uptime() -> PinGuardResult<String> {
        let output = Command::new("uptime")
            .arg("-p")
            .output()?;
            
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(super::PinGuardError::ScanError("Uptime bilgisi alınamadı".to_string()))
        }
    }
}

/// Dosya ve dizin utilities
pub mod file_utils {
    use super::PinGuardResult;
    use std::path::Path;
    
    /// Dizin varlığını kontrol et, yoksa oluştur
    pub fn ensure_directory_exists<P: AsRef<Path>>(path: P) -> PinGuardResult<()> {
        if !path.as_ref().exists() {
            std::fs::create_dir_all(&path)?;
        }
        Ok(())
    }
    
    /// Dosya izinlerini kontrol et
    pub fn check_file_permissions<P: AsRef<Path>>(path: P) -> PinGuardResult<u32> {
        use std::os::unix::fs::PermissionsExt;
        
        let metadata = std::fs::metadata(&path)?;
        let permissions = metadata.permissions();
        Ok(permissions.mode())
    }
    
    /// Güvenli dosya yazma (atomic write)
    pub fn write_file_atomic<P: AsRef<Path>>(path: P, content: &str) -> PinGuardResult<()> {
        let temp_path = format!("{}.tmp", path.as_ref().display());
        std::fs::write(&temp_path, content)?;
        std::fs::rename(&temp_path, &path)?;
        Ok(())
    }
}