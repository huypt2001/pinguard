# 🛡️ PinGuard

**Linux-first Vulnerability Scanner & Remediator**

PinGuard is a comprehensive, enterprise-grade security scanning and remediation tool designed specifically for Linux systems. It identifies security vulnerabilities, provides detailed reports in multiple formats, and offers automated fixing capabilities to keep your Linux infrastructure secure and compliant.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Build Status](https://github.com/reicalasso/pinGuard/workflows/CI/badge.svg)](https://github.com/reicalasso/pinGuard/actions)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)](https://hub.docker.com/r/pinguard/pinguard)
[![Release](https://img.shields.io/github/v/release/reicalasso/pinGuard)](https://github.com/reicalasso/pinGuard/releases)

## 🚀 Key Features

### 🔍 **Comprehensive Security Scanning**
- **Package Vulnerability Audit**: Scans installed packages against CVE databases
- **Kernel Security Check**: Verifies kernel version and security patches
- **File Permissions Audit**: Identifies dangerous file permissions and ownership
- **Service Configuration Audit**: Reviews system services for security misconfigurations
- **User Policy Audit**: Examines user accounts, passwords, and access policies
- **Network Security Audit**: Analyzes open ports, firewall rules, and network services

### 📊 **Multi-Format Reporting**
- **JSON Reports**: Machine-readable format for automation and integration
- **HTML Reports**: Beautiful, interactive reports for human consumption
- **PDF Reports**: Professional documentation for compliance and audits
- **Executive Summaries**: High-level overviews for management reporting

### 🔧 **Intelligent Automated Remediation**
- **Smart Package Updates**: Automated security patches with dependency resolution
- **Kernel Updates**: Safe kernel upgrades with rollback capabilities
- **Permission Fixes**: Automatic correction of dangerous file permissions
- **Service Hardening**: Security configuration improvements for system services
- **User Policy Enforcement**: Automated password and access policy fixes
- **Firewall Configuration**: Intelligent firewall rule optimization

### 🗄️ **Advanced CVE Management**
- **NVD Integration**: Real-time National Vulnerability Database synchronization
- **Local CVE Caching**: High-performance local database for offline operation
- **Automatic Updates**: Background CVE database refresh
- **Custom CVE Sources**: Support for private vulnerability feeds

### ⏰ **Enterprise Scheduling**
- **Systemd Integration**: Native Linux service integration
- **Flexible Cron Scheduling**: Custom scan schedules with full cron syntax
- **Background Monitoring**: Continuous system monitoring capabilities
- **Alert Integration**: Email and webhook notifications for critical findings

### 🐳 **Production-Ready Deployment**
- **Docker Support**: Official container images for easy deployment
- **Multi-Architecture**: Support for x86_64 and ARM64 platforms
- **Cloud-Ready**: Optimized for cloud and container environments
- **High Performance**: Rust-powered for maximum speed and minimal resource usage

## 📋 System Requirements

### **Supported Operating Systems**
- **Ubuntu**: 20.04 LTS, 22.04 LTS, 24.04 LTS
- **Debian**: 11 (Bullseye), 12 (Bookworm)
- **CentOS/RHEL**: 8, 9
- **Fedora**: 36, 37, 38, 39
- **Amazon Linux**: 2, 2023
- **SUSE Linux Enterprise**: 15 SP3+

### **Hardware Requirements**
- **Architecture**: x86_64 (Intel/AMD), ARM64 (AArch64)
- **Memory**: Minimum 512MB RAM, Recommended 2GB+ for large systems
- **Storage**: 100MB for application, 500MB+ for CVE database cache
- **Network**: Internet connection for CVE updates (optional for air-gapped environments)

### **System Privileges**
- **Root Access**: Required for comprehensive system scanning and remediation
- **Sudo Access**: Alternative for limited functionality
- **SELinux/AppArmor**: Fully compatible with security frameworks

### **Build Dependencies** (for source installation)
- **Rust**: 1.70.0 or later
- **System Libraries**: SQLite3, OpenSSL, pkg-config
- **Compiler**: GCC or Clang with C++14 support

## 🛠️ Installation

### **Quick Install (Recommended)**

The fastest way to get PinGuard running on your system:

```bash
# Download and run the installation script
curl -sSL https://raw.githubusercontent.com/reicalasso/pinGuard/main/scripts/install.sh | sudo bash

# Verify installation
pinGuard --version
```

### **Package Manager Installation**

#### Debian/Ubuntu
```bash
# Add PinGuard repository
echo "deb [trusted=yes] https://apt.pinguard.dev/ stable main" | sudo tee /etc/apt/sources.list.d/pinguard.list
sudo apt update

# Install PinGuard
sudo apt install pinguard
```

#### CentOS/RHEL/Fedora
```bash
# Add PinGuard repository
sudo tee /etc/yum.repos.d/pinguard.repo << EOF
[pinguard]
name=PinGuard Repository
baseurl=https://rpm.pinguard.dev/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.pinguard.dev/pubkey.gpg
EOF

# Install PinGuard
sudo dnf install pinguard  # or sudo yum install pinguard
```

### **Pre-built Binaries**

Download and install pre-compiled binaries:

```bash
# Detect architecture and download appropriate binary
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    wget https://github.com/reicalasso/pinGuard/releases/latest/download/pinGuard-linux-x86_64.tar.gz
    tar -xzf pinGuard-linux-x86_64.tar.gz
elif [ "$ARCH" = "aarch64" ]; then
    wget https://github.com/reicalasso/pinGuard/releases/latest/download/pinGuard-linux-arm64.tar.gz
    tar -xzf pinGuard-linux-arm64.tar.gz
fi

# Install binary
sudo install -o root -g root -m 0755 pinGuard /usr/local/bin/pinGuard

# Create configuration directory
sudo mkdir -p /etc/pinGuard
sudo cp config.example.yaml /etc/pinGuard/config.yaml
```

### **Building from Source**

For development or custom builds:

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install system dependencies
# Ubuntu/Debian:
sudo apt install build-essential pkg-config libssl-dev libsqlite3-dev

# CentOS/RHEL/Fedora:
sudo dnf install gcc pkgconfig openssl-devel sqlite-devel

# Clone and build
git clone https://github.com/reicalasso/pinGuard.git
cd pinGuard/pinGuard
cargo build --release

# Install
sudo install -o root -g root -m 0755 target/release/pinGuard /usr/local/bin/
sudo mkdir -p /etc/pinGuard
sudo cp ../config.example.yaml /etc/pinGuard/config.yaml
```

### **Docker Installation**

Perfect for containerized environments and quick testing:

```bash
# Pull the latest official image
docker pull ghcr.io/reicalasso/pinguard:latest

# Quick system scan (read-only host mount)
docker run --rm --privileged \
  -v /:/host:ro \
  -v $(pwd)/reports:/app/reports \
  ghcr.io/reicalasso/pinguard:latest \
  scan --output /app/reports/scan_results.json

# Interactive mode with persistent configuration
docker run -it --privileged \
  -v /:/host:ro \
  -v pinguard-config:/etc/pinGuard \
  -v pinguard-data:/var/lib/pinGuard \
  ghcr.io/reicalasso/pinguard:latest bash
```

#### Docker Compose Setup

Create a `docker-compose.yml` for production deployment:

```yaml
version: '3.8'
services:
  pinguard:
    image: ghcr.io/reicalasso/pinguard:latest
    privileged: true
    volumes:
      - /:/host:ro
      - pinguard-config:/etc/pinGuard
      - pinguard-data:/var/lib/pinGuard
      - ./reports:/app/reports
    environment:
      - RUST_LOG=info
      - PINGUARD_CONFIG=/etc/pinGuard/config.yaml
    restart: unless-stopped

volumes:
  pinguard-config:
  pinguard-data:
```

## 🚀 Quick Start

After installation, get started with these simple commands:

```bash
# Initialize PinGuard (first-time setup)
sudo pinGuard database init

# Perform your first security scan
sudo pinGuard scan

# View the results
sudo pinGuard report --format html

# Update CVE database
sudo pinGuard cve update
```

## 🔧 Configuration

PinGuard uses a YAML configuration file. Create your configuration:

```bash
# Copy the default configuration
sudo cp /usr/local/share/pinGuard/config.yaml /etc/pinGuard/config.yaml

# Edit the configuration
sudo nano /etc/pinGuard/config.yaml
```

### Configuration Example

```yaml
# Scanner settings
scanner:
  modules:
    package_audit: true
    kernel_check: true
    permission_audit: true
    service_audit: true
    user_audit: true
    network_audit: true
  concurrent_scans: true
  max_scan_time: 300

# Report settings
report:
  format: "json"
  output_dir: "/var/log/pinGuard/reports"
  template: "default"

# CVE settings
cve:
  api_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
  cache_duration: 86400
  auto_update: true

# Fixer settings
fixer:
  auto_fix: false
  require_confirmation: true
  backup_before_fix: true
```

## 📖 Usage

### Basic Commands

#### Perform a System Scan
```bash
# Full system scan
sudo pinGuard scan

# Scan specific modules
sudo pinGuard scan --module package
sudo pinGuard scan --module kernel

# Save results to specific file
sudo pinGuard scan --output /tmp/my_scan.json
```

#### Generate Reports
```bash
# Generate HTML report
sudo pinGuard report --format html --input /var/log/pinGuard/scan_results.json

# Generate PDF report
sudo pinGuard report --format pdf --input /var/log/pinGuard/scan_results.json
```

#### Fix Vulnerabilities
```bash
# Interactive fix (with confirmation)
sudo pinGuard fix --input /var/log/pinGuard/scan_results.json

# Automatic fix (use with caution)
sudo pinGuard fix --input /var/log/pinGuard/scan_results.json --auto

# Fix specific types only
sudo pinGuard fix --input /var/log/pinGuard/scan_results.json --module package_updater
```

#### CVE Management
```bash
# Update CVE database
sudo pinGuard cve update

# Search for specific CVE
sudo pinGuard cve search CVE-2023-1234

# Get CVE information
sudo pinGuard cve info CVE-2023-1234
```

#### Scheduled Scans
```bash
# Set up daily scans
sudo pinGuard schedule add --name "daily-scan" --cron "0 2 * * *" --scan-modules "all"

# List scheduled scans
sudo pinGuard schedule list

# Remove a scheduled scan
sudo pinGuard schedule remove --name "daily-scan"
```

### Advanced Usage

#### Custom Configuration
```bash
# Use custom config file
sudo pinGuard --config /path/to/custom-config.yaml scan

# Verbose output
sudo pinGuard -v scan
```

#### Database Management
```bash
# Initialize database
sudo pinGuard database init

# Show database status
sudo pinGuard database status

# Backup database
sudo pinGuard database backup --output /backup/pinGuard-backup.sql
```

## 📊 Report Examples

### JSON Report Structure
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-09-18T15:30:00Z",
  "version": "0.1.0",
  "system_info": {
    "hostname": "production-server-01",
    "os": "Ubuntu 24.04 LTS",
    "kernel": "6.8.0-45-generic",
    "architecture": "x86_64",
    "uptime": "15 days, 3 hours, 22 minutes"
  },
  "scan_summary": {
    "duration": "00:02:45",
    "modules_scanned": [
      "package_audit",
      "kernel_check", 
      "permission_audit",
      "service_audit",
      "user_audit",
      "network_audit"
    ],
    "total_checks": 1247,
    "total_vulnerabilities": 23
  },
  "vulnerabilities": [
    {
      "id": "VULN-PKG-001",
      "severity": "CRITICAL",
      "category": "package_vulnerability",
      "cve_ids": ["CVE-2024-1234", "CVE-2024-1235"],
      "package": {
        "name": "openssl",
        "current_version": "3.0.2-0ubuntu1.10",
        "fixed_version": "3.0.2-0ubuntu1.15",
        "architecture": "amd64"
      },
      "description": "Multiple buffer overflow vulnerabilities in OpenSSL cryptographic library",
      "impact": "Remote code execution, privilege escalation",
      "remediation": {
        "type": "package_update",
        "command": "apt update && apt upgrade openssl",
        "automated": true,
        "estimated_downtime": "< 30 seconds"
      },
      "references": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234",
        "https://ubuntu.com/security/notices/USN-6854-1"
      ]
    },
    {
      "id": "VULN-PERM-002", 
      "severity": "HIGH",
      "category": "file_permissions",
      "file": "/etc/shadow",
      "current_permissions": "644",
      "expected_permissions": "640",
      "owner": "root:root",
      "description": "World-readable shadow file exposes password hashes",
      "remediation": {
        "type": "permission_fix",
        "command": "chmod 640 /etc/shadow",
        "automated": true
      }
    }
  ],
  "security_summary": {
    "risk_score": 8.5,
    "risk_level": "HIGH",
    "vulnerability_counts": {
      "critical": 3,
      "high": 8,
      "medium": 9,
      "low": 3,
      "informational": 2
    },
    "compliance": {
      "cis_benchmark": "85%",
      "nist_csf": "78%",
      "iso27001": "82%"
    }
  },
  "recommendations": [
    "Enable automatic security updates for critical packages",
    "Implement file integrity monitoring",
    "Review and harden SSH configuration",
    "Enable audit logging for privileged operations"
  ]
}
```

### HTML Report Features
- **Interactive Dashboard**: Real-time filtering and sorting
- **Executive Summary**: High-level overview for management
- **Detailed Findings**: Comprehensive vulnerability analysis
- **Remediation Tracking**: Progress monitoring and task management
- **Compliance Mapping**: CIS, NIST, ISO 27001 alignment
- **Trending Analysis**: Historical comparison and metrics

## 🧪 Testing

### Unit Tests
```bash
cd pinGuard
cargo test
```

### Integration Tests
```bash
# Run test suite with Docker
./scripts/run_tests.sh

# Validate installation
./scripts/validate_tests.sh
```

### Test Environment Setup
```bash
# Set up test VM
./scripts/setup_vm_tests.sh
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/reicalasso/pinGuard.git
cd pinGuard

# Install development dependencies
rustup component add rustfmt clippy

# Run tests
cargo test

# Format code
cargo fmt

# Run linter
cargo clippy
```

### Reporting Issues

- **Security vulnerabilities**: Please see [SECURITY.md](SECURITY.md)
- **Bug reports**: Use [GitHub Issues](https://github.com/reicalasso/pinGuard/issues)
- **Feature requests**: Use [GitHub Discussions](https://github.com/reicalasso/pinGuard/discussions)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security

Security is our top priority. Please see [SECURITY.md](SECURITY.md) for:
- Supported versions
- Reporting security vulnerabilities
- Security best practices

## 🗺️ Roadmap

### **Version 0.2.0** (Q4 2025)
- [ ] **Enhanced Compliance Reporting**: Full CIS Benchmark, NIST CSF, ISO 27001 support
- [ ] **REST API**: HTTP API for integration with external tools
- [ ] **Web Dashboard**: Browser-based management interface
- [ ] **Container Security**: Docker and Kubernetes image scanning
- [ ] **Custom Rules Engine**: User-defined security policies and checks

### **Version 0.3.0** (Q1 2026)
- [ ] **Windows Support**: Cross-platform vulnerability scanning
- [ ] **Cloud Integration**: AWS, GCP, Azure security assessments
- [ ] **SIEM Integration**: Splunk, Elasticsearch, QRadar connectors
- [ ] **Machine Learning**: Anomaly detection and threat hunting
- [ ] **Zero-Trust Assessment**: Network segmentation and access validation

### **Version 1.0.0** (Q2 2026)
- [ ] **macOS Support**: Complete cross-platform coverage
- [ ] **Enterprise SSO**: SAML, OIDC, Active Directory integration
- [ ] **High Availability**: Clustered deployments and failover
- [ ] **Regulatory Compliance**: SOX, HIPAA, PCI-DSS reporting
- [ ] **Professional Services**: Managed security monitoring

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🙏 Acknowledgments

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) for CVE data
- The Rust community for excellent libraries
- Linux security community for best practices

## 📞 Support & Community

### **Getting Help**
- **📖 Documentation**: [Complete Guide](https://github.com/reicalasso/pinGuard/wiki)
- **💬 Community Forum**: [GitHub Discussions](https://github.com/reicalasso/pinGuard/discussions)
- **🐛 Bug Reports**: [GitHub Issues](https://github.com/reicalasso/pinGuard/issues)
- **💡 Feature Requests**: [GitHub Discussions](https://github.com/reicalasso/pinGuard/discussions/categories/ideas)

### **Commercial Support**
- **Enterprise Support**: Priority support with SLA guarantees
- **Professional Services**: Security consulting and custom integrations
- **Training**: On-site and remote security training programs
- **Contact**: [enterprise@pinguard.dev](mailto:enterprise@pinguard.dev)

### **Community**
- **Discord**: [Join our community server](https://discord.gg/pinguard)
- **Twitter**: [@PinGuardSec](https://twitter.com/PinGuardSec)
- **LinkedIn**: [PinGuard Security](https://linkedin.com/company/pinguard-security)
- **Blog**: [Security insights and updates](https://blog.pinguard.dev)

---

## 🏆 Why Choose PinGuard?

**🚀 Performance-First**: Built with Rust for maximum speed and minimal resource usage  
**🔒 Security-Native**: Designed by security professionals for security professionals  
**🐧 Linux-Optimized**: Deep integration with Linux systems and best practices  
**📈 Enterprise-Ready**: Scalable from single servers to massive infrastructures  
**🛡️ Compliance-Focused**: Built-in support for major security frameworks  
**🤝 Community-Driven**: Open source with transparent development and roadmap  

---

<div align="center">

**Made with ❤️ by the PinGuard Team**

**Securing Linux, One System at a Time**

[⭐ Star us on GitHub](https://github.com/reicalasso/pinGuard) | [🐛 Report Issues](https://github.com/reicalasso/pinGuard/issues) | [💬 Join Community](https://github.com/reicalasso/pinGuard/discussions)

</div>