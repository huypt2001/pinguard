# 🛡️ PinGuard

**Linux-first Vulnerability Scanner & Remediator**

PinGuard is a comprehensive security scanning and remediation tool designed specifically for Linux systems. It identifies security vulnerabilities, provides detailed reports, and offers automated fixing capabilities to keep your Linux systems secure.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Build Status](https://github.com/reicalasso/pinGuard/workflows/CI/badge.svg)](https://github.com/reicalasso/pinGuard/actions)

## 🚀 Features

- **🔍 Comprehensive Scanning**: Multiple scan modules for different security aspects
  - Package vulnerability audit
  - Kernel security check
  - File permissions audit
  - Service configuration audit
  - User policy audit
  - Network security audit

- **📊 Detailed Reporting**: Multiple output formats
  - JSON reports for automation
  - HTML reports for human-readable format
  - PDF reports for formal documentation

- **🔧 Automated Remediation**: Fix vulnerabilities automatically
  - Package updates
  - Kernel updates
  - Permission fixes
  - Service hardening
  - User policy fixes
  - Firewall configuration

- **🗄️ CVE Database Integration**: 
  - NVD (National Vulnerability Database) integration
  - Local CVE caching for fast access
  - Automatic CVE updates

- **⏰ Scheduled Scans**: 
  - Systemd integration for automated scans
  - Flexible scheduling options
  - Background monitoring

- **🐳 Docker Support**: 
  - Ready-to-use Docker containers
  - Test environment setup
  - Production deployment options

## 📋 Requirements

- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, or equivalent)
- **Architecture**: x86_64, ARM64
- **Privileges**: Root access required for full functionality
- **Dependencies**: 
  - Rust 1.70+ (for building from source)
  - SQLite3
  - OpenSSL

## 🛠️ Installation

### Quick Install (Recommended)

```bash
# Download and run the installation script
curl -sSL https://raw.githubusercontent.com/reicalasso/pinGuard/main/scripts/install.sh | sudo bash
```

### From Pre-built Binaries

1. Download the latest release for your architecture:
```bash
# For x86_64
wget https://github.com/reicalasso/pinGuard/releases/latest/download/pinGuard-linux-x86_64.tar.gz

# For ARM64
wget https://github.com/reicalasso/pinGuard/releases/latest/download/pinGuard-linux-arm64.tar.gz
```

2. Extract and install:
```bash
tar -xzf pinGuard-linux-x86_64.tar.gz
sudo mv pinGuard /usr/local/bin/
sudo chmod +x /usr/local/bin/pinGuard
```

### Building from Source

1. **Install Rust** (if not already installed):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

2. **Clone and build**:
```bash
git clone https://github.com/reicalasso/pinGuard.git
cd pinGuard/pinGuard
cargo build --release
sudo cp target/release/pinGuard /usr/local/bin/
```

### Docker Installation

```bash
# Pull the latest image
docker pull ghcr.io/reicalasso/pinGuard:latest

# Run a quick scan
docker run --rm -v /:/host:ro ghcr.io/reicalasso/pinGuard:latest scan --output /tmp/scan_results.json
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

## 📊 Output Examples

### JSON Report Structure
```json
{
  "scan_id": "uuid-here",
  "timestamp": "2024-01-15T10:30:00Z",
  "system_info": {
    "hostname": "server01",
    "os": "Ubuntu 22.04",
    "kernel": "5.15.0-56-generic"
  },
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "severity": "HIGH",
      "cve_id": "CVE-2023-1234",
      "package": "openssl",
      "current_version": "1.1.1f",
      "fixed_version": "1.1.1n",
      "description": "Buffer overflow vulnerability..."
    }
  ],
  "summary": {
    "total_vulnerabilities": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2
  }
}
```

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

- [ ] Windows support
- [ ] macOS support
- [ ] GUI interface
- [ ] REST API
- [ ] Kubernetes integration
- [ ] Cloud provider integrations (AWS, GCP, Azure)
- [ ] Compliance reporting (CIS, NIST)

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🙏 Acknowledgments

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) for CVE data
- The Rust community for excellent libraries
- Linux security community for best practices

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/reicalasso/pinGuard/wiki)
- **Community**: [GitHub Discussions](https://github.com/reicalasso/pinGuard/discussions)
- **Issues**: [GitHub Issues](https://github.com/reicalasso/pinGuard/issues)

---

Made with ❤️ by the PinGuard Team