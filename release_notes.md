# PinGuard v0.1.0

## What's New

- Initial release of PinGuard Linux Security Scanner & Remediator
- Complete vulnerability scanning system with multiple modules
- CVE database integration with NVD
- Automated remediation capabilities
- Multiple report formats (JSON, HTML, PDF)
- Docker support for containerized deployment
- Comprehensive CI/CD pipeline

## Installation

### Quick Install
```bash
curl -sSL https://raw.githubusercontent.com/reicalasso/pinGuard/main/scripts/install.sh | sudo bash
```

### Manual Install
1. Download the binary for your platform from the assets below
2. Extract: `tar -xzf pinGuard-linux-*.tar.gz`
3. Install: `sudo mv pinGuard /usr/local/bin/`
4. Make executable: `sudo chmod +x /usr/local/bin/pinGuard`

## Usage

```bash
# Run a security scan
sudo pinGuard scan

# Generate an HTML report
sudo pinGuard report --format html

# Fix vulnerabilities
sudo pinGuard fix --input scan_results.json
```

## System Requirements

- Linux (Ubuntu 20.04+, CentOS 8+, or equivalent)
- Root privileges for full functionality
- Architecture: x86_64 or ARM64

## What's Changed

See [CHANGELOG.md](https://github.com/reicalasso/pinGuard/blob/main/CHANGELOG.md) for detailed changes.

## Full Changelog

**Full Changelog**: https://github.com/reicalasso/pinGuard/commits/v0.1.0
