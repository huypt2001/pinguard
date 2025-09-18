# Changelog

All notable changes to PinGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2025-09-18

### Added
- **Container Security Scanner** - Comprehensive Docker and Kubernetes security auditing
  - Docker container vulnerability scanning and privilege escalation detection
  - Docker image security analysis including base image checks and layer scanning
  - Docker daemon configuration audit for security best practices
  - Container runtime security checks and secrets scanning
  - Container network security analysis
  - Basic Kubernetes cluster security audit with RBAC and network policy checks
- Enhanced configuration support for container_security module
- Extended CLI support for container-specific findings filtering

### Security
- Added detection for privileged containers running with elevated privileges
- Implemented secrets scanning in container environment variables
- Added sensitive port exposure detection for containers
- Enhanced Docker daemon security configuration validation

## [0.1.0] - 2024-12-XX

### Added
- Initial release of PinGuard
- Complete vulnerability scanning system
- CVE database integration with NVD
- Multiple scanner modules (package, kernel, permission, service, user, network)
- Automated remediation system
- Multiple report formats (JSON, HTML, PDF)
- Docker support for containerized deployment
- Comprehensive CI/CD pipeline
- Installation scripts for easy deployment
- Scheduled scanning with systemd integration

### Security
- Comprehensive security audit implementation
- Secure configuration management
- Encrypted communications with external APIs
- Security-focused Docker containers

## [0.1.0] - 2024-12-XX

### Added
- Initial implementation of PinGuard Linux security scanner
- Core scanning modules:
  - Package vulnerability audit
  - Kernel security check
  - File permissions audit
  - Service configuration audit
  - User policy audit
  - Network security audit
- CVE Manager with NVD integration
- Local CVE caching system
- Report generation in multiple formats
- Automated remediation system
- Configuration management
- Database management with SQLite
- Comprehensive logging system
- Docker support
- Installation and setup scripts
- GitHub Actions CI/CD pipeline
- Comprehensive documentation
- Security policy and contributing guidelines

### Technical Details
- Rust implementation for performance and security
- Async/await support for concurrent operations
- SQLite database for local data storage
- HTTPS communication with external APIs
- Configurable scan modules
- Modular architecture for extensibility

### Documentation
- Complete README with installation and usage instructions
- Security policy and vulnerability reporting process
- Contributing guidelines for developers
- Configuration examples and reference
- Docker deployment documentation