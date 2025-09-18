#!/bin/bash

# Release preparation script for PinGuard
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if we're in the right directory
    if [[ ! -f "pinGuard/Cargo.toml" ]]; then
        log_error "Please run this script from the project root directory"
        exit 1
    fi
    
    # Check git status
    if [[ -n $(git status --porcelain) ]]; then
        log_warning "Working directory is not clean. Please commit or stash changes."
        git status --short
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check if Rust is installed
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo not found. Please install Rust first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

run_tests() {
    log_info "Running tests..."
    cd pinGuard
    
    # Format check
    if ! cargo fmt --all -- --check; then
        log_error "Code formatting check failed. Run 'cargo fmt' to fix."
        exit 1
    fi
    
    # Clippy check
    if ! cargo clippy --all-targets --all-features -- -D warnings; then
        log_error "Clippy check failed. Fix warnings before release."
        exit 1
    fi
    
    # Run tests
    if ! cargo test; then
        log_error "Tests failed. Fix tests before release."
        exit 1
    fi
    
    # Security audit
    if command -v cargo-audit &> /dev/null; then
        if ! cargo audit; then
            log_warning "Security audit found issues. Review before release."
        fi
    else
        log_warning "cargo-audit not installed. Consider running 'cargo install cargo-audit'"
    fi
    
    cd ..
    log_success "All tests passed"
}

build_release() {
    log_info "Building release binary..."
    cd pinGuard
    
    if ! cargo build --release; then
        log_error "Release build failed"
        exit 1
    fi
    
    # Test the binary
    if ! ./target/release/pinGuard --help > /dev/null; then
        log_error "Release binary is not working"
        exit 1
    fi
    
    cd ..
    log_success "Release binary built successfully"
}

create_release_notes() {
    log_info "Creating release notes..."
    
    VERSION=$(grep '^version = ' pinGuard/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
    
    cat > release_notes.md << EOF
# PinGuard v${VERSION}

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
\`\`\`bash
curl -sSL https://raw.githubusercontent.com/reicalasso/pinGuard/main/scripts/install.sh | sudo bash
\`\`\`

### Manual Install
1. Download the binary for your platform from the assets below
2. Extract: \`tar -xzf pinGuard-linux-*.tar.gz\`
3. Install: \`sudo mv pinGuard /usr/local/bin/\`
4. Make executable: \`sudo chmod +x /usr/local/bin/pinGuard\`

## Usage

\`\`\`bash
# Run a security scan
sudo pinGuard scan

# Generate an HTML report
sudo pinGuard report --format html

# Fix vulnerabilities
sudo pinGuard fix --input scan_results.json
\`\`\`

## System Requirements

- Linux (Ubuntu 20.04+, CentOS 8+, or equivalent)
- Root privileges for full functionality
- Architecture: x86_64 or ARM64

## What's Changed

See [CHANGELOG.md](https://github.com/reicalasso/pinGuard/blob/main/CHANGELOG.md) for detailed changes.

## Full Changelog

**Full Changelog**: https://github.com/reicalasso/pinGuard/commits/v${VERSION}
EOF

    log_success "Release notes created: release_notes.md"
}

prepare_release_assets() {
    log_info "Preparing release assets..."
    
    VERSION=$(grep '^version = ' pinGuard/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
    ASSETS_DIR="release_assets"
    
    mkdir -p "$ASSETS_DIR"
    
    # Copy binary and create tarball
    cd pinGuard
    cp target/release/pinGuard "../$ASSETS_DIR/"
    cd "../$ASSETS_DIR"
    
    tar -czf "pinGuard-linux-x86_64.tar.gz" pinGuard
    sha256sum "pinGuard-linux-x86_64.tar.gz" > "pinGuard-linux-x86_64.tar.gz.sha256"
    
    # Copy configuration example
    cp ../config.example.yaml ./
    
    cd ..
    log_success "Release assets prepared in $ASSETS_DIR/"
}

show_next_steps() {
    VERSION=$(grep '^version = ' pinGuard/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
    
    log_success "Release preparation completed!"
    echo
    echo "Next steps:"
    echo "1. Review the release notes in release_notes.md"
    echo "2. Commit and push all changes:"
    echo "   git add ."
    echo "   git commit -m 'Prepare release v${VERSION}'"
    echo "   git push origin main"
    echo
    echo "3. Create and push a tag:"
    echo "   git tag -a v${VERSION} -m 'Release v${VERSION}'"
    echo "   git push origin v${VERSION}"
    echo
    echo "4. Create a GitHub release:"
    echo "   - Go to https://github.com/reicalasso/pinGuard/releases/new"
    echo "   - Select tag: v${VERSION}"
    echo "   - Copy content from release_notes.md"
    echo "   - Upload assets from release_assets/ directory"
    echo "   - Publish release"
    echo
    echo "5. After release, test the installation script:"
    echo "   curl -sSL https://raw.githubusercontent.com/reicalasso/pinGuard/main/scripts/install.sh | sudo bash"
}

# Main execution
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 PinGuard Release Preparation                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    
    check_prerequisites
    run_tests
    build_release
    create_release_notes
    prepare_release_assets
    show_next_steps
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "PinGuard Release Preparation Script"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --skip-tests   Skip running tests (not recommended)"
        echo
        exit 0
        ;;
    --skip-tests)
        SKIP_TESTS=true
        ;;
esac

if [[ "${SKIP_TESTS:-false}" == "true" ]]; then
    log_warning "Skipping tests as requested"
    main() {
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                 PinGuard Release Preparation                 ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo
        
        check_prerequisites
        build_release
        create_release_notes
        prepare_release_assets
        show_next_steps
    }
fi

main