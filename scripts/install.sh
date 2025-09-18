#!/bin/bash

# PinGuard Installation Script
# This script installs PinGuard on Linux systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/reicalasso/pinGuard"
BINARY_NAME="pinGuard"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/pinGuard"
DATA_DIR="/var/lib/pinGuard"
LOG_DIR="/var/log/pinGuard"
SERVICE_USER="pinGuard"

# Functions
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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use sudo."
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    
    log_info "Detected OS: $OS $OS_VERSION"
}

detect_architecture() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    log_info "Detected architecture: $ARCH"
}

install_dependencies() {
    log_info "Installing dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y curl wget tar sqlite3 openssl ca-certificates systemd
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y curl wget tar sqlite openssl ca-certificates systemd
            else
                yum install -y curl wget tar sqlite openssl ca-certificates systemd
            fi
            ;;
        *)
            log_warning "Unknown OS. Please install curl, wget, tar, sqlite3, openssl, and systemd manually."
            ;;
    esac
}

download_binary() {
    log_info "Downloading PinGuard binary..."
    
    # Get latest release URL
    LATEST_RELEASE=$(curl -s "https://api.github.com/repos/reicalasso/pinGuard/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [[ -z "$LATEST_RELEASE" ]]; then
        log_error "Could not fetch latest release information"
        exit 1
    fi
    
    DOWNLOAD_URL="https://github.com/reicalasso/pinGuard/releases/download/${LATEST_RELEASE}/pinGuard-linux-${ARCH}.tar.gz"
    
    log_info "Downloading from: $DOWNLOAD_URL"
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download and extract
    if ! wget -q "$DOWNLOAD_URL" -O "pinGuard-linux-${ARCH}.tar.gz"; then
        log_error "Failed to download PinGuard binary"
        exit 1
    fi
    
    tar -xzf "pinGuard-linux-${ARCH}.tar.gz"
    
    # Install binary
    if [[ -f "$BINARY_NAME" ]]; then
        cp "$BINARY_NAME" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
        log_success "PinGuard binary installed to $INSTALL_DIR/$BINARY_NAME"
    else
        log_error "Binary not found in downloaded archive"
        exit 1
    fi
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
}

create_user() {
    log_info "Creating PinGuard service user..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd --system --shell /bin/false --home "$DATA_DIR" --create-home "$SERVICE_USER"
        log_success "Created user: $SERVICE_USER"
    else
        log_info "User $SERVICE_USER already exists"
    fi
}

create_directories() {
    log_info "Creating directories..."
    
    # Create directories
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR/backups"
    mkdir -p "$DATA_DIR/reports"
    
    # Set permissions
    chown root:root "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
    chmod 750 "$DATA_DIR"
    
    chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    
    log_success "Directories created and configured"
}

install_config() {
    log_info "Installing configuration files..."
    
    # Download default config if not exists
    if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
        if wget -q "https://raw.githubusercontent.com/reicalasso/pinGuard/main/config.example.yaml" -O "$CONFIG_DIR/config.yaml"; then
            # Update paths in config
            sed -i "s|./pinGuard.db|$DATA_DIR/pinGuard.db|g" "$CONFIG_DIR/config.yaml"
            sed -i "s|./reports|$DATA_DIR/reports|g" "$CONFIG_DIR/config.yaml"
            sed -i "s|./backups|$DATA_DIR/backups|g" "$CONFIG_DIR/config.yaml"
            sed -i "s|./pinGuard.log|$LOG_DIR/pinGuard.log|g" "$CONFIG_DIR/config.yaml"
            
            chmod 644 "$CONFIG_DIR/config.yaml"
            log_success "Default configuration installed"
        else
            log_warning "Could not download default configuration"
        fi
    else
        log_info "Configuration file already exists"
    fi
}

create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > /etc/systemd/system/pinGuard.service << EOF
[Unit]
Description=PinGuard Linux Security Scanner
Documentation=https://github.com/reicalasso/pinGuard
After=network.target
Wants=network.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=$INSTALL_DIR/$BINARY_NAME scan --config $CONFIG_DIR/config.yaml
WorkingDirectory=$DATA_DIR
StandardOutput=append:$LOG_DIR/pinGuard.log
StandardError=append:$LOG_DIR/pinGuard.log
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$DATA_DIR $LOG_DIR
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # Create timer for regular scans
    cat > /etc/systemd/system/pinGuard.timer << EOF
[Unit]
Description=Run PinGuard security scan daily
Requires=pinGuard.service

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    log_success "Systemd service created"
}

setup_logrotate() {
    log_info "Setting up log rotation..."
    
    cat > /etc/logrotate.d/pinGuard << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload pinGuard.service || true
    endscript
}
EOF

    log_success "Log rotation configured"
}

verify_installation() {
    log_info "Verifying installation..."
    
    # Check binary
    if [[ -x "$INSTALL_DIR/$BINARY_NAME" ]]; then
        VERSION=$("$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null || echo "unknown")
        log_success "PinGuard binary is executable (version: $VERSION)"
    else
        log_error "PinGuard binary is not executable"
        return 1
    fi
    
    # Check configuration
    if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
        log_success "Configuration file exists"
    else
        log_warning "Configuration file not found"
    fi
    
    # Check systemd service
    if systemctl list-unit-files | grep -q pinGuard.service; then
        log_success "Systemd service installed"
    else
        log_warning "Systemd service not found"
    fi
    
    return 0
}

show_next_steps() {
    log_success "PinGuard installation completed!"
    echo
    echo "Next steps:"
    echo "1. Review and customize the configuration:"
    echo "   sudo nano $CONFIG_DIR/config.yaml"
    echo
    echo "2. Run your first scan:"
    echo "   sudo $BINARY_NAME scan"
    echo
    echo "3. Enable automatic daily scans:"
    echo "   sudo systemctl enable pinGuard.timer"
    echo "   sudo systemctl start pinGuard.timer"
    echo
    echo "4. View scan reports:"
    echo "   ls -la $DATA_DIR/reports/"
    echo
    echo "5. Check logs:"
    echo "   sudo tail -f $LOG_DIR/pinGuard.log"
    echo
    echo "For more information, visit: $REPO_URL"
}

# Main installation flow
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    PinGuard Installer                        ║"
    echo "║            Linux Security Scanner & Remediator              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    
    log_info "Starting PinGuard installation..."
    
    check_root
    detect_os
    detect_architecture
    install_dependencies
    download_binary
    create_user
    create_directories
    install_config
    create_systemd_service
    setup_logrotate
    
    if verify_installation; then
        show_next_steps
    else
        log_error "Installation verification failed"
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "PinGuard Installation Script"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --uninstall    Uninstall PinGuard"
        echo
        exit 0
        ;;
    --uninstall)
        echo "Uninstalling PinGuard..."
        systemctl stop pinGuard.timer 2>/dev/null || true
        systemctl disable pinGuard.timer 2>/dev/null || true
        systemctl stop pinGuard.service 2>/dev/null || true
        systemctl disable pinGuard.service 2>/dev/null || true
        rm -f /etc/systemd/system/pinGuard.service
        rm -f /etc/systemd/system/pinGuard.timer
        rm -f /etc/logrotate.d/pinGuard
        rm -f "$INSTALL_DIR/$BINARY_NAME"
        systemctl daemon-reload
        echo "PinGuard uninstalled. Data in $CONFIG_DIR and $DATA_DIR preserved."
        exit 0
        ;;
    *)
        main
        ;;
esac