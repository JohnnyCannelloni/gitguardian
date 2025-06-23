#!/bin/bash

# GitGuardian Installation Script
# This script installs GitGuardian on Unix-like systems

set -e

# Configuration
REPO_URL="https://github.com/yourusername/gitguardian"
BINARY_NAME="gitguardian"
INSTALL_DIR="/usr/local/bin"
VERSION=${VERSION:-"latest"}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
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

# Check if running as root for system installation
check_permissions() {
    if [ "$EUID" -ne 0 ] && [ "$1" = "system" ]; then
        log_error "System installation requires root privileges"
        log_info "Please run with sudo: sudo $0"
        exit 1
    fi
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case $ARCH in
        x86_64) ARCH="amd64" ;;
        arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) 
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    case $OS in
        linux) ;;
        darwin) ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    log_info "Detected platform: $OS/$ARCH"
}

# Check if required tools are available
check_dependencies() {
    local deps=("curl" "tar")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "Required dependency not found: $dep"
            log_info "Please install $dep and try again"
            exit 1
        fi
    done
}

# Download and install binary
install_binary() {
    local install_type=$1
    
    if [ "$install_type" = "source" ]; then
        install_from_source
        return
    fi

    # Set download URL based on version
    if [ "$VERSION" = "latest" ]; then
        DOWNLOAD_URL="$REPO_URL/releases/latest/download/${BINARY_NAME}-${OS}-${ARCH}"
    else
        DOWNLOAD_URL="$REPO_URL/releases/download/v${VERSION}/${BINARY_NAME}-${OS}-${ARCH}"
    fi

    if [ "$OS" = "linux" ]; then
        DOWNLOAD_URL="${DOWNLOAD_URL}.tar.gz"
    else
        DOWNLOAD_URL="${DOWNLOAD_URL}.tar.gz"
    fi

    log_info "Downloading GitGuardian..."
    log_info "URL: $DOWNLOAD_URL"

    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT

    # Download binary
    if ! curl -L -o "$TEMP_DIR/${BINARY_NAME}.tar.gz" "$DOWNLOAD_URL"; then
        log_error "Failed to download GitGuardian"
        log_info "Please check your internet connection and try again"
        exit 1
    fi

    # Extract binary
    log_info "Extracting binary..."
    cd "$TEMP_DIR"
    tar -xzf "${BINARY_NAME}.tar.gz"

    # Determine installation directory
    if [ "$install_type" = "user" ]; then
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
    fi

    # Install binary
    log_info "Installing to $INSTALL_DIR..."
    cp "${BINARY_NAME}-${OS}-${ARCH}" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    log_success "GitGuardian installed successfully!"
}

# Install from source
install_from_source() {
    log_info "Installing from source..."

    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        log_error "Go is required to install from source"
        log_info "Please install Go from https://golang.org/dl/"
        exit 1
    fi

    # Check Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    REQUIRED_VERSION="1.21"
    
    if ! printf '%s\n%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V -C; then
        log_warning "Go version $GO_VERSION detected. Version $REQUIRED_VERSION or higher is recommended."
    fi

    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT

    # Clone repository
    log_info "Cloning repository..."
    git clone "$REPO_URL" "$TEMP_DIR/gitguardian"
    cd "$TEMP_DIR/gitguardian"

    # Build binary
    log_info "Building GitGuardian..."
    go build -ldflags="-s -w" -o "$BINARY_NAME" ./

    # Install binary
    if [ "$EUID" -eq 0 ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
    fi

    log_info "Installing to $INSTALL_DIR..."
    cp "$BINARY_NAME" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    log_success "GitGuardian built and installed successfully!"
}

# Verify installation
verify_installation() {
    if command -v "$BINARY_NAME" &> /dev/null; then
        VERSION_OUTPUT=$($BINARY_NAME -version 2>/dev/null || echo "GitGuardian installed")
        log_success "Installation verified: $VERSION_OUTPUT"
    else
        log_warning "GitGuardian binary not found in PATH"
        log_info "You may need to add $INSTALL_DIR to your PATH"
        log_info "Add this line to your shell profile:"
        log_info "export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
}

# Setup shell completion (if supported)
setup_completion() {
    log_info "Setting up shell completion..."
    
    # This would be implemented if the binary supports completion
    # For now, just inform the user
    log_info "Shell completion setup not yet implemented"
}

# Install Git hooks helper
install_hooks_helper() {
    log_info "To install Git hooks in a repository, run:"
    log_info "  cd /path/to/your/repo"
    log_info "  $BINARY_NAME -install-hooks"
}

# Show usage information
show_usage() {
    cat << EOF
GitGuardian Installation Script

Usage: $0 [OPTIONS]

Options:
    -h, --help          Show this help message
    -v, --version VER   Install specific version (default: latest)
    -s, --source        Install from source code
    -u, --user          Install for current user only
    --uninstall         Uninstall GitGuardian

Examples:
    $0                  # Install latest version system-wide
    $0 --user           # Install for current user
    $0 --source         # Build and install from source
    $0 --version 1.0.0  # Install specific version

Environment Variables:
    VERSION             Specify version to install
    INSTALL_DIR         Override installation directory

EOF
}

# Uninstall GitGuardian
uninstall() {
    log_info "Uninstalling GitGuardian..."
    
    local found=false
    local locations=("/usr/local/bin/$BINARY_NAME" "$HOME/.local/bin/$BINARY_NAME")
    
    for location in "${locations[@]}"; do
        if [ -f "$location" ]; then
            rm -f "$location"
            log_success "Removed $location"
            found=true
        fi
    done
    
    if [ "$found" = false ]; then
        log_warning "GitGuardian binary not found"
    else
        log_success "GitGuardian uninstalled successfully"
    fi
}

# Main installation logic
main() {
    local install_type="system"
    local install_source=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -s|--source)
                install_source=true
                shift
                ;;
            -u|--user)
                install_type="user"
                shift
                ;;
            --uninstall)
                uninstall
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    log_info "Starting GitGuardian installation..."
    log_info "Version: $VERSION"
    log_info "Install type: $install_type"

    # Check permissions for system installation
    check_permissions "$install_type"

    # Detect platform
    detect_platform

    # Check dependencies
    check_dependencies

    # Install binary
    if [ "$install_source" = true ]; then
        install_binary "source"
    else
        install_binary "$install_type"
    fi

    # Verify installation
    verify_installation

    # Setup completion
    setup_completion

    # Show hooks installation help
    install_hooks_helper

    log_success "GitGuardian installation completed!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Navigate to a Git repository"
    log_info "2. Run '$BINARY_NAME -install-hooks' to install Git hooks"
    log_info "3. Run '$BINARY_NAME -path .' to scan your repository"
    log_info ""
    log_info "For more information, visit: $REPO_URL"
}

# Run main function
main "$@"