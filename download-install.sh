#!/usr/bin/env bash
# NoteDaemon Installation Script
# This script downloads, builds, and installs the NoteDaemon system
# Usage: sudo ./install-notedaemon.sh
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/networkspore/NoteDaemon/archive/refs/tags/v1.0.0-beta.1.tar.gz"
TAG_VERSION="v1.0.0-beta.1"
WORK_DIR="/tmp/notedaemon-install"
EXTRACTED_DIR="NoteDaemon-1.0.0-beta.1"

# Functions
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

get_sudo_user() {
    if [[ -n "$SUDO_USER" ]]; then
        echo "$SUDO_USER"
    else
        echo "$USER"
    fi
}

# Main installation process
main() {
    check_root
    
    CALLING_USER=$(get_sudo_user)
    print_status "Installation started by user: $CALLING_USER"
    
    # Step 1: Update and install dependencies
    print_status "Updating package list..."
    apt-get update -qq
    
    print_status "Installing required packages..."
    apt-get install -y \
        build-essential \
        cmake \
        pkg-config \
        libusb-1.0-0-dev \
        libssl-dev \
        libboost-all-dev \
        wget \
        tar
    
    print_success "Dependencies installed"
    
    # Step 2: Download source code
    print_status "Creating working directory: $WORK_DIR"
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"
    
    print_status "Downloading NoteDaemon $TAG_VERSION..."
    wget -q --show-progress "$REPO_URL" -O notedaemon.tar.gz
    print_success "Download complete"
    
    # Step 3: Extract archive
    print_status "Extracting archive..."
    tar -xzf notedaemon.tar.gz
    cd "$EXTRACTED_DIR"
    print_success "Extraction complete"
    
    # Step 4: Create netnotes group and user
    print_status "Setting up netnotes system user and group..."
    if ! getent group netnotes >/dev/null; then
        groupadd --system netnotes
        print_success "Created netnotes group"
    else
        print_warning "Group netnotes already exists"
    fi
    
    if ! id netnotes >/dev/null 2>&1; then
        useradd --system --no-create-home --home-dir /var/lib/netnotes \
                -g netnotes --shell /usr/sbin/nologin netnotes
        print_success "Created netnotes user"
    else
        print_warning "User netnotes already exists"
    fi
    
    # Step 5: Create runtime/data directories
    print_status "Creating runtime directories..."
    mkdir -p /var/lib/netnotes /run/netnotes
    chown netnotes:netnotes /var/lib/netnotes /run/netnotes
    chmod 0750 /var/lib/netnotes /run/netnotes
    print_success "Runtime directories created"
    
    # Step 6: Build the project
    print_status "Building NoteDaemon..."
    mkdir -p build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release .. > /dev/null
    make -j$(nproc)
    print_success "Build complete"
    
    # Step 7: Install binary
    print_status "Installing note-daemon binary..."
    install -m 0755 -o root -g netnotes note-daemon /usr/local/bin/note-daemon
    print_success "Binary installed to /usr/local/bin/note-daemon"
    
    # Step 8: Install udev rules
    cd ..
    print_status "Installing udev rules..."
    cp 99-netnotes.rules /etc/udev/rules.d/99-netnotes.rules
    chmod 0644 /etc/udev/rules.d/99-netnotes.rules
    print_success "Udev rules installed"
    
    # Step 9: Reload udev rules without restarting
    print_status "Reloading udev rules..."
    udevadm control --reload-rules
    udevadm trigger
    print_success "Udev rules reloaded"
    
    # Step 10: Install systemd service
    print_status "Installing systemd service..."
    cp note-daemon.service /etc/systemd/system/note-daemon.service
    chmod 0644 /etc/systemd/system/note-daemon.service
    systemctl daemon-reload
    print_success "Systemd service installed"
    
    # Step 11: Apply group membership without restart
    print_status "Applying group memberships..."
    # Force nscd to refresh if it's running
    if command -v nscd >/dev/null 2>&1; then
        nscd -i group 2>/dev/null || true
    fi
    # Force sssd to refresh if it's running
    if command -v sss_cache >/dev/null 2>&1; then
        sss_cache -G 2>/dev/null || true
    fi
    print_success "Group cache refreshed"
    
    # Step 12: Enable and start service
    print_status "Enabling and starting note-daemon service..."
    systemctl enable note-daemon.service
    systemctl start note-daemon.service
    sleep 5
    
    if systemctl is-active --quiet note-daemon.service; then
        print_success "Service started successfully"
        systemctl status note-daemon.service --no-pager | head -10
    else
        print_error "Service failed"
        systemctl status note-daemon.service --no-pager || true
    fi
    
    # Step 13: User group management
    echo ""
    echo "============================================"
    print_status "User Group Configuration"
    echo "============================================"
    echo ""
    
    # Ask about adding the calling user
    if [[ "$CALLING_USER" != "root" ]]; then
        read -p "Add user '$CALLING_USER' to the netnotes group? [Y/n]: " add_calling_user
        add_calling_user=${add_calling_user:-Y}
        
        if [[ "$add_calling_user" =~ ^[Yy]$ ]]; then
            usermod -a -G netnotes "$CALLING_USER"
            print_success "User '$CALLING_USER' added to netnotes group"
            print_warning "User '$CALLING_USER' must log out and back in for group membership to take effect"
            
            # Provide immediate access command
            echo ""
            print_status "To apply group membership immediately in current shell, run:"
            echo -e "${GREEN}    newgrp netnotes${NC}"
        fi
    fi
    
    # Ask about adding another user
    echo ""
    read -p "Add another user to the netnotes group (for client app)? [y/N]: " add_another
    add_another=${add_another:-N}
    
    if [[ "$add_another" =~ ^[Yy]$ ]]; then
        read -p "Enter username to add: " username
        if id "$username" >/dev/null 2>&1; then
            usermod -a -G netnotes "$username"
            print_success "User '$username' added to netnotes group"
            print_warning "User '$username' must log out and back in for group membership to take effect"
        else
            print_error "User '$username' does not exist"
        fi
    fi
    newgrp netnotes
    # Step 14: Cleanup
    echo ""
    print_status "Cleaning up temporary files..."
    cd /
    rm -rf "$WORK_DIR"
    print_success "Cleanup complete"
    
    # Final summary
    echo ""
    echo "============================================"
    print_success "NoteDaemon Installation Complete!"
    echo "============================================"
    echo ""
    echo "Installation Summary:"
    echo "  • Binary:         /usr/local/bin/note-daemon"
    echo "  • Service:        note-daemon.service"
    echo "  • Udev Rules:     /etc/udev/rules.d/99-netnotes.rules"
    echo "  • User/Group:     netnotes:netnotes"
    echo "  • Data Directory: /var/lib/netnotes"
    echo ""
    echo "Service Status:"
    if systemctl is-active --quiet note-daemon.service; then
        echo -e "  ${GREEN}● Running${NC}"
    else
        echo -e "  ${RED}● Stopped${NC}"
    fi
    echo ""
    echo "Useful Commands:"
    echo "  • Check status:   systemctl status note-daemon"
    echo "  • View logs:      journalctl -u note-daemon -f"
    echo "  • Restart:        systemctl restart note-daemon"
    echo "  • Stop:           systemctl stop note-daemon"
    echo ""
}

# Run main function
main "$@"