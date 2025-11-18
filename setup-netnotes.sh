#!/usr/bin/env bash
# Netnotes Daemon Interactive Setup Script
# This script configures the system for Netnotes daemon operation with user prompts
# Usage: sudo ./setup-netnotes.sh
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-Y}"
    local response
    
    if [[ "$default" == "Y" ]]; then
        read -p "$prompt [Y/n]: " response
        response=${response:-Y}
    else
        read -p "$prompt [y/N]: " response
        response=${response:-N}
    fi
    
    [[ "$response" =~ ^[Yy]$ ]]
}

# Main setup process
main() {
    check_root
    
    CALLING_USER=$(get_sudo_user)
    
    echo ""
    echo "============================================"
    echo "  NoteDaemon Interactive Setup"
    echo "============================================"
    echo ""
    print_status "Setup initiated by user: $CALLING_USER"
    echo ""
    
    # Step 1: Build
    if prompt_yes_no "Build the NoteDaemon project?" "Y"; then
        print_status "Building NoteDaemon..."
        
        if [[ ! -f "CMakeLists.txt" ]]; then
            print_error "CMakeLists.txt not found. Are you in the project directory?"
            exit 1
        fi
        
        mkdir -p build
        cd build
        
        print_status "Running CMake configuration..."
        cmake -DCMAKE_BUILD_TYPE=Release .. > /dev/null
        
        print_status "Compiling (using $(nproc) cores)..."
        make -j$(nproc)
        
        print_success "Build complete"
        
        if [[ ! -f "note-daemon" ]]; then
            print_error "Build failed: note-daemon binary not found"
            exit 1
        fi
        
        cd ..
    else
        print_warning "Skipping build step"
        
        if [[ ! -f "build/note-daemon" ]]; then
            print_error "note-daemon binary not found in build/ directory"
            print_error "You must build the project first or run with build enabled"
            exit 1
        fi
    fi
    
    echo ""
    
    # Step 2: Create system group and user
    if prompt_yes_no "Create netnotes system user and group?" "Y"; then
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
    else
        print_warning "Skipping user/group creation"
        
        if ! getent group netnotes >/dev/null; then
            print_error "netnotes group does not exist and is required"
            exit 1
        fi
    fi
    
    echo ""
    
    # Step 3: Create runtime/data directories
    if prompt_yes_no "Create runtime and data directories?" "Y"; then
        print_status "Creating runtime directories..."
        mkdir -p /var/lib/netnotes /run/netnotes
        chown netnotes:netnotes /var/lib/netnotes /run/netnotes
        chmod 0750 /var/lib/netnotes /run/netnotes
        print_success "Runtime directories created"
    else
        print_warning "Skipping directory creation"
    fi
    
    echo ""
    
    # Step 4: Install binary
    if prompt_yes_no "Install note-daemon binary to /usr/local/bin?" "Y"; then
        print_status "Installing note-daemon binary..."
        
        if [[ ! -f "build/note-daemon" ]]; then
            print_error "Binary not found at build/note-daemon"
            exit 1
        fi
        
        install -m 0755 -o root -g netnotes build/note-daemon /usr/local/bin/note-daemon
        print_success "Binary installed to /usr/local/bin/note-daemon"
    else
        print_warning "Skipping binary installation"
    fi
    
    echo ""
    
    # Step 5: Install udev rules
    if prompt_yes_no "Install udev rules?" "Y"; then
        print_status "Installing udev rules..."
        
        if [[ ! -f "99-netnotes.rules" ]]; then
            print_error "99-netnotes.rules not found"
            exit 1
        fi
        
        cp 99-netnotes.rules /etc/udev/rules.d/99-netnotes.rules
        chmod 0644 /etc/udev/rules.d/99-netnotes.rules
        print_success "Udev rules installed"
        
        if prompt_yes_no "Reload udev rules now (no restart required)?" "Y"; then
            print_status "Reloading udev rules..."
            udevadm control --reload-rules
            udevadm trigger
            print_success "Udev rules reloaded"
        else
            print_warning "Udev rules will take effect after system restart"
        fi
    else
        print_warning "Skipping udev rules installation"
    fi
    
    echo ""
    
    # Step 6: Install systemd service
    if prompt_yes_no "Install systemd service?" "Y"; then
        print_status "Installing systemd service..."
        
        if [[ ! -f "note-daemon.service" ]]; then
            print_error "note-daemon.service not found"
            exit 1
        fi
        
        cp note-daemon.service /etc/systemd/system/note-daemon.service
        chmod 0644 /etc/systemd/system/note-daemon.service
        systemctl daemon-reload
        print_success "Systemd service installed"
        
        if prompt_yes_no "Enable service to start on boot?" "Y"; then
            systemctl enable note-daemon.service
            print_success "Service enabled"
        fi
        
        if prompt_yes_no "Start service now?" "Y"; then
            print_status "Starting note-daemon service..."
            systemctl start note-daemon.service
            sleep 2
            
            if systemctl is-active --quiet note-daemon.service; then
                print_success "Service started successfully"
                systemctl status note-daemon.service --no-pager | head -10
            else
                print_error "Service failed to start"
                systemctl status note-daemon.service --no-pager || true
            fi
        fi
    else
        print_warning "Skipping systemd service installation"
    fi
    
    echo ""
    
    # Step 7: Apply group membership without restart
    if prompt_yes_no "Refresh group cache (allows immediate group recognition)?" "Y"; then
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
    else
        print_warning "Skipping group cache refresh"
    fi
    
    echo ""
    
    # Step 8: User group management
    echo "============================================"
    print_status "User Group Configuration"
    echo "============================================"
    echo ""
    
    # Ask about adding the calling user
    if [[ "$CALLING_USER" != "root" ]]; then
        if prompt_yes_no "Add user '$CALLING_USER' to the netnotes group?" "Y"; then
            usermod -a -G netnotes "$CALLING_USER"
            print_success "User '$CALLING_USER' added to netnotes group"
            print_warning "User '$CALLING_USER' must log out and back in for group membership to take effect"
            
            # Provide immediate access command
            echo ""
            print_status "To apply group membership immediately in current shell, run:"
            echo -e "${GREEN}    newgrp netnotes${NC}"
            echo ""
        fi
    fi
    
    # Ask about adding another user
    if prompt_yes_no "Add another user to the netnotes group (for client app)?" "N"; then
        read -p "Enter username to add: " username
        
        if [[ -z "$username" ]]; then
            print_warning "No username provided, skipping"
        elif id "$username" >/dev/null 2>&1; then
            usermod -a -G netnotes "$username"
            print_success "User '$username' added to netnotes group"
            print_warning "User '$username' must log out and back in for group membership to take effect"
        else
            print_error "User '$username' does not exist"
        fi
    fi
    
    # Step 9: View permissions
    echo ""
    if prompt_yes_no "View device permissions?" "N"; then
        echo ""
        print_status "USB device permissions:"
        ls -l /dev/bus/usb/*/* 2>/dev/null | head -20 || echo "  No USB devices found"
        
        echo ""
        print_status "HID device permissions:"
        ls -l /dev/hidraw* 2>/dev/null || echo "  No HID devices found"
    fi
    
    # Final summary
    echo ""
    echo "============================================"
    print_success "NoteDaemon Setup Complete!"
    echo "============================================"
    echo ""
    echo "Installation Summary:"
    echo "  • Binary:         /usr/local/bin/note-daemon"
    echo "  • Service:        note-daemon.service"
    echo "  • Udev Rules:     /etc/udev/rules.d/99-netnotes.rules"
    echo "  • User/Group:     netnotes:netnotes"
    echo "  • Data Directory: /var/lib/netnotes"
    echo ""
    
    if systemctl list-unit-files note-daemon.service >/dev/null 2>&1; then
        echo "Service Status:"
        if systemctl is-active --quiet note-daemon.service; then
            echo -e "  ${GREEN}● Running${NC}"
        else
            echo -e "  ${YELLOW}○ Stopped${NC}"
        fi
        echo ""
        echo "Useful Commands:"
        echo "  • Check status:   systemctl status note-daemon"
        echo "  • View logs:      journalctl -u note-daemon -f"
        echo "  • Restart:        systemctl restart note-daemon"
        echo "  • Stop:           systemctl stop note-daemon"
        echo ""
    fi
    
    print_success "Setup complete!"
}

# Run main function
main "$@"