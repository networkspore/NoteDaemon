#!/bin/bash
# Netnotes Daemon Setup Script
# This script configures the system for Netnotes daemon operation.
# Usage: sudo ./setup-netnotes.sh [USERNAME]
set -e

# Check if user specified on command line, otherwise detect current user
if [ -n "$1" ]; then
    USER_TO_ADD="$1"
else
    # Detect the user who ran sudo (SUDO_USER environment variable)
    if [ -n "$SUDO_USER" ]; then
        read -p "Add user '$SUDO_USER' to netnotes group? (y/n): " add_user
        if [[ "$add_user" =~ ^[Yy]$ ]]; then
            USER_TO_ADD="$SUDO_USER"
        else
            USER_TO_ADD=""
        fi
    else
        read -p "Enter username to add to netnotes group (or press Enter to skip): " USER_TO_ADD
    fi
fi

# Create system group and user
if ! getent group netnotes >/dev/null; then
    groupadd --system netnotes
fi
if ! id netnotes >/dev/null 2>&1; then
    useradd --system --no-create-home -g netnotes --shell /usr/sbin/nologin netnotes
fi

# Add user to netnotes group if specified
if [ -n "$USER_TO_ADD" ]; then
    if id "$USER_TO_ADD" >/dev/null 2>&1; then
        usermod -a -G netnotes "$USER_TO_ADD"
        echo "Added user '$USER_TO_ADD' to netnotes group."
    else
        echo "Warning: User '$USER_TO_ADD' does not exist, skipping group addition."
    fi
fi

# Create runtime/data directories
mkdir -p /var/lib/netnotes /run/netnotes
chown netnotes:netnotes /var/lib/netnotes /run/netnotes
chmod 0750 /var/lib/netnotes /run/netnotes

# Install udev rule
cp 99-netnotes.rules /etc/udev/rules.d/99-netnotes.rules
udevadm control --reload-rules
udevadm trigger

# Install systemd service
cp note-daemon.service /etc/systemd/system/note-daemon.service
systemctl daemon-reload
systemctl enable --now note-daemon.service

# Show status and permissions
systemctl status note-daemon.service --no-pager
ls -l /dev/hidraw* /dev/bus/usb/*/* | grep netnotes || true

if [ -n "$USER_TO_ADD" ]; then
    echo ""
    echo "Note: User '$USER_TO_ADD' has been added to the netnotes group."
    echo ""
    echo "To activate the group membership immediately in this shell session, run:"
    echo "  newgrp netnotes"
    echo ""
    echo "Or log out and log back in for all future sessions to have the group membership."
fi

echo "Netnotes setup complete."
