#!/bin/bash
# Netnotes Daemon Setup Script
# This script configures the system for Netnotes daemon operation.
# Usage: sudo ./setup-netnotes.sh
set -e

# Create system group and user
if ! getent group netnotes >/dev/null; then
    groupadd --system netnotes
fi
if ! id netnotes >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /var/lib/netnotes -g netnotes --shell /usr/sbin/nologin netnotes
fi

usermod -a -G netnotes netnotes
newgrp netnotes
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

if [ -n "$USER_TO_ADD" ]; then
    echo ""
    echo "Note: User '$USER_TO_ADD' has been added to the netnotes group."
    echo ""
    echo ""
    echo "Or log out and log back in for all future sessions to have the group membership."
fi
echo "Netnotes setup complete."
