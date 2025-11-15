#!/bin/bash
# Netnotes Daemon Uninstall Script
# Usage: sudo ./uninstall-netnotes.sh
set -e

# Stop and disable systemd service
systemctl stop note-daemon.service || true
systemctl disable note-daemon.service || true
rm -f /etc/systemd/system/note-daemon.service
systemctl daemon-reload

# Remove udev rule
rm -f /etc/udev/rules.d/99-netnotes.rules
udevadm control --reload-rules
udevadm trigger

# Remove runtime/data directories
rm -rf /var/lib/netnotes /run/netnotes /var/run/netnotes


# Remove netnotes user
if id netnotes >/dev/null 2>&1; then
    userdel netnotes
fi

# Prompt to remove all users from netnotes group before deleting group
if getent group netnotes >/dev/null; then
    members=$(getent group netnotes | awk -F: '{print $4}')
    if [ -n "$members" ]; then
        echo "The netnotes group has members: $members"
        read -p "Do you want to remove all users from the netnotes group and delete the group? [y/N]: " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            IFS=',' read -ra users <<< "$members"
            for u in "${users[@]}"; do
                if id "$u" >/dev/null 2>&1; then
                    deluser "$u" netnotes
                fi
            done
            groupdel netnotes
            echo "All users removed and group deleted."
        else
            echo "Group netnotes not deleted. Manual cleanup may be required."
        fi
    else
        groupdel netnotes
        echo "Group netnotes deleted."
    fi
fi

echo "Netnotes uninstall complete."
