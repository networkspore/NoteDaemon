#!/usr/bin/env bash
# ============================================================
# build-admin.sh — Compile + Install the note_admin CLI tool
# ============================================================
#
# Builds the standalone C admin tool from tools/note_admin.c.
# No cmake required — just gcc and libc.
#
# By default, compiles to build/note_admin AND installs to
# /etc/netnotes/note_admin (the daemon's binary path).
#
# Usage:
#   ./build-admin.sh                    # Build + install
#   ./build-admin.sh --no-install       # Build only (build/note_admin)
#   ./build-admin.sh -o /tmp/note_admin # Custom output only
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/tools/note_admin.c"
OUT="$SCRIPT_DIR/build/note_admin"
NO_INSTALL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-install) NO_INSTALL=true; shift ;;
        -o) OUT="$2"; NO_INSTALL=true; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "  --no-install    Build only, skip install"
            echo "  -o <path>       Custom output path (implies --no-install)"
            echo ""
            echo "Default: compiles to build/note_admin AND installs to"
            echo "         /etc/netnotes/note_admin"
            exit 0 ;;
        *) shift ;;
    esac
done

if [ ! -f "$SRC" ]; then
    echo "Error: $SRC not found"
    exit 1
fi

mkdir -p "$(dirname "$OUT")"

echo "Compiling note_admin..."
gcc -O2 -o "$OUT" "$SRC" -Wall -Wno-unused
echo "  → $OUT ($(du -h "$OUT" | cut -f1))"

# Install to binary path
if [ "$NO_INSTALL" = false ]; then
    DST="/etc/netnotes/note_admin"
    if [ "$EUID" -ne 0 ]; then
        sudo cp "$OUT" "$DST"
        sudo chmod 0755 "$DST"
    else
        cp "$OUT" "$DST"
        chmod 0755 "$DST"
    fi
    echo "  → $DST"
    echo ""
    echo "Try: note_admin ping"
    echo "     note_admin setup <admin-key>"
fi
