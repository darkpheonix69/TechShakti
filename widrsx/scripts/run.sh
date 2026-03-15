#!/usr/bin/env bash

# WIDRS-X launcher script
# Enables monitor mode on the specified interface (default wlan1) and runs the backend.
# Usage: sudo ./run.sh [interface]

set -euo pipefail

# monitor interface for packet capture (must support monitor mode)
MONITOR_IFACE="${1:-wlan1}"
# managed interface for internet (kept up, not switched to monitor mode)
MANAGED_IFACE="${2:-wlan0}"

set_monitor_mode() {
    echo "[*] Creating monitor interface from $MONITOR_IFACE..."
    sudo iw dev "$MONITOR_IFACE" interface add "${MONITOR_IFACE}_monitor" type monitor
    MONITOR_IFACE="${MONITOR_IFACE}_monitor"
    sudo ifconfig "$MONITOR_IFACE" up
}

set_managed_mode() {
    echo "[*] Removing monitor interface $MONITOR_IFACE..."
    sudo iw dev "$MONITOR_IFACE" del
    MONITOR_IFACE="${MONITOR_IFACE%_monitor}"
    echo "[*] Ensuring managed interface ($MANAGED_IFACE) is up..."
    if sudo iw dev "$MANAGED_IFACE" >/dev/null 2>&1; then
        sudo ifconfig "$MANAGED_IFACE" up
        echo "[*] Reconnecting managed interface via NetworkManager..."
        sudo nmcli device connect "$MANAGED_IFACE" || true
    else
        echo "[*] Managed interface $MANAGED_IFACE not found, trying to reconnect $MONITOR_IFACE..."
        sudo nmcli device connect "$MONITOR_IFACE" || true
    fi
    sudo nmcli networking on || true
}

cleanup() {
    set_managed_mode
    echo "[*] Deploying Blockchain Contract..."

    cd /home/bhairavam/Downloads/Shakti-main-AI/WIDRS-X-Blockchain || exit
    npx hardhat run scripts/deploy.ts
}

trap cleanup EXIT

set_monitor_mode

echo "[WIDRS-X] Setting monitor interface to channel 6 (adjust if needed)..."
sudo iwconfig "${MONITOR_IFACE}" channel 6

echo "[WIDRS-X] Starting backend..."
cd "$(dirname "$0")/.."
python3 main.py --interface "${MONITOR_IFACE}"

# cleanup will run on exit via trap
