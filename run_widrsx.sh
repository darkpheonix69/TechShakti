#!/bin/bash

WIFI_IFACE="wlan1"

set_monitor_mode() {
    echo "[*] Setting $WIFI_IFACE to monitor mode..."
    sudo iw dev $WIFI_IFACE set type monitor
    sudo ifconfig $WIFI_IFACE up
}

set_managed_mode() {
    echo "[*] Reverting $WIFI_IFACE to managed mode..."
    sudo iw dev $WIFI_IFACE set type managed
    sudo ifconfig $WIFI_IFACE up
}

cleanup() {
    set_managed_mode
    echo "[*] Deploying Blockchain Contract..."

    cd /home/bhairavam/Downloads/Shakti-main-AI/WIDRS-X-Blockchain || exit
    npx hardhat run scripts/deploy.ts
}

trap cleanup EXIT

set_monitor_mode

echo "[*] Building Rust firewall TCP server..."
(cd firewall && cargo build --release)

echo "[*] Starting Rust firewall TCP server..."
(cd firewall && ./target/release/widrsx-backend &)  # Background

echo "[*] Starting Flask API server..."
python3 api_server.py &  # Background

echo "[*] Starting Wi-Fi sniffer..."
sudo venv/bin/python3 main.py &  # Background

echo "[*] All services started. Press Ctrl+C to stop everything."
wait