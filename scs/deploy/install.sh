#!/bin/bash
# NAIS SCS Installation Script
# Run as root or with sudo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nais-scs"
DATA_DIR="/var/lib/nais-scs"
SERVICE_USER="nais-scs"

echo "=== NAIS SCS Installer ==="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Create service user if it doesn't exist
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating service user: $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"

# Install binary
echo "Installing binary to $INSTALL_DIR..."
cp "$SCRIPT_DIR/nais-scs" "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/nais-scs"

# Install config if it doesn't exist
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
    echo "Installing default config to $CONFIG_DIR/config.toml..."
    cp "$SCRIPT_DIR/config.toml" "$CONFIG_DIR/config.toml"
    chmod 640 "$CONFIG_DIR/config.toml"
    chown root:$SERVICE_USER "$CONFIG_DIR/config.toml"
    echo "  NOTE: Edit $CONFIG_DIR/config.toml to customize your setup"
else
    echo "Config already exists at $CONFIG_DIR/config.toml, skipping..."
    echo "  New config saved as $CONFIG_DIR/config.toml.new"
    cp "$SCRIPT_DIR/config.toml" "$CONFIG_DIR/config.toml.new"
fi

# Set data directory permissions
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"

# Install systemd service
echo "Installing systemd service..."
cp "$SCRIPT_DIR/nais-scs.service" /etc/systemd/system/
chmod 644 /etc/systemd/system/nais-scs.service

# Reload systemd
systemctl daemon-reload

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit config:     sudo nano $CONFIG_DIR/config.toml"
echo "  2. Start service:   sudo systemctl start nais-scs"
echo "  3. Enable on boot:  sudo systemctl enable nais-scs"
echo "  4. Check status:    sudo systemctl status nais-scs"
echo "  5. View logs:       sudo journalctl -u nais-scs -f"
echo ""
echo "Data directory: $DATA_DIR"
echo ""
