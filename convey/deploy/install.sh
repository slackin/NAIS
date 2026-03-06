#!/bin/bash
# Convey Images Installation Script
# Run as root or with sudo

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/convey-images"
DATA_DIR="/var/lib/convey-images"
SERVICE_USER="convey-images"
STAGING_DIR="${1:-.}"

echo "=== Convey Images Installer ==="
echo ""

# Create service user if it doesn't exist
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating service user: $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR/images"
mkdir -p "$DATA_DIR/meta"

# Install binary
echo "Installing binary to $INSTALL_DIR..."
cp "$STAGING_DIR/convey-images" "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/convey-images"

# Install config if it doesn't exist
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
    echo "Installing default config to $CONFIG_DIR/config.toml..."
    cp "$STAGING_DIR/config.toml" "$CONFIG_DIR/config.toml"
    chmod 640 "$CONFIG_DIR/config.toml"
    chown root:$SERVICE_USER "$CONFIG_DIR/config.toml"
    echo "  NOTE: Edit $CONFIG_DIR/config.toml to customize your setup"
else
    echo "Config already exists at $CONFIG_DIR/config.toml, skipping..."
    echo "  New config saved as $CONFIG_DIR/config.toml.new"
    cp "$STAGING_DIR/config.toml" "$CONFIG_DIR/config.toml.new"
fi

# Also update config if flag file exists
if [[ -f "$STAGING_DIR/.update-config" ]]; then
    echo "Updating config..."
    cp "$STAGING_DIR/config.toml" "$CONFIG_DIR/config.toml"
    chmod 640 "$CONFIG_DIR/config.toml"
    chown root:$SERVICE_USER "$CONFIG_DIR/config.toml"
fi

# Set data directory permissions
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"

# Install systemd service
echo "Installing systemd service..."
cp "$STAGING_DIR/convey-images.service" /etc/systemd/system/
chmod 644 /etc/systemd/system/convey-images.service

# Reload systemd
systemctl daemon-reload

# Restart service if running
if systemctl is-active --quiet convey-images; then
    echo "Restarting service..."
    systemctl restart convey-images
else
    echo "Starting service..."
    systemctl start convey-images
fi

systemctl enable convey-images

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Service status:"
systemctl status convey-images --no-pager || true
echo ""
echo "Next steps:"
echo "  1. Edit config:     sudo nano $CONFIG_DIR/config.toml"
echo "  2. Check status:    sudo systemctl status convey-images"
echo "  3. View logs:       sudo journalctl -u convey-images -f"
echo ""
echo "Configure Nginx to reverse proxy to 127.0.0.1:8844"
echo ""
