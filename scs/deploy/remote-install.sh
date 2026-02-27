#!/bin/bash
# NAIS SCS Remote Install Script
# This script runs on the remote server with sudo

set -e

SERVICE_NAME="nais-scs"
BIN_PATH="/usr/local/bin/nais-scs"
CONFIG_DIR="/etc/nais-scs"
DATA_DIR="/var/lib/nais-scs"
STAGING_DIR="/tmp/nais-scs-deploy"

echo "=== NAIS SCS Remote Install ==="

# Check we have the staging files
if [[ ! -d "$STAGING_DIR" ]]; then
    echo "ERROR: Staging directory not found: $STAGING_DIR"
    exit 1
fi

# Determine if first install (check both binary AND service file)
FIRST_INSTALL=false
if [[ ! -f "$BIN_PATH" ]] || [[ ! -f "/etc/systemd/system/nais-scs.service" ]]; then
    FIRST_INSTALL=true
    echo "First time installation"
else
    echo "Upgrade installation"
fi

# Stop service if running
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo "Stopping service..."
    systemctl stop "$SERVICE_NAME"
fi

# Install binary
echo "Installing binary..."
cp "$STAGING_DIR/nais-scs" "$BIN_PATH"
chmod 755 "$BIN_PATH"

# First time setup
if $FIRST_INSTALL; then
    echo "Running first-time setup..."
    
    # Create service user
    if ! id "$SERVICE_NAME" &>/dev/null; then
        echo "Creating service user..."
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_NAME"
    fi
    
    # Create directories
    echo "Creating directories..."
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    chown -R "$SERVICE_NAME:$SERVICE_NAME" "$DATA_DIR"
    chmod 750 "$DATA_DIR"
    
    # Install config
    if [[ -f "$STAGING_DIR/config.toml" ]]; then
        echo "Installing config..."
        cp "$STAGING_DIR/config.toml" "$CONFIG_DIR/config.toml"
        chown root:"$SERVICE_NAME" "$CONFIG_DIR/config.toml"
        chmod 640 "$CONFIG_DIR/config.toml"
    fi
    
    # Install systemd service
    if [[ -f "$STAGING_DIR/nais-scs.service" ]]; then
        echo "Installing systemd service..."
        cp "$STAGING_DIR/nais-scs.service" /etc/systemd/system/
        chmod 644 /etc/systemd/system/nais-scs.service
        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME"
    fi
else
    # Update config if provided and requested
    if [[ -f "$STAGING_DIR/config.toml" && -f "$STAGING_DIR/.update-config" ]]; then
        echo "Updating config..."
        cp "$STAGING_DIR/config.toml" "$CONFIG_DIR/config.toml"
        chown root:"$SERVICE_NAME" "$CONFIG_DIR/config.toml"
        chmod 640 "$CONFIG_DIR/config.toml"
    fi
fi

# Start service
echo "Starting service..."
systemctl start "$SERVICE_NAME"

# Cleanup staging
rm -rf "$STAGING_DIR"

# Show status
echo ""
echo "=== Installation Complete ==="
systemctl status "$SERVICE_NAME" --no-pager || true
