#!/bin/bash
# Convey Images Deployment Script
# Builds and deploys to remote server

set -e

# Configuration
REMOTE_USER="nais@convey.pugbot.net"
REMOTE_HOST="t3d"
REMOTE_ALIAS="T3D"
STAGING_DIR="/tmp/convey-images-deploy"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${GREEN}=== Convey Images Deployment ===${NC}"
echo "Target: $REMOTE_USER @ $REMOTE_HOST ($REMOTE_ALIAS)"
echo ""

# Parse arguments
SKIP_BUILD=false
UPDATE_CONFIG=false
RESTART_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --update-config)
            UPDATE_CONFIG=true
            shift
            ;;
        --restart-only)
            RESTART_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --skip-build     Skip building, deploy existing binary"
            echo "  --update-config  Also update config file on server"
            echo "  --restart-only   Only restart the service (no deploy)"
            echo "  -h, --help       Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# SSH/SCP helper functions
ssh_cmd() {
    ssh -l "$REMOTE_USER" "$REMOTE_HOST" "$@"
}

ssh_tty() {
    ssh -t -l "$REMOTE_USER" "$REMOTE_HOST" "$@"
}

scp_cmd() {
    scp -o "User=$REMOTE_USER" "$@"
}

# Restart only mode
if $RESTART_ONLY; then
    echo -e "${YELLOW}Restarting service...${NC}"
    ssh_tty "sudo systemctl restart convey-images && sudo systemctl status convey-images --no-pager"
    exit 0
fi

# Build
if ! $SKIP_BUILD; then
    echo -e "${YELLOW}Building release binary (musl static)...${NC}"
    cd "$PROJECT_ROOT"
    cargo build --release --target x86_64-unknown-linux-musl -p convey-images
    echo -e "${GREEN}Build complete${NC}"
else
    echo -e "${YELLOW}Skipping build (--skip-build)${NC}"
fi

# Check binary exists
BINARY_PATH="$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/convey-images"
if [[ ! -f "$BINARY_PATH" ]]; then
    echo -e "${RED}Binary not found at $BINARY_PATH${NC}"
    exit 1
fi

# Get version info
VERSION=$(grep '^version' "$SCRIPT_DIR/Cargo.toml" | head -1 | cut -d'"' -f2)
echo "Version: $VERSION"

# Check SSH connection
echo -e "${YELLOW}Checking SSH connection...${NC}"
if ! ssh -l "$REMOTE_USER" -o ConnectTimeout=5 "$REMOTE_HOST" "echo 'OK'" 2>/dev/null; then
    echo -e "${RED}Cannot connect to $REMOTE_USER@$REMOTE_HOST${NC}"
    exit 1
fi
echo -e "${GREEN}SSH connection OK${NC}"

# Create local staging directory
echo -e "${YELLOW}Preparing deployment package...${NC}"
LOCAL_STAGING=$(mktemp -d)
trap "rm -rf $LOCAL_STAGING" EXIT

cp "$BINARY_PATH" "$LOCAL_STAGING/convey-images"
cp "$SCRIPT_DIR/deploy/install.sh" "$LOCAL_STAGING/"
cp "$SCRIPT_DIR/deploy/config.toml" "$LOCAL_STAGING/"
cp "$SCRIPT_DIR/deploy/convey-images.service" "$LOCAL_STAGING/"
cp "$SCRIPT_DIR/deploy/nginx-convey.conf" "$LOCAL_STAGING/"

if $UPDATE_CONFIG; then
    touch "$LOCAL_STAGING/.update-config"
fi

# Copy everything to remote staging in one scp call
echo -e "${YELLOW}Copying files to server...${NC}"
ssh_cmd "rm -rf $STAGING_DIR && mkdir -p $STAGING_DIR"
scp_cmd "$LOCAL_STAGING"/* "$REMOTE_HOST:$STAGING_DIR/"

# Run remote install script with sudo (single password prompt)
echo -e "${YELLOW}Running remote install (sudo password required once)...${NC}"
ssh_tty "sudo bash $STAGING_DIR/install.sh $STAGING_DIR"

echo ""
echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo ""
echo "View logs: ssh -l '$REMOTE_USER' $REMOTE_HOST 'sudo journalctl -u convey-images -f'"
echo ""
echo "Don't forget to set up Nginx:"
echo "  1. Copy nginx-convey.conf to /etc/nginx/sites-available/"
echo "  2. ln -s /etc/nginx/sites-available/nginx-convey.conf /etc/nginx/sites-enabled/"
echo "  3. sudo certbot --nginx -d convey.pugbot.net"
echo "  4. sudo nginx -t && sudo systemctl reload nginx"
