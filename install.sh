#!/bin/bash
#
# RansomWatch Installer
# =====================
#
# 100% LOCAL - NO TELEMETRY - NO PHONE HOME
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            🛡️  RANSOMWATCH INSTALLER                          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  100% Client-Side • No Telemetry • No Phone Home             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Rust/Cargo not found${NC}"
    echo ""
    echo "Install Rust first:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓${NC} Rust found: $(rustc --version)"

# Build the project
echo ""
echo "Building RansomWatch..."
echo ""

cargo build --release

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✓${NC} Build successful"

# Determine install location
INSTALL_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/ransomwatch"

# Ask user
echo ""
echo "Install locations:"
echo "  Binary: ${INSTALL_DIR}/ransomwatch"
echo "  Config: ${CONFIG_DIR}/config.toml"
echo ""
read -p "Continue with installation? [Y/n] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
    echo "Installation cancelled."
    exit 0
fi

# Create directories
mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"

# Copy binary
cp target/release/ransomwatch "${INSTALL_DIR}/ransomwatch"
chmod +x "${INSTALL_DIR}/ransomwatch"

echo -e "${GREEN}✓${NC} Binary installed to ${INSTALL_DIR}/ransomwatch"

# Copy config if it doesn't exist
if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    cp config.example.toml "${CONFIG_DIR}/config.toml"
    echo -e "${GREEN}✓${NC} Config created at ${CONFIG_DIR}/config.toml"
else
    echo -e "${YELLOW}!${NC} Config already exists, not overwriting"
fi

# Check if install dir is in PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo ""
    echo -e "${YELLOW}Warning:${NC} ${INSTALL_DIR} is not in your PATH"
    echo ""
    echo "Add it to your shell profile:"
    echo "  echo 'export PATH=\"\${HOME}/.local/bin:\${PATH}\"' >> ~/.bashrc"
    echo "  source ~/.bashrc"
    echo ""
fi

# Create systemd service (optional)
echo ""
read -p "Create systemd user service for auto-start? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    SYSTEMD_DIR="${HOME}/.config/systemd/user"
    mkdir -p "${SYSTEMD_DIR}"

    cat > "${SYSTEMD_DIR}/ransomwatch.service" << EOF
[Unit]
Description=RansomWatch - Local Ransomware Monitor
Documentation=https://github.com/yourusername/ransomwatch
After=default.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/ransomwatch --config ${CONFIG_DIR}/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

    echo -e "${GREEN}✓${NC} Systemd service created"
    echo ""
    echo "To enable auto-start:"
    echo "  systemctl --user enable ransomwatch"
    echo "  systemctl --user start ransomwatch"
    echo ""
    echo "To check status:"
    echo "  systemctl --user status ransomwatch"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo ""
echo "  1. Edit your config:"
echo "     nano ${CONFIG_DIR}/config.toml"
echo ""
echo "  2. Add paths to monitor in [watch] section"
echo ""
echo "  3. Start monitoring:"
echo "     ransomwatch --config ${CONFIG_DIR}/config.toml"
echo ""
echo "  Or quick start (watches /home):"
echo "     ransomwatch --watch /home"
echo ""
echo "Commands:"
echo "  ransomwatch init       - Create config file"
echo "  ransomwatch check      - Validate config"
echo "  ransomwatch test       - Test alerts"
echo "  ransomwatch entropy    - Analyze file entropy"
echo "  ransomwatch patterns   - Show detection patterns"
echo ""
echo "═══════════════════════════════════════════════════════════════"
