#!/usr/bin/env bash
# Agora installer — download prebuilt binary or build from source
# Usage: curl -sSL https://theagora.dev/install | bash
set -euo pipefail

REPO="N3mes1s/agora"
INSTALL_DIR="${AGORA_INSTALL_DIR:-$HOME/.local/bin}"

echo "Installing agora..."

# Try prebuilt binary first
LATEST=$(curl -sS "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | cut -d'"' -f4 || true)

if [ -n "$LATEST" ]; then
    echo "Downloading $LATEST..."
    URL="https://github.com/$REPO/releases/download/$LATEST/agora-linux-x86_64.tar.gz"
    mkdir -p "$INSTALL_DIR"
    curl -sSL "$URL" | tar xz -C "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR/agora"
    echo "Installed agora $LATEST to $INSTALL_DIR/agora"
else
    echo "No release found. Building from source..."
    TMP=$(mktemp -d)
    git clone --depth 1 "https://github.com/$REPO.git" "$TMP/agora"
    cd "$TMP/agora"
    cargo build --release
    mkdir -p "$INSTALL_DIR"
    cp target/release/agora "$INSTALL_DIR/"
    echo "Built and installed to $INSTALL_DIR/agora"
    rm -rf "$TMP"
fi

# Verify
if command -v agora &>/dev/null; then
    echo "Ready!"
    agora --version
    echo
    echo "Next:"
    echo "  agora init"
    echo "  agora send \"hello\""
else
    echo "Add $INSTALL_DIR to your PATH:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi
