#!/bin/sh
# vibescan — Universal Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Armur-Ai/vibescan/main/scripts/install.sh | sh

set -e

REPO="Armur-Ai/vibescan"
INSTALL_DIR="${VIBESCAN_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="vibescan"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { printf "${CYAN}→${NC} %s\n" "$1"; }
success() { printf "${GREEN}✓${NC} %s\n" "$1"; }
error() { printf "${RED}✗${NC} %s\n" "$1"; exit 1; }

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) error "Unsupported OS: $(uname -s)" ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac
}

# Download helper
fetch() {
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
    elif command -v wget > /dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        error "curl or wget required for installation"
    fi
}

# Get latest release version
get_latest_version() {
    local tmpfile
    tmpfile=$(mktemp)
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            -H "User-Agent: vibescan-installer" > "$tmpfile" 2>/dev/null
    elif command -v wget > /dev/null 2>&1; then
        wget -qO "$tmpfile" "https://api.github.com/repos/${REPO}/releases/latest" \
            --header="User-Agent: vibescan-installer" 2>/dev/null
    else
        error "curl or wget required for installation"
    fi
    grep '"tag_name"' "$tmpfile" | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
    rm -f "$tmpfile"
}

main() {
    OS=$(detect_os)
    ARCH=$(detect_arch)
    VERSION=$(get_latest_version)

    if [ -z "$VERSION" ]; then
        error "Could not determine latest version. Check https://github.com/${REPO}/releases"
    fi

    TAG=$(echo "$VERSION" | sed 's/^v//')
    EXT="tar.gz"
    if [ "$OS" = "windows" ]; then
        EXT="zip"
        BINARY_NAME="vibescan.exe"
    fi

    FILENAME="vibescan_${TAG}_${OS}_${ARCH}.${EXT}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"

    echo ""
    info "vibescan installer"
    info "Version:  ${VERSION}"
    info "Platform: ${OS}/${ARCH}"
    echo ""

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    info "Downloading ${FILENAME}..."
    fetch "$URL" "${TMP_DIR}/${FILENAME}"

    # Verify checksum
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
    if fetch "$CHECKSUM_URL" "${TMP_DIR}/checksums.txt" 2>/dev/null; then
        EXPECTED=$(grep "$FILENAME" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
        if [ -n "$EXPECTED" ]; then
            if command -v sha256sum > /dev/null 2>&1; then
                ACTUAL=$(sha256sum "${TMP_DIR}/${FILENAME}" | awk '{print $1}')
            elif command -v shasum > /dev/null 2>&1; then
                ACTUAL=$(shasum -a 256 "${TMP_DIR}/${FILENAME}" | awk '{print $1}')
            fi
            if [ -n "$ACTUAL" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
                error "Checksum mismatch! Expected: ${EXPECTED}, Got: ${ACTUAL}"
            fi
            success "Checksum verified"
        fi
    fi

    info "Extracting..."
    if [ "$EXT" = "tar.gz" ]; then
        tar -xzf "${TMP_DIR}/${FILENAME}" -C "$TMP_DIR"
    else
        unzip -q "${TMP_DIR}/${FILENAME}" -d "$TMP_DIR"
    fi

    # Install binary
    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        info "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    echo ""
    success "vibescan ${VERSION} installed to ${INSTALL_DIR}/${BINARY_NAME}"
    echo ""
    echo "  Get started:"
    echo "    ${CYAN}vibescan run .${NC}        scan current directory"
    echo "    ${CYAN}vibescan doctor${NC}       check tool availability"
    echo "    ${CYAN}vibescan --help${NC}       see all commands"
    echo ""

    # Verify it works
    if command -v vibescan > /dev/null 2>&1; then
        success "Installation verified — vibescan is in your PATH"
    else
        echo "  ${RED}Note:${NC} ${INSTALL_DIR} may not be in your PATH."
        echo "  Add it: export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi
}

main
