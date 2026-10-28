#!/usr/bin/env bash
#
# Marsadix - external tools installer (Linux/macOS)
# Usage: sudo ./install-tools.sh
#
set -uo pipefail

GREEN="\033[1;32m"
BLUE="\033[1;34m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"

FAILED=()

log_info() { echo -e "${BLUE}[*] $1${RESET}"; }
log_ok()   { echo -e "${GREEN}[+] $1${RESET}"; }
log_warn() { echo -e "${YELLOW}[!] $1${RESET}"; }
log_err()  { echo -e "${RED}[-] $1${RESET}"; }

echo -e "${BLUE}[*] Starting Marsadix Dependencies Installer...${RESET}"
INSTALL_TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/marsadix-install.XXXXXX") || exit 1
trap 'rm -rf "$INSTALL_TMP_DIR"' EXIT

# 1. Root check
if [ "$EUID" -ne 0 ]; then
  log_err "Please run this script with sudo: sudo ./install-tools.sh"
  exit 1
fi

# Where the binaries go. The Dockerfile passes /usr/local/bin explicitly;
# local runs use the same default. The old script ignored its argument and
# always wrote to /usr/local/bin, so a custom install dir was silently lost.
INSTALL_DIR="${1:-/usr/local/bin}"
case "$INSTALL_DIR" in
    /*) ;;
    *) log_err "Install directory must be an absolute path: $INSTALL_DIR"; exit 1 ;;
esac
mkdir -p "$INSTALL_DIR"
export PATH="$PATH:$INSTALL_DIR"

# 2. Detect package manager instead of assuming apt
if command -v apt &>/dev/null; then
    PKG_INSTALL="apt install -y"
    PKG_UPDATE="apt update -y"
elif command -v dnf &>/dev/null; then
    PKG_INSTALL="dnf install -y"
    PKG_UPDATE="dnf check-update || true"
elif command -v pacman &>/dev/null; then
    PKG_INSTALL="pacman -S --noconfirm"
    PKG_UPDATE="pacman -Sy"
elif command -v brew &>/dev/null; then
    PKG_INSTALL="brew install"
    PKG_UPDATE="brew update"
else
    log_err "No supported package manager found (apt/dnf/pacman/brew). Install base packages manually: curl wget git unzip python3 golang"
    exit 1
fi

log_info "Updating system and installing base prerequisites..."
$PKG_UPDATE
$PKG_INSTALL curl wget git unzip file python3 python3-venv python3-pip nmap || log_warn "Some base packages may have failed to install"

# 3. Go: make sure a recent-enough version is present.
MIN_GO_MINOR=21
GO_TARBALL_VERSION="1.23.0"

need_fresh_go() {
    command -v go &>/dev/null || return 0
    local ver major minor
    ver=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | tr -d 'go')
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    [ "$major" -lt 1 ] && return 0
    [ "$major" -eq 1 ] && [ "$minor" -lt "$MIN_GO_MINOR" ] && return 0
    return 1
}

if need_fresh_go; then
    log_info "Installing Golang ${GO_TARBALL_VERSION} from go.dev..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) GOARCH="amd64" ;;
        aarch64|arm64) GOARCH="arm64" ;;
        *) log_err "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    GO_TARBALL="$INSTALL_TMP_DIR/go.tar.gz"
    if curl -fsSL "https://go.dev/dl/go${GO_TARBALL_VERSION}.${OS_NAME}-${GOARCH}.tar.gz" -o "$GO_TARBALL"; then
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "$GO_TARBALL"
    else
        log_err "Failed to download Go tarball."
    fi
else
    log_info "Golang is already installed and recent enough ($(go version))."
fi

export PATH=$PATH:/usr/local/go/bin

REAL_USER="${SUDO_USER:-$USER}"
# No `eval echo "~$REAL_USER"`: SUDO_USER is environment-controlled, and eval
# would execute shell metacharacters in it. Read the passwd entry instead.
REAL_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6)
[ -n "$REAL_HOME" ] || REAL_HOME="$HOME"
export GOPATH="$REAL_HOME/go"
export PATH=$PATH:$GOPATH/bin

if ! command -v go &>/dev/null; then
    log_err "Go installation failed - aborting."
    exit 1
fi

# 4. Persist PATH for the real (non-root) user
for RC in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
    [ -f "$RC" ] || continue
    grep -qF '/usr/local/go/bin' "$RC" 2>/dev/null || \
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$RC"
done

# 5. Install each Go-based tool
install_go_tool() {
    local name="$1" pkg="$2" logfile="/tmp/marsadix_${1}.log"
    log_info "Installing $name..."
    if [ -n "${SUDO_USER:-}" ] && command -v sudo >/dev/null 2>&1; then
        sudo -u "$REAL_USER" env PATH="$PATH" GOPATH="$GOPATH" go install -v "$pkg@latest" &>"$logfile"
    else
        env PATH="$PATH" GOPATH="$GOPATH" go install -v "$pkg@latest" &>"$logfile"
    fi
    if [ "$?" -eq 0 ]; then
        local bin="$GOPATH/bin/$name"
        if [ -x "$bin" ]; then
            cp -f "$bin" "$INSTALL_DIR/" && { log_ok "$name installed."; return; }
        fi
    fi
    FAILED+=("$name")
    log_err "$name failed to install (see $logfile)."
}

install_go_tool subfinder   github.com/projectdiscovery/subfinder/v2/cmd/subfinder
install_go_tool assetfinder github.com/tomnomnom/assetfinder
install_go_tool chaos       github.com/projectdiscovery/chaos-client/cmd/chaos
install_go_tool httpx       github.com/projectdiscovery/httpx/cmd/httpx
install_go_tool katana      github.com/projectdiscovery/katana/cmd/katana
install_go_tool dnsx        github.com/projectdiscovery/dnsx/cmd/dnsx
install_go_tool naabu       github.com/projectdiscovery/naabu/v2/cmd/naabu
install_go_tool nuclei      github.com/projectdiscovery/nuclei/v3/cmd/nuclei
install_go_tool gau         github.com/lc/gau/v2/cmd/gau
install_go_tool ffuf        github.com/ffuf/ffuf/v2
install_go_tool alterx      github.com/projectdiscovery/alterx/cmd/alterx
install_go_tool massdns     github.com/blechschmidt/massdns/bin/massdns
install_go_tool puredns     github.com/d3mondev/puredns/v2/cmd/puredns
# `apt install amass` does not exist on Debian/Ubuntu (it is a Kali package),
# which made the Docker build fail its tool check. Install it like the other
# Go tools instead of relying on the distro package manager.
install_go_tool amass       github.com/owasp-amass/amass/v4/cmd/amass

# 7. Findomain
log_info "Installing Findomain..."
if ! command -v findomain &>/dev/null; then
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) FD_ASSET="findomain-linux.zip" ;;
        aarch64|arm64) FD_ASSET="findomain-aarch64.zip" ;;
        *) FD_ASSET="" ;;
    esac
    FD_OK=0
    FINDOMAIN_ZIP="$INSTALL_TMP_DIR/findomain.zip"
    FINDOMAIN_EXTRACT="$INSTALL_TMP_DIR/findomain_extract"
    if [ -n "$FD_ASSET" ] && curl -fsSL -o "$FINDOMAIN_ZIP" \
        "https://github.com/Findomain/Findomain/releases/latest/download/${FD_ASSET}"; then
        if file "$FINDOMAIN_ZIP" | grep -qi "Zip archive"; then
            mkdir -p "$FINDOMAIN_EXTRACT"
            if unzip -q "$FINDOMAIN_ZIP" -d "$FINDOMAIN_EXTRACT" && \
               [ -x "$FINDOMAIN_EXTRACT/findomain" -o -f "$FINDOMAIN_EXTRACT/findomain" ]; then
                chmod +x "$FINDOMAIN_EXTRACT/findomain"
                mv "$FINDOMAIN_EXTRACT/findomain" "$INSTALL_DIR/findomain"
                FD_OK=1
            fi
        fi
    fi
    [ "$FD_OK" -eq 1 ] && log_ok "findomain installed." || { FAILED+=("findomain"); log_err "findomain failed."; }
else
    log_info "findomain is already installed."
fi

# 8. Final report
echo ""
echo -e "${BLUE}=== Installation report ===${RESET}"
for t in subfinder assetfinder chaos httpx katana dnsx naabu nuclei gau ffuf alterx massdns puredns amass findomain nmap; do
    if command -v "$t" &>/dev/null; then
        echo -e "  ${GREEN}[OK]${RESET}    $t"
    else
        echo -e "  ${RED}[FAIL]${RESET} $t"
    fi
done

echo ""
if [ "${#FAILED[@]}" -eq 0 ]; then
    log_ok "All external tools installed successfully!"
else
    log_warn "Some tools failed: ${FAILED[*]}. Check logs in /tmp/marsadix_*.log"
fi

log_info "Open a NEW terminal (or run: source ${REAL_HOME}/.bashrc) so PATH changes take effect."
if [ "${#FAILED[@]}" -gt 0 ]; then
    log_err "Installer finished with missing tools: ${FAILED[*]}"
    exit 1
fi
