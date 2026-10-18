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

# 1. Root check
if [ "$EUID" -ne 0 ]; then
  log_err "Please run this script with sudo: sudo ./install-tools.sh"
  exit 1
fi

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
$PKG_INSTALL curl wget git unzip file python3 python3-venv python3-pip || log_warn "Some base packages may have failed to install"

# 3. Go: make sure a recent-enough version is present.
#    Distro packages (apt's golang-go) are often too old for modern `go install pkg@latest`.
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
    log_info "Installing Golang ${GO_TARBALL_VERSION} from go.dev (distro package is too old or missing)..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) GOARCH="amd64" ;;
        aarch64|arm64) GOARCH="arm64" ;;
        *) log_err "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    if curl -fsSL "https://go.dev/dl/go${GO_TARBALL_VERSION}.${OS_NAME}-${GOARCH}.tar.gz" -o /tmp/go.tar.gz; then
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
    else
        log_err "Failed to download Go tarball."
    fi
else
    log_info "Golang is already installed and recent enough ($(go version))."
fi

export PATH=$PATH:/usr/local/go/bin

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")
export GOPATH="$REAL_HOME/go"
export PATH=$PATH:$GOPATH/bin

if ! command -v go &>/dev/null; then
    log_err "Go installation failed - aborting, Go-based tools cannot be installed."
    exit 1
fi

# 4. Persist PATH for the real (non-root) user, not just this shell
for RC in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
    [ -f "$RC" ] || continue
    grep -qF '/usr/local/go/bin' "$RC" 2>/dev/null || \
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$RC"
done

# 5. Install each Go-based tool and verify it actually landed, instead of
#    hiding failures behind `cp ... 2>/dev/null`.
install_go_tool() {
    local name="$1" pkg="$2" logfile="/tmp/marsadix_${1}.log"
    log_info "Installing $name..."
    if sudo -u "$REAL_USER" env PATH="$PATH" GOPATH="$GOPATH" go install -v "$pkg@latest" &>"$logfile"; then
        local bin="$GOPATH/bin/$name"
        if [ -x "$bin" ]; then
            cp -f "$bin" /usr/local/bin/ && { log_ok "$name installed."; return; }
        fi
    fi
    FAILED+=("$name")
    log_err "$name failed to install (see $logfile)."
}

install_go_tool subfinder   github.com/projectdiscovery/subfinder/v2/cmd/subfinder
install_go_tool assetfinder github.com/tomnomnom/assetfinder
install_go_tool chaos       github.com/projectdiscovery/chaos-client/cmd/chaos
install_go_tool httpx       github.com/projectdiscovery/httpx/cmd/httpx
install_go_tool dnsx        github.com/projectdiscovery/dnsx/cmd/dnsx
install_go_tool naabu       github.com/projectdiscovery/naabu/v2/cmd/naabu
install_go_tool nuclei      github.com/projectdiscovery/nuclei/v3/cmd/nuclei
install_go_tool gau         github.com/lc/gau/v2/cmd/gau
install_go_tool ffuf        github.com/ffuf/ffuf/v2

# 6. Amass via the system package manager
log_info "Installing Amass..."
if $PKG_INSTALL amass &>/tmp/marsadix_amass.log && command -v amass &>/dev/null; then
    log_ok "amass installed."
else
    FAILED+=("amass")
    log_err "amass failed via package manager (see /tmp/marsadix_amass.log)."
    log_warn "Fallback: go install -v github.com/owasp-amass/amass/v4/...@master"
fi

# 7. Findomain - current releases ship a .zip archive (not a raw binary),
#    so download it, verify it's actually a zip, then unzip - instead of
#    moving the downloaded file straight into /usr/local/bin and trusting
#    it blindly (a failed download silently returns an HTML/JSON error
#    page, which `mv`-ing directly turns into a broken "ASCII text" binary).
log_info "Installing Findomain..."
if ! command -v findomain &>/dev/null; then
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) FD_ASSET="findomain-linux.zip" ;;
        aarch64|arm64) FD_ASSET="findomain-aarch64.zip" ;;
        armv7l) FD_ASSET="findomain-armv7.zip" ;;
        i386|i686) FD_ASSET="findomain-linux-i386.zip" ;;
        *) FD_ASSET="" ;;
    esac
    FD_OK=0
    if [ -n "$FD_ASSET" ] && curl -fsSL -o /tmp/findomain.zip \
        "https://github.com/Findomain/Findomain/releases/latest/download/${FD_ASSET}"; then
        if file /tmp/findomain.zip | grep -qi "Zip archive"; then
            rm -rf /tmp/findomain_extract
            mkdir -p /tmp/findomain_extract
            if unzip -q /tmp/findomain.zip -d /tmp/findomain_extract && \
               [ -x /tmp/findomain_extract/findomain -o -f /tmp/findomain_extract/findomain ]; then
                chmod +x /tmp/findomain_extract/findomain
                mv /tmp/findomain_extract/findomain /usr/local/bin/findomain
                FD_OK=1
            fi
            rm -rf /tmp/findomain_extract
        else
            log_err "Downloaded findomain asset is not a zip - GitHub asset naming may have changed again."
        fi
        rm -f /tmp/findomain.zip
    fi
    if [ "$FD_OK" -eq 1 ]; then
        log_ok "findomain installed."
    else
        FAILED+=("findomain")
        log_err "findomain download/extract failed for architecture ($ARCH)."
    fi
else
    log_info "findomain is already installed."
fi

# 8. Final report - verify every tool actually resolves on PATH,
#    instead of unconditionally printing "installed successfully".
echo ""
echo -e "${BLUE}=== Installation report ===${RESET}"
for t in subfinder assetfinder chaos httpx dnsx naabu nuclei gau ffuf amass findomain; do
    if command -v "$t" &>/dev/null; then
        echo -e "  ${GREEN}[OK]${RESET}   $t"
    else
        echo -e "  ${RED}[FAIL]${RESET} $t"
    fi
done

echo ""
if [ "${#FAILED[@]}" -eq 0 ]; then
    log_ok "All external tools installed successfully!"
else
    log_warn "Some tools failed: ${FAILED[*]}. Check the logs in /tmp/marsadix_*.log"
fi

log_info "Open a NEW terminal (or run: source ${REAL_HOME}/.bashrc) so PATH changes take effect."
