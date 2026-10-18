#!/usr/bin/env bash
#
# Marsadix - one-shot project setup.
# Run this ONCE right after `git clone`, from the repo root:
#   chmod +x setup.sh && ./setup.sh
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN="\033[1;32m"
BLUE="\033[1;34m"
RED="\033[1;31m"
RESET="\033[0m"

log_info() { echo -e "${BLUE}[*] $1${RESET}"; }
log_ok()   { echo -e "${GREEN}[+] $1${RESET}"; }
log_err()  { echo -e "${RED}[-] $1${RESET}"; }

# 1. Fix permissions on every script in scripts/, no matter how git checked
#    them out - this is what prevents "Permission denied" after a fresh clone.
log_info "Fixing script permissions..."
find scripts -type f -name "*.sh" -exec chmod +x {} \;

# 2. Install all external recon tools (subfinder, assetfinder, amass,
#    findomain, chaos, httpx, dnsx, naabu, nuclei, gau, ffuf).
if [ "$EUID" -ne 0 ]; then
    log_info "Installing external tools (needs sudo)..."
    sudo ./scripts/install-tools.sh
else
    log_info "Installing external tools..."
    ./scripts/install-tools.sh
fi

# 3. Python virtual environment - created as the invoking user, not root,
#    so later `pip install` / `python -m marsadix` don't fight over file
#    ownership (the actual permission-change headache most people hit).
REAL_USER="${SUDO_USER:-$USER}"
if [ ! -d venv ]; then
    log_info "Creating Python venv..."
    if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$REAL_USER" python3 -m venv venv
    else
        python3 -m venv venv
    fi
else
    log_info "venv already exists, skipping creation."
fi

log_info "Installing Python requirements into venv..."
if [ -f requirements.txt ]; then
    ./venv/bin/pip install --upgrade pip --quiet
    ./venv/bin/pip install -r requirements.txt --quiet
else
    log_err "No requirements.txt found - skipping Python deps."
fi

# 4. Make sure the whole project folder is owned by the real user, not root,
#    even though install-tools.sh needed sudo - this is the exact
#    "permission changed" problem to avoid on the next run.
if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    log_info "Restoring ownership of the project folder to $REAL_USER..."
    chown -R "$REAL_USER":"$REAL_USER" "$SCRIPT_DIR"
fi

# 5. Final verification - confirm every external tool is actually reachable.
echo ""
echo -e "${BLUE}=== Tool check ===${RESET}"
MISSING=0
for t in subfinder assetfinder amass findomain chaos httpx dnsx naabu nuclei gau ffuf; do
    if command -v "$t" &>/dev/null; then
        echo -e "  ${GREEN}[OK]${RESET}   $t"
    else
        echo -e "  ${RED}[MISSING]${RESET} $t"
        MISSING=1
    fi
done

echo ""
if [ "$MISSING" -eq 0 ]; then
    log_ok "Setup complete. Every tool is installed."
else
    log_err "Some tools are still missing - open a NEW terminal (PATH may need a refresh) and re-run ./setup.sh"
fi
log_info "Activate the venv with: source venv/bin/activate"
