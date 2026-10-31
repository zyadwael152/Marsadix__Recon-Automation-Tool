#!/usr/bin/env bash
# Install the external tools used by the Member 2 web-surface extension.
#
# Usage:
#   ./scripts/install_member2_tools.sh
#   MARSADIX_TOOLS_DIR="$HOME/.local/bin" ./scripts/install_member2_tools.sh
#
# The script installs the web/archive tools plus Nuclei for the A1-A4 ASM
# checks. Existing files in the target directory are left alone. Nuclei is
# optional at runtime: a missing binary is reported as a skipped/missing tool.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="${MARSADIX_TOOLS_DIR:-$ROOT/.tools/bin}"
GOPATH_BIN="${GOPATH:-$HOME/go}/bin"

command -v go >/dev/null 2>&1 || {
  echo "error: Go is required (https://go.dev/dl/)" >&2
  exit 1
}

mkdir -p "$TOOLS_DIR" "$GOPATH_BIN"
export GOBIN="$TOOLS_DIR"

echo "[*] Installing Member 2 tools into $TOOLS_DIR"
echo "[*] Go: $(go version)"

install_go() {
  local label="$1" module="$2"
  echo "[*] $label"
  GOBIN="$TOOLS_DIR" go install "$module"
}

# Pinned where a stable tag is known; ProjectDiscovery tools use latest because
# their release tags change frequently and the extension validates flags at
# runtime through `marsadix-member2 doctor`.
install_go "gau 2.2.4" "github.com/lc/gau/v2/cmd/gau@v2.2.4"
install_go "waybackurls" "github.com/tomnomnom/waybackurls@latest"
install_go "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go "ProjectDiscovery httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go "katana" "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

echo
echo "[+] Installed binaries:"
for tool in httpx katana gau subfinder dnsx waybackurls nuclei; do
  if [ -x "$TOOLS_DIR/$tool" ]; then
    echo "    $TOOLS_DIR/$tool"
  else
    echo "    MISSING $tool" >&2
  fi
done

echo
echo "Add the directory to PATH for this shell:"
echo "    export PATH=\"$TOOLS_DIR:\$PATH\""
echo
echo "Then verify:"
echo "    python -m marsadix_member2 doctor"
