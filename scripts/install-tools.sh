#!/usr/bin/env bash
# Marsadix - installs the external tools on Linux (amd64 / arm64).
#
#   bash scripts/install-tools.sh                 -> installs into ~/.local/bin
#   bash scripts/install-tools.sh /opt/tools/bin  -> installs into a folder you choose
#
# nmap is not included:  sudo apt install nmap
# naabu needs libpcap:   sudo apt install libpcap-dev
# Needs: curl, unzip, tar   (sudo apt install curl unzip)
set -u

INSTALL_DIR="${1:-$HOME/.local/bin}"

[ "$(uname -s)" = "Linux" ] || { echo "This script is for Linux. On macOS use: brew install ... or go install."; exit 1; }
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported CPU: $(uname -m)"; exit 1 ;;
esac
for c in curl unzip tar; do
  command -v "$c" >/dev/null 2>&1 || { echo "Missing '$c'. Install it first: sudo apt install $c"; exit 1; }
done

mkdir -p "$INSTALL_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# tool:github-owner
TOOLS="subfinder:projectdiscovery dnsx:projectdiscovery httpx:projectdiscovery naabu:projectdiscovery katana:projectdiscovery nuclei:projectdiscovery gau:lc ffuf:ffuf"
FAILED=""

latest_tag() {  # $1=owner $2=repo -> e.g. v2.17.0
  curl -fsIL -o /dev/null -w '%{url_effective}' "https://github.com/$1/$2/releases/latest" | sed 's#.*/##'
}

for entry in $TOOLS; do
  t="${entry%%:*}"; owner="${entry##*:}"
  if [ -x "$INSTALL_DIR/$t" ]; then echo "[$t] already there"; continue; fi

  tag="$(latest_tag "$owner" "$t")"
  if [ -z "$tag" ]; then echo "[$t] FAILED: cannot find the latest release"; FAILED="$FAILED $t"; continue; fi
  ver="${tag#v}"

  got=""
  for ext in zip tar.gz; do
    name="${t}_${ver}_linux_${ARCH}.${ext}"
    if curl -fsL -o "$TMP/$name" "https://github.com/$owner/$t/releases/download/$tag/$name"; then got="$TMP/$name"; break; fi
  done
  if [ -z "$got" ]; then echo "[$t] FAILED: no linux_${ARCH} file found for $tag"; FAILED="$FAILED $t"; continue; fi

  rm -rf "$TMP/x"; mkdir -p "$TMP/x"
  case "$got" in
    *.zip) unzip -q -o "$got" -d "$TMP/x" ;;
    *)     tar -xzf "$got" -C "$TMP/x" ;;
  esac
  bin="$(find "$TMP/x" -type f -name "$t" | head -n 1)"
  if [ -n "$bin" ]; then
    install -m 755 "$bin" "$INSTALL_DIR/$t"
    echo "[$t] installed: $name"
  else
    echo "[$t] FAILED: binary not found inside the archive"; FAILED="$FAILED $t"
  fi
done

echo
ls -1 "$INSTALL_DIR"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo
     echo "$INSTALL_DIR is not in your PATH. Add it permanently with:"
     echo "  echo 'export PATH=\"\$PATH:$INSTALL_DIR\"' >> ~/.bashrc && source ~/.bashrc" ;;
esac
[ -n "$FAILED" ] && echo "Failed:$FAILED"
echo "Next: install nmap (sudo apt install nmap libpcap-dev), then run:  marsadix doctor"
