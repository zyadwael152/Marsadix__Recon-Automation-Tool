# Marsadix - Recon & Vuln Engine
#
# Build:
#   docker build -t marsadix .
#
# Run (scan an authorized target, keep the db + output on the host):
#   docker run --rm -v marsadix-data:/data marsadix scan example.com
#   docker run --rm -v marsadix-data:/data marsadix report example.com --out /data/output
#   docker run --rm -v marsadix-data:/data marsadix doctor
#
# The image bundles the ProjectDiscovery tool family (subfinder, dnsx,
# httpx, naabu, katana, nuclei), gau, ffuf and nmap -- see
# scripts/install-tools.sh, which this build reuses so there is exactly
# ONE place that lists tool versions/sources for both local and Docker
# setups.

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:${PATH}"

WORKDIR /opt/marsadix

# --- OS packages: build/runtime deps for the installer script + nmap/naabu ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip tar ca-certificates \
        nmap libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# --- external recon tools (Go binaries fetched from their GitHub releases) ---
# Copied in before the rest of the source so this layer is cached across
# ordinary code changes -- only rebuilds when install-tools.sh itself changes.
COPY scripts/install-tools.sh scripts/install-tools.sh
RUN bash scripts/install-tools.sh /usr/local/bin

# --- the marsadix Python package ---
COPY pyproject.toml README.md ./
COPY marsadix marsadix
RUN pip install --no-cache-dir .

# --- verify the image actually has everything marsadix expects ---
RUN marsadix doctor || true

# scans, databases and reports persist here -- mount a volume in `docker run`
RUN mkdir -p /data
WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["marsadix", "--db", "/data/marsadix.db"]
CMD ["--help"]
