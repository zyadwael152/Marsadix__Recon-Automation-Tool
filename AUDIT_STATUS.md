# Marsadix Audit Status — First Pass

Date: 2026-10-27

## Scope and confidence

This audit is based on the repository snapshot in `/mnt/d/DEPI/Marsadix` (HEAD `965dc9d`, plus the fixes below). `compileall` passed and the automated test suite passed: **320 passed**. Tests use mocks for external reconnaissance and do not establish that real third-party tools work end-to-end. No live recon tools were run, no external target was scanned, and the Docker image was not built in this environment.

## Fixed or improved in this pass

- `.env` reads only Marsadix-recognized environment variables rather than mutating arbitrary process variables.
- Scope normalization rejects backslashes, whitespace and control characters that can cause URL-parser disagreement.
- UTF-8 BOM and UTF-16 scope/config text files are supported.
- CT monitor validates the target and writes to the configured output directory.
- Recon now refuses to fall back to `example.com` if a target is missing.
- Depth zero performs one root discovery pass without recursive expansion.
- Discovery no longer drops valid subdomains merely because labels are long or contain five or more digits; tool output is decoded with replacement and malformed/log lines are filtered.
- Recursive discovery sorts and caps target batches deterministically and checks domain-label boundaries.
- SecurityTrails is configured in `Config`/`.env.example`, but its fetch function was removed; it is not currently a discovery source.
- Chaos API key is passed through `PDCP_API_KEY` in the child environment instead of command-line arguments.
- CDN classification no longer treats generic `amazon`, `google`, `azure`, or `microsoft` ownership as sufficient evidence of a CDN.
- Third-party ASN lookup is restricted to public IPs; PTR results are forward-confirmed against the original public IPs before being accepted.
- HTTP probing and port scanning were removed from the Recon stage because dedicated Web and Ports stages already perform them; this avoids duplicate probes/scans in standard/full mode.
- VHost results are retained as in-scope asset records instead of being discarded.
- Asset source classification distinguishes passive, permutation and bruteforce discoveries.
- Unknown technologies no longer receive guessed CPE identifiers; a missing version uses `*`, not `-`.
- Resolver fallback now supports IPv4 and IPv6, and dnsx requests AAAA results too.
- CT monitor reconnects iteratively instead of recursively and deduplicates hosts written to its output.
- Unconfigured `resolvers.txt` in the current directory is no longer trusted automatically.
- Legacy Naabu helper preserves partial stdout on timeout; Nmap XML parsing rejects entity declarations.
- Web stage applies the HTTP confidence bonus after its single HTTP probe.
- Disappearing tracked assets now create deduplicated low-priority alerts.
- Empty reports no longer display an empty Assets section.
- Installer temporary downloads use a per-run temporary directory; Go installs avoid assuming `sudo` exists in Docker; installer failures return non-zero.
- Docker image checks for expected tools and runs the app as an unprivileged user.
- `websockets` is declared as a dependency for CT monitoring.
- Added regression tests for depth-zero discovery, recursion boundaries, CPE behavior and IPv6 parsing.
- Removed the duplicate legacy implementations `recon/portscan.py` and `recon/webprobe.py`; `ports/probe.py` and `web/probe.py` are now the single implementations.
- httpx/katana subprocesses now have a timeout and are killed on expiry (a hung tool no longer blocks the stage).
- Report file names are sanitized, so `marsadix report ../../x` cannot write outside `--out` (also fixes `:`/`*` targets on Windows).
- Scan queries use `id` as a tiebreaker when `started_at` has one-second resolution; the "new port" alert wording is no longer reversed.
- A failed graph rebuild rolls back instead of leaving a partially deleted graph in an open transaction.
- CLI DB commands load their module once and always close the SQLite connection (Windows file-lock fix).
- Text files are normalized to LF and `.gitattributes` prevents shell scripts from getting CRLF again; `setup.sh` had a stray `else` and both installers were syntax-broken.
- `.env.example` no longer contains real-looking API keys (they remain in git history — rotate them).
- Installer honors its install-directory argument, installs nmap/amass, and no longer uses `eval` on `SUDO_USER`; Docker adds the C toolchain naabu needs.

## Still open or needs additional verification

### Recon and data sources

- VirusTotal, Censys and Shodan pagination is not implemented yet.
- Shodan's documented endpoint requires its API key in the query string; logging is redacted, but the key still exists in the request URL. This is a provider/API design limitation and needs a documented mitigation decision.
- Reverse DNS currently starts from discovered public IPs; PTR sweeps across ASN ranges are not implemented.
- Real-world compatibility of all installed tool versions/flags has not been tested. VHost parsing now reads ffuf's `input.FUZZ` (with an isolated regression test), but DNS brute-force behavior still needs an integration test against a live tool.
- Installer still uses moving `@latest` versions and does not verify downloaded binaries against pinned checksums. Docker build has not been run.
- CT endpoint availability has not been verified against the live service.

### Web and ASM

- `gau` is not integrated into URL collection; current Web stage uses `httpx` and `katana`.
- JS file recording is partial; parsing JavaScript for endpoints/subdomains, JS library versions and public emails is not implemented as a complete pipeline.
- Screenshot capture (`gowitness`), WAF detection (`wafw00f`), security-header scoring, exposed-panel checks, JS secret scanning, TLS analysis and email-security posture checks are not integrated.
- The ASM stage is absent. Nuclei execution/configuration, injection detection, ffuf fuzzing, custom detection skills, source attribution and three-state result generation are not implemented end-to-end, even though some model/report fields and OWASP mappings exist.

### CVE monitoring and risk

- `marsadix/monitor/runner.py` is absent, so NVD/KEV clients, incremental sync, scheduling, KEV rechecks, CPE matching, confidence levels, EPSS integration and monitor-driven alerts are not operational end-to-end.
- Alert rows/configuration exist, but delivery for Discord/Telegram/email/webhooks and Slack/Teams is not implemented end-to-end.
- Context-aware risk scoring, misconfiguration pattern hunting, attack-surface score trends and remediation database are not complete.
- OWASP percentage currently counts categories with findings; that is not equivalent to measuring which categories were actually tested. The report wording/metric needs redesign once detection coverage is recorded by the ASM stage.

### Graph, reports and benchmarks

- Graph schema/building, shared-infrastructure lookup and blast-radius query exist. Attack-path and Shadow-IT query coverage needs explicit tests; current visualization is a static SVG/ASCII view, not an interactive Cytoscape.js/D3.js graph.
- CSV export has formula-prefix protection; SARIF and PDF export are not implemented.
- `investigate` CLI command is absent.
- Reproducible subfinder-vs-Marsadix benchmarks and DVWA/Juice Shop detection-rate/precision benchmark are not implemented.
- Tool failures are often logged and skipped inside individual modules; structured per-tool status recording and report presentation still need implementation.

## Next recommended order

1. Finish API pagination and test all data-source parsers with mocked responses.
2. Add structured tool-run outcomes and ensure partial failures are visible in scan results.
3. Implement the missing ASM pipeline and safe detection-status model before claiming OWASP detection coverage.
4. Implement the CVE monitor runner and alert delivery.
5. Complete report exports, graph queries/visualization and reproducible benchmarks.
6. Run real-tool integration tests only against local labs or explicitly authorized targets, then build and smoke-test Docker on Linux and Windows-compatible setup paths.
