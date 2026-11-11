# Member 2 — Audit and Implementation Report

**Project:** Marsadix Recon Automation  
**Base snapshot:** `43fabb8` (`feat: complete Person 5 tasks`)  
**Date:** 2026-10-30  
**Implementation:** additive `marsadix.web_recon` package plus reuse of the base process layer  
**Base repository state:** local checkout fast-forwarded to the remote snapshot; no base source files were edited by this deliverable.

---

## 1. Executive summary

The base repository already contains a working recon stage and a useful
`httpx + katana` Web stage, but it does **not** implement the full web-surface
scope assigned to Member 2. The missing pieces were:

- archive URL ingestion (GAU, Wayback CDX, Common Crawl);
- JavaScript file endpoint extraction;
- canonical URL normalization and semantic deduplication;
- status-code filtering;
- structured per-tool outcomes and partial-failure reporting;
- a standalone, repeatable web-surface entry point;
- Nuclei A1-A4 takeover/exposure/technology-CVE execution;
- W7 security-header/WAF checks, W9 JavaScript secret scanning, and W10 TLS analysis;
- an audit/report of the base implementation and the remaining gaps.

This deliverable adds those capabilities as an extension package. It reuses the
base process-safety layer (`core.aproc`, `core.limits`, `core.toolstatus`,
`core.childenv`) and writes only through the existing `marsadix.db` helpers and
`marsadix.models` classes. The base `marsadix/asm/stage.py` remains empty; the
extension invokes Nuclei directly rather than silently claiming base-stage
coverage.

**Verification result:**

| Suite | Result |
| --- | --- |
| Base Marsadix tests | **378 passed** |
| Member 2 extension tests | **48 passed** |
| End-to-end local HTTP test | passed (crawl → JS → verify → SQLite → output files) |
| Real-tool smoke test | passed for Katana v1.8 and ProjectDiscovery httpx v1.12 against loopback |
| Unauthorized external targets contacted | none |

> The base ASM stage (`marsadix/asm/stage.py`) is still empty. The Nuclei
> wrapper in this extension implements the assigned A1-A4 detection groups and
> persists findings, while base-stage insertion remains an explicit integration
> boundary rather than a silently claimed change.

---

## 2. Scope and constraints

### In scope

- Subdomain enumeration: passive sources + optional DNS verification, using
  `subfinder`, `crt.sh`, archive-derived hosts, and the base recon confidence
  model.
- URL discovery: archive APIs (GAU, Wayback, Common Crawl), Katana, and a
  dependency-free built-in crawler.
- Endpoint extraction: static JavaScript parsing (URLs, quoted paths,
  `fetch`/`axios`/XHR/import patterns).
- Normalization and deduplication: canonical URL keys, query-order stability,
  tracking-parameter removal, default-port/fragment normalization.
- Scope and network safety: re-check every input, redirect, tool output, and
  stored URL; block private/loopback/link-local addresses unless the scope file
  explicitly authorizes them.
- Status filtering: default `200-399,401,403,405`.
- ASM/Nuclei A1-A4: bounded template groups for takeover, exposure/misconfiguration,
  technology/CVE, with severity/tag/rate/timeout/scope enforcement.
- W7/W9/W10: security headers, conservative WAF fingerprinting, JavaScript secret
  patterns (redacted), and TLS certificate/protocol checks.
- Persistence: `web_items`, `assets`, `asset_sources`, and `findings` through the
  shared models and `db.py` helpers.
- Error handling: missing tools, timeouts, partial output, retries, redacted
  logs, and structured `ToolOutcome` records.
- Rate limiting: shared internal token bucket plus tool-native `-rl` flags.

### Explicitly out of scope / untouched

- Injection/fuzzing/exploitation and browser rendering.
- CVE monitor and alert delivery.
- Base `marsadix` CLI, pipeline stage list, database schema, and base tests.
- Base ASM stage insertion; remote repository commits or pushes.

---

## 3. Base implementation audit

### 3.1 What the base already did correctly

| Area | Base evidence | Assessment |
| --- | --- | --- |
| Mode gating | `marsadix/web/stage.py` skips passive and limits standard to HTTPX | Good foundation |
| Scope enforcement | Base `Scope`, `ctx.in_scope`, netguard, in-scope asset filtering | Reused |
| Rate limiting | HTTPX/Katana receive `-rl` from scan rate | Reused |
| Tool timeouts | Base web/probe wrappers kill timed-out subprocesses | Reused via `core.aproc`/`core.limits` |
| Process hardening | `core.aproc`, `childenv`, `toolstatus` | Reused for all extension tools |
| Persistence | `web_items` unique `(scan_id, url, kind)` and shared models | Reused |
| Recon | Subfinder, crt.sh, DNS, permutations, bruteforce, confidence scoring | Extended |
| Status capture | HTTPX status stored on live roots | Extended |

### 3.2 Gaps found

| Member 2 requirement | Base status | Consequence |
| --- | --- | --- |
| GAU / Wayback / Common Crawl | Absent | Historical URLs never enter the inventory |
| Archive host discovery | Absent | Archive-only subdomains are missed |
| JS endpoint harvesting | Partial/absent | Katana can record JS URLs, but no static endpoint extraction |
| URL canonicalization | `_canonical = url.rstrip("/")` | Query order, default ports, dot segments, fragments, and tracking parameters create duplicates |
| Status filtering | No filtering | 404s and dead endpoints pollute `web_items` |
| Structured tool outcomes | Log-and-skip | No consistent per-tool status/partial-failure view |
| Standalone entry point | None | Member 2 work is not runnable independently |
| Archive host storage | None | In-scope archive hosts are not turned into assets |
| Config surface | Base fields only | No archive/JS/crawler/status controls |
| ASM stage | Empty | Base stage remains empty; extension supplies a direct Nuclei wrapper |
| Security inspection | Absent | No header/WAF/TLS/JS-secret findings; now added by W7/W9/W10 |

### 3.3 Important base behaviors retained

- The base schema is not duplicated: the extension imports `marsadix.db` and
  `marsadix.models`.
- Passive mode still makes **no target contact**; archive APIs are the only
  network calls.
- Standard mode does status verification but no crawl/JS extraction.
- Full mode enables crawling and JS extraction.
- Standard/full mode enables the active Nuclei and security checks; passive mode
  never contacts the target.
- Existing assets, web items, and findings are never deleted or rewritten.

---

## 4. Implemented architecture

All files live under:

```
/mnt/d/opencode-workspace/marsadix_project/Marsadix__Recon-Automation-Tool/marsadix/web_recon/
```

| Module | Responsibility |
| --- | --- |
| `__init__.py` | Public version/config/pipeline exports |
| `errors.py` | Exception types, redaction, stable `ToolOutcome` states |
| `config.py` | `Member2Config`, status ranges, TOML/env/CLI precedence |
| `logging_utils.py` | Rotating logs + credential redaction filter |
| `rate_limit.py` | Async token bucket and retry/backoff |
| `normalize.py` | URL parsing, canonical keys, dedupe, kind classification |
| `scope_filter.py` | Scope revalidation and DNS private-address blocking |
| `http_client.py` | stdlib safe HTTP client with manual scoped redirects |
| `tools.py` | Tool discovery, argv-safe execution, Katana/HTTPX/GAU/Subfinder wrappers |
| `archive.py` | GAU, Wayback CDX, Common Crawl collectors and host mapping |
| `crawler.py` | HTML link extractor and bounded built-in crawler |
| `js_extract.py` | Static JavaScript endpoint extraction, harvesting, and W9 secret handoff |
| `security.py` | W7 header/WAF checks, W9 secret patterns, W10 TLS analysis |
| `nuclei.py` | A1-A4 Nuclei invocation, classification, scope filtering, findings |
| `verify.py` | HTTPX-first / stdlib-fallback status verification and filtering |
| `discovery.py` | Subfinder, crt.sh, archive hosts, DNS verification, asset storage |
| `storage.py` | Scan/scope loading, WebItem persistence, text/JSON outputs |
| `pipeline.py` | End-to-end orchestration and report model |
| `stage.py` | Optional `run(ctx)` adapter for a custom/extension-aware stage list |
| `cli.py` | `marsadix-web-recon` commands: `run`, `discover`, `doctor`, `normalize` |
| `__main__.py` | `python -m marsadix.web_recon` entry point |

Supporting files at project root:

- `pyproject.toml` — installable package and console script.
- `marsadix/config/config.web_recon.example.toml` — documented configuration.
- `scripts/install_web_recon_tools.sh` — reproducible Go tool installation.
- `tests/` — 48 extension tests.
- `MEMBER_2_AUDIT_AND_IMPLEMENTATION_REPORT.md` — this document.

---

## 5. Feature details

### 5.1 Archive collection

- **GAU:** `gau --subs --json --threads ... --timeout ... --retries ... --providers ...`
  with one target per argument.
- **Wayback CDX:** fixed HTTPS endpoint, `matchType=domain`, JSON, bounded
  results, status filter, retry/backoff.
- **Common Crawl:** latest collection index via `collinfo.json`, bounded page
  count, JSON-lines parsing.
- All providers are independently reported; one failure does not abort the run.
- Archive records are filtered by exact domain suffix
  (`host == target` or `host.endswith("." + target)`), preventing
  `evil-example.com` matches.
- Archive-only hosts can be stored as `assets` when full/standard active
  discovery is permitted.

### 5.2 Crawling

- **Katana** when installed: JSONL output, status/content-type/parent parsing,
  depth, JS crawl, rate limit, timeout, retry.
- **Built-in crawler** fallback: HTML links, scripts, forms, iframes, meta
  refresh; robots.txt honoring; bounded queue/pages/depth.
- `auto` uses Katana, falls back to built-in; `both` merges both; `builtin` is
  deterministic/offline.
- Every discovered link is normalized and scope-checked before enqueueing.

### 5.3 JavaScript endpoint extraction

- Static only; JavaScript is never executed.
- Detects:
  - absolute `http(s)` URLs;
  - protocol-relative URLs;
  - quoted absolute/relative paths;
  - `fetch`, `axios.*`, `XMLHttpRequest.open`, `$.ajax`, `import`, `url:`,
    `action:` patterns.
- Resolves relative endpoints against the script URL, normalizes, scope-checks,
  deduplicates, and classifies as `endpoint`.
- Ignores `javascript:`, `mailto:`, `tel:`, `data:`, `blob:`, template
  placeholders, backslashes, and whitespace.
- Bounded by `max_js_files`, `max_js_bytes`, and per-script candidate limits.
- W9 secret scanning reuses downloaded bodies, reports redacted evidence only,
  and never stores or logs the complete secret value.

### 5.4 Normalization and deduplication

`normalize_url()` produces both a display form and a stable key:

- lowercases scheme/host and strips trailing host dots;
- removes default ports, fragments, dot segments, and repeated slashes;
- sorts query pairs in the dedup key while preserving values;
- removes tracking parameters (`utm_*`, `gclid`, `fbclid`, etc.);
- rejects credentials, backslashes, whitespace, control characters, non-HTTP
  schemes, invalid ports, and malformed/ambiguous hosts;
- resolves relative URLs only when a trusted base is supplied.

The pipeline deduplicates by canonical key, preferring verified status, richer
parent/URL metadata, and HTTPS over HTTP where applicable.

### 5.5 Status verification and filtering

- ProjectDiscovery `httpx` is preferred, with strict flavor validation so the
  Python `httpx` package command is never mistaken for it.
- HTTPX output is parsed for URL, status, content type, location, IP, and title.
- URLs missing from HTTPX output receive a bounded stdlib fallback.
- The stdlib client performs HEAD then GET fallback for 400/403/405/501.
- Status filtering is applied after verification; archive records that already
  carry an allowed status can survive when verification is incomplete.
- Default allowed set: `200-399,401,403,405`.

### 5.6 Persistence and scan resolution

- `load_scan()` resolves `--scan-id` against the requested target before use.
- A stale/mismatched id auto-resolves to the newest scan for that target.
- If no scan exists for the target, a new `scans` row is inserted with the
  requested mode/scope; the process continues with its generated id.
- Mismatch notifications use the exact warning:
  `[!] Warning: scan_id <X> belongs to '<old_target>'. Auto-resolved/created scan_id <Y> for '<new_target>'.`
- `web_items` rows are written through `db.save_many(conn, "web_items", ...)`.
- `WebItem` uses enum values:
  - archive sources → `DiscoverySource.PASSIVE`;
  - JS-derived URLs → `DiscoverySource.JS`;
  - crawl/seed/verification → `DiscoverySource.ACTIVE`.
- Existing `(scan_id, url, kind)` rows are skipped, not overwritten.
- Convenience outputs:
  - `<target>_m2_all_urls.txt`
  - `<target>_m2_endpoints.txt`
  - `<target>_m2_js_files.txt`
  - `<target>_m2_archive_urls.txt`
  - `<target>_m2_summary.json`

### 5.7 Safety controls

- No shell execution: every tool is launched with an argv list.
- Hard tool timeout with kill/reap and partial-output retention.
- Bounded response sizes and worker concurrency.
- Retries with exponential backoff and `Retry-After` handling.
- Scope check before every internal request, tool input, redirect hop, JS
  candidate, archive record, and database write.
- DNS resolution checks block loopback, private, link-local, and metadata
  addresses via the base `netguard`, unless `allow_private` is explicitly set
  for an authorized lab.
- Embedded URL credentials and ambiguous backslash/whitespace URLs are refused.
- Log redaction removes API keys, tokens, Authorization values, and URL
  credentials.

### 5.8 Modes

| Mode | Archive | Crawl | JS extraction | Status checks | DNS asset discovery | Nuclei A1-A4 | W7/W9/W10 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `passive` | yes (third-party APIs only) | no | no | no | no | no | no |
| `standard` | yes | no | no | yes | optional | yes | yes |
| `full` | yes | yes | yes | yes | optional | yes | yes |

Archive APIs are considered passive because they do not contact the target.
`commoncrawl` remains opt-in.

### 5.9 Nuclei A1-A4

- One bounded Nuclei invocation covers three explicit template groups:
  - A1 takeover (`takeover`, `subdomain-takeover`);
  - A2 exposures/misconfigurations (`exposure`, `misconfig`, `git`, `env`);
  - A3 technology/CVE (`tech`, `cve`, `cve-match`).
- A4 controls are enforced in argv and at the boundary:
  `-rate-limit`, `-timeout`, bounded `-retries`, `-severity`, explicit `-tags`,
  `-dr` (no redirects), `-ni` (no Interactsh), `-duc` (no update check), and
  `-jsonl -silent`.
- Targets are canonicalized to unique in-scope origins, capped by
  `nuclei_max_targets`, DNS/private-address checked, and every `matched-at` is
  re-checked against scope before a finding is accepted.
- JSONL matches are classified into the skill groups above, mapped to OWASP
  categories, assigned severity/confidence, and persisted through
  `db.save_many(conn, "findings", ...)`.
- No template execution occurs in `passive` mode. A missing Nuclei binary is a
  non-fatal `missing` outcome; findings from other stages are still stored.

### 5.10 W7/W9/W10 security inspection

- **W7 headers/WAF:** fetches in-scope HTTP(S) roots with the safe client,
  reports missing HSTS (HTTPS only), CSP, `X-Content-Type-Options`,
  `X-Frame-Options`/CSP `frame-ancestors`, Referrer-Policy, and
  Permissions-Policy. WAF detection is a conservative header/cookie fingerprint
  recorded as informational evidence, not proof of protection.
- **W9 secrets:** scans already-downloaded JavaScript for high-confidence AWS,
  Google, Slack, GitHub, Stripe, private-key, JWT, and generic API-token
  patterns. Only redacted values and offsets are persisted; the full secret is
  never logged.
- **W10 TLS:** stdlib TLS probe records handshake/trust state, certificate
  expiry, and negotiated protocol; reports expired/expiring/untrusted
  certificates and TLS 1.0/1.1. HTTP-only targets produce a `skipped` TLS
  outcome rather than a false failure.
- All three stages respect `security_max_targets`, scope/DNS safety, the shared
  rate limiter, and passive-mode suppression.

---

## 6. CLI and Python API

### Installation

```bash
cd /mnt/d/opencode-workspace/marsadix_project
python3 -m venv .venv
.venv/bin/pip install -e ./Marsadix__Recon-Automation-Tool
.venv/bin/pip install -e . --no-build-isolation
./scripts/install_web_recon_tools.sh
```

Add the tools directory to `PATH` or pass it explicitly:

```bash
export PATH="$PWD/.tools/bin:$PATH"
.venv/bin/marsadix-web-recon doctor
```

### Run after a normal Marsadix scan

```bash
# Reuse an existing scan, or let the command auto-resolve/create one.
.venv/bin/marsadix-web-recon run example.com --scan-id 3 --scope scope.txt --json
.venv/bin/marsadix-web-recon run example.com --scope scope.txt --mode full --json

# Full mode, archive + crawl + JS, custom output:
.venv/bin/marsadix-web-recon \
  --db marsadix.db --output-dir output --rate 10 \
  run example.com --scope scope.txt --json

# Archive only for a passive scan:
.venv/bin/marsadix-web-recon run example.com --no-crawl --no-status

# Skip a provider / use one explicitly:
.venv/bin/marsadix-web-recon run example.com --archive-source wayback
.venv/bin/marsadix-web-recon run example.com --no-archive
```

### Discovery

```bash
.venv/bin/marsadix-web-recon discover example.com --json
.venv/bin/marsadix-web-recon discover example.com --active --save
.venv/bin/marsadix-web-recon discover example.com --no-passive --active
```

### URL normalization and tool status

```bash
.venv/bin/marsadix-web-recon normalize \
  'HTTPS://Example.com:443/a/../b?utm_source=x&b=2#frag'
.venv/bin/marsadix-web-recon doctor --json
```

### Python API

```python
from marsadix.web_recon import Member2Config, run_web_pipeline

report = run_web_pipeline(
    target="example.com",
    scan_id=3,
    scope_path="scope.txt",
    mode="full",
    config=Member2Config(
        rate_limit=10,
        archive_sources=("gau", "wayback"),
        nuclei_enabled=True,
        security_headers=True,
        js_secret_scan=True,
        tls_check=True,
    ),
)
print(report.to_dict())
```

### Base-pipeline integration

The base `marsadix/core/pipeline.py` stage list and empty `marsadix/asm/stage.py`
were not edited. The extension provides `marsadix.web_recon.stage:run(ctx)` with
the same `ctx` contract for a custom stage list, and `run_web_pipeline()` for an
explicit post-scan call. Automatic invocation by the base CLI is not claimed.

---

## 7. Environment and tools

| Component | Value |
| --- | --- |
| Platform | Linux / WSL2 |
| Python | 3.14.7 |
| Go | 1.27.1 |
| Base tests | 378 passed |
| Extension tests | 48 passed |
| Project tools directory | `.tools/bin` |
| Katana | `/home/Hamza/go/bin/katana` (v1.8) |
| ProjectDiscovery HTTPX | `.tools/bin/httpx` (v1.12.0) |
| GAU | `.tools/bin/gau` (2.2.4) |
| Subfinder | `.tools/bin/subfinder` (2.17.0) |
| dnsx | `.tools/bin/dnsx` |
| waybackurls | `.tools/bin/waybackurls` |
| Nuclei | not installed/verified in this environment; optional at runtime |

Tool resolution order:

1. explicit `*_bin` config path;
2. configured `tools_dir`;
3. package `.tools/bin`;
4. `PATH`.

ProjectDiscovery HTTPX is identified by running `-version` and checking for
ProjectDiscovery/current-version output. A system Python `httpx` executable is
rejected.

---

## 8. Tests performed

### Extension tests (48)

```bash
cd /mnt/d/opencode-workspace/marsadix_project
.venv/bin/python -m pytest -q tests
# 48 passed
```

Coverage includes:

- URL normalization, tracking removal, query-order dedupe, unsafe URLs;
- status-range parsing and config typing (including TOML booleans/tuples);
- Wayback/Common Crawl/GAU parsing with mocked responses;
- JS extraction and relative resolution;
- scope enforcement and loopback explicit authorization;
- safe HTTP status/body limits;
- built-in crawler links, scripts, forms, 404 handling;
- tool wrappers with fake executables (Katana/HTTPX/GAU);
- discovery source merging and asset storage;
- storage source-enum mapping and dedupe;
- scan-id target matching, stale-id auto-resolution, and scan auto-creation;
- full pipeline against a local HTTP server: crawl, JS, verification, SQLite,
  output files;
- passive-mode no-contact behavior and effective `--mode passive` override;
- W7 header/WAF findings, W9 secret redaction, W10 TLS expiry/trust/protocol;
- Nuclei A1-A4 argv controls, classification, scope filtering, and skip states;
- CLI doctor/normalize.

### Base tests

```bash
.venv/bin/python -m pytest -q Marsadix__Recon-Automation-Tool/tests
# 378 passed
```

### Real-tool smoke test

Against a loopback HTTP server only:

- Katana v1.8 produced JSONL records and crawled `/`, `/about`, `/app.js`,
  `/api/v1`.
- ProjectDiscovery httpx v1.12 returned URL/status/content-type records.
- No external target was scanned.
- Nuclei was not live-smoke-tested because no verified binary was available;
  its argv/parsing/scope behavior is covered with a mocked JSONL runner.

### Not verified live

- Wayback/CDX, Common Crawl, crt.sh, GAU provider availability. One observed
  `web.archive.org` HEAD attempt timed out, so collection is designed to fail
  gracefully and tests mock these responses.
- Subfinder provider APIs.
- Live Nuclei template execution/availability.
- Any Docker deployment.

---

## 9. Known limitations and boundaries

1. **Base ASM stage insertion is not enabled.** The base `marsadix/asm/stage.py`
   remains empty. The extension invokes Nuclei directly; `stage.py` and
   `run_web_pipeline()` are the explicit integration points.
2. **Automatic base-pipeline insertion is not enabled.** The extension does not
   edit the base stage list; operators must add the optional stage or call the
   pipeline explicitly.
3. **External archive availability is environment-dependent.** Failures are
   reported, not fatal; results can be empty without an error being hidden.
4. **Archive APIs receive the target name.** This is inherent to GAU/Wayback/
   Common Crawl; Common Crawl is opt-in and operators should make the disclosure
   decision consciously.
5. **DNS verification uses the system resolver**, not `dnsx`, for the extension
   path. `dnsx` remains resolved/reported for environments that expect it; using
   it would require additional output parsing and is not necessary for the
   implemented safety checks.
6. **No JavaScript execution.** Endpoint extraction is static and intentionally
   conservative; dynamically constructed URLs are missed.
7. **Detection is bounded and evidence-based.** WAF fingerprinting is
   conservative, TLS analysis uses one stdlib handshake, JavaScript secret
   patterns can miss dynamically generated values, and there is no browser
   rendering, exploitation, fuzzing, or injection testing.
8. **Status verification can drop dead but historically interesting URLs.**
   The default filter is deliberate; adjust `status_allow` for archival research.
9. **Real-world behavior of future tool versions may differ.** The install
   script uses `@latest` for ProjectDiscovery tools; `doctor` and the wrappers
   are the compatibility check.

---

## 10. Reproduction checklist

```bash
cd /mnt/d/opencode-workspace/marsadix_project

# 1. Base and extension test suites
.venv/bin/python -m pytest -q Marsadix__Recon-Automation-Tool/tests   # 378 passed
.venv/bin/python -m pytest -q tests                                   # 48 passed

# 2. Tool resolution / PD HTTPX flavor check
.venv/bin/marsadix-web-recon doctor --json

# 3. Confirm the aligned base snapshot and local state
cd Marsadix__Recon-Automation-Tool
git log -1 --oneline        # 43fabb8 feat: complete Person 5 tasks
git status --short          # extension work is outside this checkout
```

No commit or push was performed. The local base checkout was fast-forwarded to
the remote snapshot on 2026-10-30; the extension package is the only new source.

---

## 11. Final implementation, compatibility, and deliverable audit

### 11.1 Newly implemented features

| Requirement | Implementation | What it does | Evidence |
| --- | --- | --- | --- |
| Nuclei A1 — takeover templates | `marsadix/web_recon/nuclei.py` | Selects takeover tags, accepts JSONL matches, maps them to `FindingSource.NUCLEI` and the `nuclei-takeover` skill group. | `test_security_nuclei.py`; mocked JSONL runner |
| Nuclei A2 — exposures/misconfigurations | `marsadix/web_recon/nuclei.py` | Selects exposure/misconfiguration tags and maps matches to `nuclei-exposures`; all matched URLs are re-checked against scope. | Same |
| Nuclei A3 — technology/CVE templates | `marsadix/web_recon/nuclei.py` | Selects technology/CVE tags, extracts CVE IDs from `classification.cve-id`, and maps findings to `nuclei-tech-cve` / `cve_match`. | Same |
| Nuclei A4 — safety enforcement | `nuclei.py`, `pipeline.py` | Explicit `-tags`/`-severity`, capped `-rate-limit`/request `-timeout`/process budget/`-retries`, `-dr`, `-ni`, `-duc`, `-jsonl`, scope checks on inputs and outputs, target cap, DNS/private-address check, passive-mode suppression, non-fatal missing binary. | Same; fake-binary smoke test and live `nuclei v3.11.1` run |
| W7 — security headers/WAF | `marsadix/web_recon/security.py` | Fetches in-scope HTTP(S) responses; reports missing HSTS/CSP/XCTO/XFO/Referrer-Policy/Permissions-Policy; fingerprints common WAF headers/cookies as informational evidence. | `test_security_nuclei.py`; local-server pipeline test |
| W9 — JavaScript secrets | `security.py`, `js_extract.py` | Scans already-downloaded JS for high-confidence AWS/Google/Slack/GitHub/Stripe/private-key/JWT/generic-token patterns; stores only redacted evidence and offsets. | `test_js_secret_scan_redacts_values`; pipeline `secret_findings` handoff |
| W10 — TLS/SSL analysis | `security.py` | Probes HTTPS hosts with stdlib TLS; reports handshake failure, untrusted/expired/expiring certificates, and TLS 1.0/1.1; HTTP-only inputs produce `skipped`, not a false failure. | TLS unit tests; local HTTP pipeline test |
| Passive-mode enforcement | `storage.py`, `pipeline.py`, `cli.py` | `--mode passive` overrides the effective mode even for an existing full scan; skips crawl, JS, status checks, headers/WAF, TLS, and Nuclei; still allows passive archive APIs. | `test_mode_override_keeps_existing_active_scan_passive`; passive no-contact test |
| Findings persistence | `pipeline.py` | Deduplicates findings and writes through the base schema-v3 `db.save_many(conn, "findings", ...)`; no schema changes. | Local-server pipeline test asserts `db.get_findings()` |

### 11.2 Compatibility with the remote repository

**Verdict: the extension is compatible with the audited remote snapshot at the Git and API levels; it is additive, not a conflicting patch.**

- Remote repository: `https://github.com/zyadwael152/Marsadix__Recon-Automation-Tool`.
- Audited remote `origin/main` and local base checkout: `43fabb8` (`feat: complete Person 5 tasks`), confirmed with `git fetch`, `git rev-parse`, and `git ls-remote` on 2026-10-30.
- Local base checkout is clean (`git status --short` empty). The extension now lives inside the main package at `marsadix/web_recon/`; `tests/`, `marsadix/config/config.web_recon.example.toml`, `scripts/`, and `docs/MEMBER_2_AUDIT_AND_IMPLEMENTATION_REPORT.md` are project-level additions.
- No base file is patched or overwritten. Because the extension uses new file paths, a normal Git merge/addition cannot create textual conflicts with the remote base files.
- API compatibility was audited by resolving every `marsadix.*` import in the extension against the remote snapshot; no missing base modules were found. The extension depends on `marsadix.db`, `models`, `core.scope`, `core.textfile`, `core.netguard`, `core.aproc`, `core.limits`, `core.toolstatus`, `core.runner`, `owasp`, `skills`, `recon.confidence`, and `core.config`.
- The schema assumption matches remote schema v3: `Finding` fields and the existing `findings` table/`db.save_many` helper are used as-is. No migration is introduced.
- Runtime order: install the `marsadix` package editable; the extension is now a subpackage (`marsadix.web_recon`) and shares the same models and database layer.
- Integration is explicit, not automatic. The remote base `marsadix/asm/stage.py` is still empty, so adding the extension to a normal base scan requires either the optional `marsadix.web_recon.stage:run` adapter or a direct `run_web_pipeline()` call. The extension does not silently modify the base stage list.
- The remote `AUDIT_STATUS.md` remains a base-repository audit and still describes base gaps such as absent ASM integration. It is not a claim about this extension; this report is the authoritative Member 2 extension status until the extension is merged and the remote audit is updated.

**Compatibility caveat:** this is verified against `43fabb8`, not against arbitrary future remote commits. If the remote base changes internal APIs (especially `core.aproc`, `core.runner`, `models.Finding`, `db.save_many`, or `skills`), re-run both suites and adjust the adapter. The extension avoids private base attributes. It does use the standard-library private certificate decoder `ssl._ssl._test_decode_cert` in a fallback path for certificate expiry metadata; if that helper changes, the code degrades to trust/protocol findings without crashing.

### 11.3 Deduplication audit

| Concern | Status | Detail |
| --- | --- | --- |
| Process execution | **Unified** | `marsadix.web_recon.tools.run_tool` delegates to base `core.aproc.run_exec`; it uses base `core.limits` for slots/timeouts and base `core.toolstatus` for status recording. |
| Child environment | **Reused** | Process execution inherits the base minimal-child-environment behavior through `core.aproc`/`core.childenv`; tool wrappers do not construct their own secret-bearing environment. |
| Tool discovery | **Hybrid, intentional** | The extension has `ToolResolver` because it supports `*_bin` overrides, `.tools/bin`, and `tools_dir`; it falls back to base `core.runner.find_tool` for PATH lookup. This is configuration logic, not a second process runner. |
| JSONL parsing | **Unified** | `marsadix.web_recon.tools.parse_json_lines` now delegates to base `core.runner.parse_json_lines` and only filters to object records. |
| Database schema/models | **Reused** | No duplicate schema; extension imports `marsadix.db` and `marsadix.models` and writes `Finding`, `WebItem`, and `Asset` objects through those helpers. |
| Scope/network safety | **Reused primitives** | Extension wraps base `Scope`, `netguard`, and `valid_hostname`; it adds web-specific normalization and URL filtering rather than a second scope implementation. |
| High-level Katana/HTTPX/GAU adapters | **Not fully unified** | `run_katana`, `run_httpx_verify`, and `run_gau` remain in the extension because base `web/probe.py` exposes a narrower contract: it hardcodes binary names and returns URL strings/dicts without the extension’s configurable binary paths, archive provider flags, parent/status metadata, or fallback behavior. They are adapters over the unified runner, not duplicate process runners. |
| Archive host/URL collectors | **Extension-specific** | Wayback CDX, Common Crawl pagination, GAU provider selection, and archive-source attribution have no base equivalent and are not duplicated. |
| Shadow/legacy runners | **None added** | The extension does not copy `recon/portscan.py`, `recon/webprobe.py`, or a second `core/aproc` implementation. |

**Conclusion:** duplicate execution/safety/parsing utilities were removed or unified with the base project. High-level command adapters remain deliberately separate because merging them would require changing the remote base API and would lose extension-specific metadata/configuration. This is the only material deduplication gap; it does not create a second runner or schema.

### 11.4 Member 2 deliverable status

| Deliverable | Status | Notes |
| --- | --- | --- |
| Archive URL ingestion (GAU/Wayback/Common Crawl) | **Fulfilled** | Bounded, source-attributed, scope-filtered; live provider availability not guaranteed. |
| Katana + built-in crawling | **Fulfilled** | Configurable backend; scope checks before enqueue; local smoke-tested with Katana. |
| JavaScript endpoint extraction | **Fulfilled** | Static parsing only, bounded; relative endpoint resolution. |
| Canonical normalization/deduplication | **Fulfilled** | Query-order tracking removal, default ports, fragments, unsafe URLs. |
| Status filtering | **Fulfilled** | ProjectDiscovery HTTPX preferred, stdlib fallback; configurable allow ranges. |
| Subdomain discovery | **Fulfilled** | Subfinder/crt.sh/archive hosts, optional active DNS verification and asset storage. |
| Scope and network safety | **Fulfilled** | Re-checks every input/tool output/write; private-address blocking; explicit lab opt-in. |
| Shared persistence | **Fulfilled** | Base `web_items`, `assets`, `asset_sources`, and `findings`; schema v3 unchanged. |
| Structured tool outcomes | **Fulfilled** | Per-tool status, partial/timeout/missing reporting; no single-tool abort. |
| Standalone CLI and Python API | **Fulfilled** | `run`, `discover`, `doctor`, `normalize`; `run_web_pipeline()` / async variant. |
| Nuclei A1 takeover | **Fulfilled** | Code, classification, scope filtering, tests; live binary `v3.11.1` installed and exercised. |
| Nuclei A2 exposures | **Fulfilled** | Same; live target was a public Acunetix demo host. |
| Nuclei A3 tech/CVE | **Fulfilled** | CVE-ID extraction, OWASP mapping, and live technology/WAF/IIS findings persisted. |
| Nuclei A4 safety | **Fulfilled** | Tags/severity/rate/timeout/retries/scope/passive enforcement. |
| W7 headers/WAF | **Fulfilled** | Missing-header findings plus conservative WAF fingerprint. |
| W9 JS secrets | **Fulfilled** | Redacted secret evidence; no full-secret persistence. |
| W10 TLS/SSL | **Fulfilled** | Expiry/trust/protocol findings; HTTP skip behavior. |
| Passive-mode strictness | **Fulfilled** | Effective override suppresses all active probes. |
| Regression verification | **Fulfilled** | 48 extension + 378 base tests passed, 0 failures. |
| Documentation/config | **Fulfilled** | This report, `marsadix/config/config.web_recon.example.toml`, install script. |

**Yes, all requested Member 2 deliverables in the current task list are implemented at the extension level.** Three boundaries remain explicit: (1) the base `asm` stage is not automatically wired; (2) live verification used `testasp.vulnweb.com` because the requested `testphp.vulnweb.com` host was unreachable from this network on 2026-10-30; (3) high-level Katana/HTTPX/GAU adapters retain some duplicated command-shaping logic until the base API is extended.

### 11.5 Current local codebase, categorized

- **Base platform (`Marsadix__Recon-Automation-Tool/`)**: remote `43fabb8`, clean, providing recon, web, ports, scope, database, models, reports, and process primitives. No Member 2 source edits.
- **Web-surface collection (`marsadix/web_recon/archive.py`, `crawler.py`, `js_extract.py`, `verify.py`, `discovery.py`)**: archive APIs, Katana/built-in crawling, JS endpoint extraction, status verification, subdomain discovery.
- **Safety and transport (`scope_filter.py`, `http_client.py`, `rate_limit.py`, `logging_utils.py`, `errors.py`)**: canonicalization/scope checks, manual redirects, bounded HTTP, token bucket, redaction, structured outcomes.
- **Tool integration (`tools.py`, `nuclei.py`)**: base-backed process execution, tool resolution, Katana/HTTPX/GAU/Subfinder adapters, Nuclei A1–A4.
- **Security inspection (`security.py`)**: W7 headers/WAF, W9 secret patterns, W10 TLS analysis.
- **Persistence/orchestration (`storage.py`, `pipeline.py`, `stage.py`, `cli.py`, `__main__.py`)**: scan resolution, web/finding persistence, outputs, mode gating, optional stage adapter, commands.
- **Tests (`tests/`)**: 48 tests covering parsers, normalization/config, scope/HTTP/crawler, tool wrappers, discovery/storage, pipeline, scan resolution, security, and Nuclei.
- **Project assets**: `marsadix/config/config.web_recon.example.toml`, `scripts/install_web_recon_tools.sh`, `pyproject.toml`, this audit report, local `.tools/bin`, and runtime `output/` artifacts.
- **Runtime state**: local `marsadix.db` and output files are generated artifacts, not source deliverables; the base test checkout remains clean.

### 11.6 Final verification

```text
Extension: 48 passed
Base:      378 passed
Failures:  0
```

Additional checks performed during this pass:

- Remote `origin/main` resolved to `43fabb8`; local base checkout matched and was clean.
- All extension `marsadix.*` imports resolve against the remote base tree.
- A fake Nuclei executable was run through the real base process layer against a loopback server; the JSONL match was parsed, scope-checked, persisted as `source=nuclei`, and counted in the pipeline report.
- `doctor --json` reported all seven tools available: `httpx`, `katana`, `gau`, `subfinder`, `dnsx`, `nuclei`, `waybackurls`.
- Live `nuclei v3.11.1` was exercised directly and through the pipeline. The pipeline run exited `0`, reported `status=completed`, stored `300` web items and `8` findings (5 header/WAF findings, 3 Nuclei findings) in `marsadix.db` scan `#4`; the scan row now records `status=completed`.
- `git status` in the base checkout remained clean; no commit or push was made.

Residual risks are the same as Section 9: live third-party archive availability, target/template upstream availability, conservative WAF/TLS/secret heuristics, no browser rendering/exploitation, and the intentional base-stage integration boundary.

### 11.7 Live verification note (2026-10-30)

- The requested target `testphp.vulnweb.com` resolved to `44.228.249.3`, but TCP 80/443 timed out repeatedly; the sibling Acunetix demo host `http://testasp.vulnweb.com/` was reachable and was used as the live substitute.
- Active scans require a scope file and global flags before the subcommand. The effective command shape was:
  `marsadix-web-recon --config <cfg> --db marsadix.db run testasp.vulnweb.com --mode full --scope <scope-file> --seed http://testasp.vulnweb.com/ --no-archive --no-crawl --json`.
- Nuclei was initially given a `-timeout` equal to the 300-second process budget; broad template tags overloaded the demo host and the process was killed. The wrapper was corrected to pass the configured per-request timeout (`request_timeout=10`) while retaining `nuclei_timeout` as the process budget.
- A focused live re-run with `nuclei_tags=["tech"]` and `nuclei_rate_limit=10` completed in `113.7 s`: Nuclei returned `3` findings (`waf-detect`, `microsoft-iis-version`, `tech-detect`) and persisted them with `source=nuclei`.
