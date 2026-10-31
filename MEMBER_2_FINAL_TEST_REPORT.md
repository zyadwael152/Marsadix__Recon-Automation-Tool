# Member 2 Final Automated Test and Live Validation Report

- **Date:** 2026-10-30
- **Workspace:** `/mnt/d/opencode-workspace/marsadix_project`
- **Module:** `marsadix_member2` v1.0.0
- **Live target:** `http://testasp.vulnweb.com/`
- **Database:** `marsadix.db`
- **Raw test artifacts:** `test_artifacts/member2_final/`
- **Report status:** **PASS with external-service degradation**

## 1. Executive Summary

The automated suites passed completely (`48 + 378 = 426` tests, zero failures). All seven external tools were detected. URL normalization and subdomain discovery completed. Passive and full pipelines executed without Python exceptions or crashes, but both were marked `partial` because the public Wayback CDX endpoint returned upstream HTTP errors. The live full run still reached `testasp.vulnweb.com`, collected 897 archive records through GAU, verified 216 URLs, parsed 52 JavaScript files, ran Nuclei successfully, and preserved all database findings and web items.

| # | Test | Exit | Result |
| --- | --- | --- | --- |
| 1 | `doctor --json` | 0 | All 7 tools available |
| 2 | `normalize` | 0 | `https://example.com/b?b=2` |
| 3 | `discover example.com --json` | 0 | 25,522 unique hosts; Wayback failed |
| 4 | Passive `example.com` run | 1 | `partial`; no candidates; Wayback network error |
| 5 | Full live `testasp.vulnweb.com` run | 1 | `partial`; 897 archive records; 300 candidates; 216 verified |
| 6 | Extension tests | 0 | 48 passed |
| 7 | Base tests | 0 | 378 passed |
| 8 | Database inspection | 0 | 600 web items; 20 findings; latest scan completed |

**Key database totals**

- `web_items`: **600**
  - `endpoint`: 545
  - `js_file`: 53
  - `url`: 2
- `findings`: **20**
  - `skill`: 12 (medium 3, low 8, info 1)
  - `nuclei`: 8 (info 7, low 1)
- Latest scan: **#4**, `testasp.vulnweb.com`, mode `full`, status `completed`
- Latest scan contents: **300 web items**, **8 findings**

The exit code `1` on the passive and full runs was produced by the CLI's normal policy (`0` only for `completed`/`dry-run`), not by an unhandled exception. The underlying failure was external: Wayback CDX returned HTTP 504/503/network errors.

---

## 2. Environment and Tool Verification

### Command

```bash
cd /mnt/d/opencode-workspace/marsadix_project
.venv/bin/marsadix-member2 doctor --json
```

**Exit code:** `0`

### Tool availability

| Tool | Available | Path |
| --- | --- | --- |
| `httpx` | yes | `/mnt/d/opencode-workspace/marsadix_project/.tools/bin/httpx` |
| `katana` | yes | `/home/Hamza/go/bin/katana` |
| `gau` | yes | `/mnt/d/opencode-workspace/marsadix_project/.tools/bin/gau` |
| `subfinder` | yes | `/mnt/d/opencode-workspace/marsadix_project/.tools/bin/subfinder` |
| `dnsx` | yes | `/mnt/d/opencode-workspace/marsadix_project/.tools/bin/dnsx` |
| `nuclei` | yes | `/mnt/d/opencode-workspace/marsadix_project/.tools/bin/nuclei` |
| `waybackurls` | yes | `/mnt/d/opencode-workspace/marsadix_project/.tools/bin/waybackurls` |

ProjectDiscovery HTTPX was also correctly detected: `/mnt/d/opencode-workspace/marsadix_project/.tools/bin/httpx`.

### Runtime

```text
Python: 3.14.7
Platform: Linux Hamza 6.6.87.2-microsoft-standard-WSL2 x86_64 GNU/Linux
Nuclei Engine Version: v3.11.1
Nuclei templates: v10.5.1
Base checkout: 43fabb8 feat: complete Person 5 tasks
Base checkout status: clean
```

Nuclei emits this non-fatal warning:

```text
WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or
(go1.20~1.26 and arm64 CPU), but your environment is not suitable
and will fallback to encoding/json
```

This does not prevent scanning; it only changes the JSON parser used by Nuclei.

### Scope file

`scope.txt` was verified and updated to contain:

```text
example.com
testasp.vulnweb.com
```

Full doctor output is preserved at `test_artifacts/member2_final/01-doctor.json`.

---

## 3. URL Normalization Test

### Command

```bash
cd /mnt/d/opencode-workspace/marsadix_project
.venv/bin/marsadix-member2 normalize 'HTTPS://Example.com:443/a/../b?utm_source=test&b=2#frag'
```

**Exit code:** `0`

### Output

```text
https://example.com/b?b=2
```

### Analysis

- Scheme and host were lowercased.
- Default HTTPS port `443` was removed.
- Dot-segment `/a/../b` was normalized to `/b`.
- Tracking parameter `utm_source=test` was removed.
- Non-tracking query parameter `b=2` was preserved.
- Fragment `#frag` was removed.

This matches the expected canonicalization contract.

---

## 4. Subdomain Discovery Test

### Command

```bash
cd /mnt/d/opencode-workspace/marsadix_project
.venv/bin/marsadix-member2 discover example.com --json
```

**Exit code:** `0`
**Duration:** approximately 4 minutes 39 seconds
**Scan resolved:** `#1` (`example.com`, passive)

### Summary output

```text
target: example.com
scan_id: 1
host_count: 25522
saved_assets: 0
outcome subfinder ok discovered=25521 kept=25521
outcome crt.sh   ok discovered=7     kept=7
outcome gau      ok discovered=0     kept=0
outcome wayback  failed: ArchiveError: Wayback CDX returned HTTP network error
outcome commoncrawl skipped
```

### Sample hosts

```text
0.0.1.example.com
0.example.com
00.example.com
000.example.com
0000-forbidden.example.com
000c.example.com
001.example.com
002.example.com
01.example.com
012.example.com
```

### Analysis

- Discovery itself succeeded and returned 25,522 unique in-scope hosts.
- `saved_assets` is `0` because the command did not include `--save`; this is expected behavior, not a write failure.
- `subfinder` supplied 25,521 hosts and `crt.sh` added 7, with overlap.
- Wayback failed independently, consistent with the later pipeline failures.
- The full 1.5 MB JSON output is preserved at `test_artifacts/member2_final/03-discover.json`.

---

## 5. Passive Pipeline Run

### Command

```bash
cd /mnt/d/opencode-workspace/marsadix_project
.venv/bin/marsadix-member2 --db marsadix.db run example.com --mode passive --json
```

**Exit code:** `1`
**Report status:** `partial`
**Duration:** 156,427 ms (2 min 36 s)
**Scan:** `#1`

### Key output

```text
target          example.com
scan_id         1
mode            passive
status          partial
archive_records 0
candidates      0
stored          0
checked         0
findings_stored 0
errors          []
```

### Outcome details

| Component | Status | Discovered | Kept | Error |
| --- | --- | --- | --- | --- |
| `gau` | ok | 0 | 0 | none |
| `wayback` | failed | 0 | 0 | `ArchiveError: Wayback CDX returned HTTP network error` |
| `commoncrawl` | skipped | 0 | 0 | disabled |

### Safety behavior

The report correctly recorded that passive mode suppressed target contact:

```text
status verification disabled: passive mode must not contact the target
crawling disabled: passive mode must not contact the target
DNS asset discovery disabled: passive mode
security inspection skipped: passive mode
nuclei skipped: passive mode
```

### Analysis

- The passive pipeline did not contact `example.com` and did not run active stages.
- GAU returned no URLs for `example.com`.
- Wayback CDX failed after retries with a network-level error.
- No candidates therefore existed, so no web items or findings were written by this run.
- The CLI returned `1` because `report.status` was `partial`.
- The pre-existing findings for scan `#1` in the database were created earlier (timestamps around 15:03 and 15:08 UTC) and are not products of this passive run.

The complete JSON output is preserved at `test_artifacts/member2_final/04-passive.json`.

---

## 6. Full Live Pipeline Run

### Command

```bash
cd /mnt/d/opencode-workspace/marsadix_project
.venv/bin/marsadix-member2 --db marsadix.db run http://testasp.vulnweb.com/ --mode full --scope scope.txt --json
```

**Exit code:** `1`
**Report status:** `partial`
**Duration:** 634,760 ms (10 min 34.8 s)
**Resolved scan:** `#4` (`testasp.vulnweb.com`, full)

### Top-level output

```json
{
  "target": "testasp.vulnweb.com",
  "scan_id": 4,
  "mode": "full",
  "status": "partial",
  "candidates": 300,
  "stored": 0,
  "skipped_existing": 300,
  "counts": {},
  "source_counts": {"existing": 300},
  "archive_records": 897,
  "checked": 216,
  "findings_stored": 0,
  "nuclei_findings": 1,
  "security_findings": 5,
  "waf": {},
  "duration_ms": 634760,
  "skipped": [],
  "errors": []
}
```

### Tool outcomes

| Tool / stage | Status | Discovered | Kept | Duration | Notes |
| --- | --- | --- | --- | --- | --- |
| `gau` | ok | 897 | 897 | 33,135 ms | Used provider `wayback`; returned archive URLs |
| `wayback` | failed | 0 | 0 | 60,277 ms | `ArchiveError: Wayback CDX returned HTTP 503` |
| `commoncrawl` | skipped | 0 | 0 | 0 | Disabled by default |
| `archive-host-discovery` | skipped | 1 | 0 | 0 | No active DNS discovery performed |
| `katana` | ok | 55 | 55 | 12,941 ms | Depth 2, rate 50/s |
| `js-extractor` | ok | 0 | 0 | 211,653 ms | 52/52 scripts parsed; 0 endpoints; 0 secrets |
| `httpx` | ok | 335 | 216 | 111,646 ms | 895 inputs, 335 checked, 216 allowed |
| `security-headers` | ok | 5 | 5 | 11,088 ms | 1 target checked; WAF map empty |
| `tls-check` | skipped | 0 | 0 | 0 | No HTTPS targets in scope |
| `nuclei` | ok | 1 | 1 | 193,415 ms | Return code 0; group `tech-cve` |

### Nuclei invocation

```text
nuclei -silent -jsonl -no-color -duc -ni -dr
  -rate-limit 50
  -timeout 10
  -retries 2
  -tags takeover,exposure,misconfig,cve,tech
  -severity critical,high,medium,low,info
```

The `-timeout 10` is the per-request HTTP timeout; the overall process budget remains 300 seconds (`nuclei_timeout`). Nuclei completed with return code `0` in 193.4 seconds.

### Output files

```text
output/testasp.vulnweb.com_m2_all_urls.txt
output/testasp.vulnweb.com_m2_endpoints.txt
output/testasp.vulnweb.com_m2_js_files.txt
output/testasp.vulnweb.com_m2_summary.json
```

### Analysis

- The target was reachable over HTTP; TLS inspection was correctly skipped because no HTTPS target entered scope.
- GAU still produced 897 archive records despite the direct Wayback CDX failure, so archive collection was degraded rather than empty.
- The 300 candidates already existed in scan `#4`; therefore `stored=0` and `skipped_existing=300`.
- Five security-header findings and one Nuclei match were re-discovered. They deduplicated against the eight findings already persisted for scan `#4`, so `findings_stored=0`.
- The full pipeline had no Python errors and no tool timeout. `status=partial` was caused solely by the failed Wayback provider.
- The latest scan row remains `completed` with 300 web items and 8 findings.

The full JSON report is preserved at `test_artifacts/member2_final/05-full-live.json`.

---

## 7. Database and Findings Inspection

Inspection was performed through the project's `marsadix.db` helper layer and read-only SQL.

### Scans

| ID | Target | Mode | Status | Scope file | Started (UTC) | Finished (UTC) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | example.com | passive | interrupted | null | 2026-10-28T16:40:50 | 2026-10-28T16:42:22 |
| 2 | testphp.vulnweb.com | passive | pending | null | 2026-10-28T17:19:40 | null |
| 3 | hackerone.com | passive | pending | null | 2026-10-30T12:34:35 | null |
| 4 | testasp.vulnweb.com | full | **completed** | `/tmp/opencode/testasp-scope.txt` | 2026-10-30T12:59:11 | 2026-10-30T14:12:49 |

**Latest scan:** `#4`, target `testasp.vulnweb.com`, mode `full`, status **`completed`**.

### Web items by kind

**Global**

| Kind | Count |
| --- | ---: |
| endpoint | 545 |
| js_file | 53 |
| url | 2 |
| **Total** | **600** |

**By scan**

| Scan | Kind | Count |
| --- | --- | ---: |
| 2 | endpoint | 298 |
| 2 | js_file | 1 |
| 2 | url | 1 |
| 4 | endpoint | 247 |
| 4 | js_file | 52 |
| 4 | url | 1 |

### All findings

| ID | Scan | Source | Severity | Template ID | Title |
| ---: | ---: | --- | --- | --- | --- |
| 1 | 4 | skill | medium | `missing-security-header:csp` | Missing security header: Content-Security-Policy |
| 2 | 4 | skill | low | `missing-security-header:x-content-type-options` | Missing security header: X-Content-Type-Options |
| 3 | 4 | skill | low | `missing-security-header:x-frame-options` | Missing security header: X-Frame-Options or CSP frame-ancestors |
| 4 | 4 | skill | low | `missing-security-header:referrer-policy` | Missing security header: Referrer-Policy |
| 5 | 4 | skill | low | `missing-security-header:permissions-policy` | Missing security header: Permissions-Policy |
| 11 | 4 | nuclei | info | `waf-detect` | WAF Detection |
| 12 | 4 | nuclei | info | `microsoft-iis-version` | Microsoft IIS version detect |
| 13 | 4 | nuclei | info | `tech-detect` | Wappalyzer Technology Detection |
| 14 | 1 | skill | info | `waf-detected` | WAF detected: cloudflare |
| 15 | 1 | skill | medium | `missing-security-header:hsts` | Missing security header: Strict-Transport-Security |
| 16 | 1 | skill | medium | `missing-security-header:csp` | Missing security header: Content-Security-Policy |
| 17 | 1 | skill | low | `missing-security-header:x-content-type-options` | Missing security header: X-Content-Type-Options |
| 18 | 1 | skill | low | `missing-security-header:x-frame-options` | Missing security header: X-Frame-Options or CSP frame-ancestors |
| 19 | 1 | skill | low | `missing-security-header:referrer-policy` | Missing security header: Referrer-Policy |
| 20 | 1 | skill | low | `missing-security-header:permissions-policy` | Missing security header: Permissions-Policy |
| 21 | 1 | nuclei | info | `dns-waf-detect` | DNS WAF Detection |
| 22 | 1 | nuclei | info | `waf-detect` | WAF Detection |
| 23 | 1 | nuclei | low | `weak-cipher-suites` | Weak Cipher Suites Detection |
| 24 | 1 | nuclei | info | `http-missing-security-headers` | HTTP Missing Security Headers |
| 25 | 1 | nuclei | info | `tech-detect` | Wappalyzer Technology Detection |

### Finding distribution

| Source / severity | Count |
| --- | ---: |
| skill / medium | 3 |
| skill / low | 8 |
| skill / info | 1 |
| nuclei / info | 7 |
| nuclei / low | 1 |
| **Total** | **20** |

**By scan:** scan `#1` has 12 findings; scan `#4` has 8 findings.

### Latest scan contents

```text
latest scan:               #4
latest status:             completed
latest web_items total:    300
latest findings total:     8
latest web_items by kind:  endpoint=247, js_file=52, url=1
```

Raw inspection output is preserved at `test_artifacts/member2_final/06-db-inspection.txt`.

---

## 8. Automated Test Suites

### Extension suite

```bash
cd /mnt/d/opencode-workspace/marsadix_project
.venv/bin/python -m pytest -q tests
```

**Exit code:** `0`

```text
................................................                         [100%]
48 passed in 19.68s
```

### Base Marsadix suite

```bash
cd /mnt/d/opencode-workspace/marsadix_project
.venv/bin/python -m pytest -q Marsadix__Recon-Automation-Tool/tests
```

**Exit code:** `0`

```text
........................................................................ [ 19%]
........................................................................ [ 38%]
........................................................................ [ 57%]
........................................................................ [ 76%]
........................................................................ [ 95%]
..................                                                       [100%]
378 passed in 79.62s (0:01:19)
```

**Combined:** 426 tests passed, 0 failed.

The base checkout remained clean:

```text
43fabb8 feat: complete Person 5 tasks
```

Raw test outputs are preserved at `test_artifacts/member2_final/07-tests-extension.out` and `test_artifacts/member2_final/08-tests-base.out`.

---

## 9. Troubleshooting and Issues

### I-1. Wayback CDX instability caused partial runs and exit code 1

**Severity:** Medium
**Status:** Open; external service issue with a code-level handling consequence

Evidence:

```text
Passive: ArchiveError: Wayback CDX returned HTTP network error
Full:    ArchiveError: Wayback CDX returned HTTP 503
Manual probe: HTTP 504 after 61.2 seconds for the domain-match query
Manual limit-5 probe: HTTP 200 in 6.6 seconds
```

The small Wayback query succeeds, but the domain-wide query used by the collector is timing out or being throttled by the upstream service. The collector retries and then degrades gracefully; no scan crash occurs. However, the failed provider still marks the whole report `partial`, and the CLI returns `1`.

**Recommended solutions:**

1. Treat an individual archive-provider failure as a warning when at least one provider succeeds, or introduce an explicit `degraded` status that exits `0`.
2. Reduce Wayback pressure: lower `max_archive_urls` for Wayback, increase `archive_timeout`, and/or add a provider-specific timeout.
3. Prefer GAU when GAU already returned records; in this run GAU produced 897 records while direct Wayback CDX was failing.
4. Add a `--archive-source gau` fallback in the test runner for environments where Wayback is unstable.

### I-2. Partial scans return a nonzero process exit

**Severity:** Medium
**Status:** Documented behavior

`cmd_run` returns `0` only for `completed` or `dry-run`; `partial` returns `1`. In this test the data collection succeeded, but a third-party provider failed. Automation that treats exit `1` as a total failure will misclassify the run.

**Recommended solution:** Decide and document the intended contract. If partial data is acceptable, return `0` for `partial` or use a distinct exit code (for example `2`) and document it in the CLI help.

### I-3. Re-running an existing scan hides new writes through deduplication

**Severity:** Low
**Status:** Expected deduplication, but potentially confusing

The full live run reported:

```text
candidates        300
stored            0
skipped_existing  300
security_findings 5
nuclei_findings   1
findings_stored   0
```

All 300 web items and all rediscovered findings already existed in scan `#4`, so the database correctly deduplicated them. The run did execute, but the output can look as if nothing happened.

**Recommended solutions:**

1. Use a fresh scan row or a fresh database for clean validation.
2. Add a `--new-scan` option, or make the CLI create a new scan for each explicit run rather than reusing the latest scan.
3. Report both `new` and `existing` totals clearly in the JSON summary.

### I-4. Reused scan metadata is stale

**Severity:** Medium
**Status:** Confirmed mismatch

The latest scan row is still:

```text
id: 4
status: completed
scope_file: /tmp/opencode/testasp-scope.txt
finished_at: 2026-10-30T14:12:49+00:00
```

The full live validation used the project `scope.txt` and completed around 15:39 UTC, but the scan row still points to the older temporary scope file and retains an older `finished_at`. The explicit `--scope` path is not persisted onto an existing scan.

**Recommended solutions:**

1. When `--scope PATH` is supplied, update the resolved scan's `scope_file` to that path.
2. Update `finished_at` after each extension run, even when the base scan row was already completed.
3. Prefer creating a new scan for each independent run so historical metadata remains correct.

### I-5. Interrupted/passive scan status is not finalized

**Severity:** Low
**Status:** Confirmed

Scan `#1` remains `interrupted` even though the passive extension run completed with a `partial` report. The extension only finalizes scans that are `pending` or `running`; it intentionally does not overwrite an `interrupted` base scan.

**Recommended solution:** Decide whether an extension run may finalize an interrupted scan. If not, document that status is owned by the base scan and should be interpreted alongside the extension's own JSON report.

### I-6. Discovery output is very large and currently unsaved

**Severity:** Low
**Status:** Expected behavior

`discover example.com --json` returned 25,522 hosts and a 1.5 MB JSON document, but `saved_assets` was `0` because `--save` was not supplied. This is correct behavior, but the output volume is operationally significant.

**Recommended solutions:**

1. Add a `--max-hosts` / `--limit` option for display and save operations.
2. Require `--save` explicitly and report the estimated write count before inserting.
3. Consider filtering known-wildcard/dangling subdomains before output.

### I-7. Report `counts` is empty when all candidates already exist

**Severity:** Low
**Status:** Confirmed reporting inconsistency

The full run had `candidates=300`, but `counts={}` because the pipeline overwrites `report.counts` with `storage.by_kind`, which only covers newly stored rows. The per-kind candidate summary is lost from the JSON report.

**Recommended solution:** Keep `counts` as the final candidate-kind counts and add a separate `stored_counts` or `deduped_counts` field. This would make reruns easier to interpret.

### I-8. Nuclei sonic/ast compatibility warning

**Severity:** Informational
**Status:** Non-blocking

Nuclei warns that the Go 1.27 environment is outside the supported range for `sonic/ast`, then falls back to `encoding/json`. Nuclei executed successfully and returned valid JSONL.

**Recommended solution:** Build Nuclei with a supported Go version (1.26 or earlier) if the optimization matters, or continue using the verified fallback.

### I-9. TLS check skipped on the live target

**Severity:** Informational
**Status:** Expected

`testasp.vulnweb.com` only responded over HTTP in this environment; HTTPS timed out. The TLS stage correctly reported `no HTTPS targets in scope` instead of generating false findings.

**Recommended solution:** None; use an HTTPS-capable target for TLS validation.

---

## 10. Conclusions and Recommended Next Steps

1. **Tooling is complete:** all seven tools and ProjectDiscovery HTTPX are installed and resolvable.
2. **Automated suites are green:** 48 extension tests and 378 base tests pass.
3. **Normalization and discovery work:** normalization output is canonical; discovery produced 25,522 unique hosts.
4. **Live scanning works:** the full pipeline reached the target, collected 897 archive records, verified 216 URLs, parsed 52 JavaScript files, and ran Nuclei successfully.
5. **Database persistence is verified:** the latest scan contains 300 web items and 8 findings; the database contains 600 web items and 20 findings overall.
6. **The only execution failures were upstream Wayback CDX errors.** No Python exception, crash, or tool timeout occurred in the validated runs.
7. **Operational follow-ups:** harden archive-provider fallback and exit-code semantics, persist `--scope` and `finished_at` on reused scans, and use a fresh scan for clean rerun metrics.

---

## Appendix A. Raw Artifact Index

All raw outputs are in `test_artifacts/member2_final/`:

| File | Contents |
| --- | --- |
| `01-doctor.json` | Full doctor JSON |
| `01-doctor.err` | Doctor stderr (empty) |
| `02-normalize.out` | Normalization stdout |
| `02-normalize.err` | Normalization stderr (empty) |
| `03-discover.json` | Full 25,522-host discovery JSON (1.5 MB) |
| `03-discover.err` | Discovery stderr |
| `04-passive.json` | Full passive pipeline JSON |
| `04-passive.err` | Passive pipeline log |
| `05-full-live.json` | Full live pipeline JSON |
| `05-full-live.err` | Full live pipeline log |
| `06-db-inspection.txt` | Raw scan, web-item, and finding inspection |
| `07-tests-extension.out` | Extension pytest output |
| `08-tests-base.out` | Base pytest output |
| `09-environment.txt` | Python, platform, Nuclei, scope, and base Git state |
| `wayback-probe.html` | Small Wayback CDX probe response |
| `wayback-domain-probe.out` | Wayback domain-query 504 response |

The discovery JSON is intentionally not embedded in this report because it contains 25,522 host records. The complete file is retained in the artifact directory.

## Appendix B. Environment Snapshot

```text
Python: 3.14.7
Platform: Linux Hamza 6.6.87.2-microsoft-standard-WSL2 x86_64 GNU/Linux
Nuclei: v3.11.1
Templates: v10.5.1
Scope:
example.com
testasp.vulnweb.com
Base Git: 43fabb8 feat: complete Person 5 tasks
Base working tree: clean
```
