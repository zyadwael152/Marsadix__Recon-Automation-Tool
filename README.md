<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&height=220&color=0:081A2F,50:123B5D,100:16A6A1&text=MARSADIX&fontColor=FFFFFF&fontSize=58&fontAlignY=38&desc=Recon%20smarter.%20Verify%20safely.%20Track%20every%20change.&descAlignY=58&descSize=16" width="100%" alt="Marsadix banner" />

<img src="assets/marsadix_logo.png" alt="Marsadix - Recon & Vuln Engine" width="460">

### An authorization-first reconnaissance, vulnerability-correlation and CVE-monitoring command-line tool

*Discover the surface. Prioritize the evidence. See what changed.*

</div>

---


## 📍 Current status

This is an active student project. The **core engine** (scope enforcement, scan pipeline, scan-to-scan diffing, asset-change alerts, HTML/JSON reporting, OWASP Top 10 coverage mapping, knowledge graph) is implemented and tested, as are the **recon, web-surface and port/service stages**. The **ASM/Nuclei detection stage and the CVE monitor** are still being built — see the [Roadmap](#️-roadmap) for exactly what's done.

## ⚡ Overview

**Marsadix** is an open-source command-line tool that brings reconnaissance, service discovery, vulnerability correlation, safe verification, scan comparison and CVE monitoring into one workflow.

You give it an **authorized domain**. It collects everything related to that domain (subdomains, IPs, services, technologies, URLs, JavaScript files, endpoints and public emails), feeds what it finds back into the process (recursive recon) while staying inside the authorized scope, correlates detected services and technologies with known CVEs, assigns a **confidence level** to every finding, confirms findings with **non-destructive checks only**, and produces a consolidated report.

Everything is stored, so later scans can be **compared** to show what changed, and newly published CVEs can be **matched against the technologies you have already discovered**, with an alert when one applies.

Marsadix deliberately **stops at verification**. Exploitation and impact analysis remain the tester's job.

## 🧩 The problem

Security assessments usually mean running several tools and manually stitching their results together.

- 🔎 Raw output is noisy and hard to prioritize.
- 🧩 Service, technology and version data end up scattered across tools and files.
- ⚠️ Matching a version to a CVE alone produces false positives (for example, distribution backports).
- 🔁 Many workflows run once and stop, instead of feeding discoveries back into further recon.
- 🕰️ Changes between scans, and newly published CVEs for already-known technologies, are easy to miss.
- 🛡️ Scope and CDN safety need deliberate attention, especially when recon expands recursively.

**Marsadix aims to connect the dots**, with evidence, confidence levels and scope safety built into the workflow.

## ✨ Core capabilities

| 🕵️ **Recursive reconnaissance** Passive and active discovery that feeds new findings back into the process, within scope and a depth limit. | 🗂️ **Broad collection** Subdomains, IPs, ports, services, technologies, URLs, JavaScript files, endpoints and public emails. |
| --- | --- |
| 🧠 **CVE correlation** Connect detected service and technology evidence with known vulnerabilities, prioritized with **EPSS** exploitation-probability scores. | 📊 **Confidence scoring** Separate possible, likely and confirmed findings based on evidence, plus a **source-confidence score** per asset from how many independent tools found it. |
| 🛡️ **Safe verification** Validate findings with non-destructive checks, without exploitation — every finding carries `exploited: false`. | 🔁 **Scan diffing** Compare scan history to identify new assets, ports, technologies and findings. |
| 🔔 **CVE monitor** Match newly published CVEs against stored technologies and send alerts. | 📄 **Unified reports** Prioritized, filterable HTML report (Triage and Engagement views) plus machine-readable JSON. |
| 🧭 **OWASP Top 10 mapping** Every finding is tagged with its OWASP Top 10 (2021) category; the report shows how much of the Top 10 was actually tested. | 🕸️ **Knowledge Graph** Link assets, services, technologies and CVEs together so questions like "what else shares this IP?" have an answer, not just a list. |

## 🔬 How it works

```mermaid
flowchart TD
    A(["🎯 Authorized target + scope"]) --> B["1. Passive recon"]
    B --> C["2. Resolve assets, check CDN, filter scope"]
    C --> D["3. Active recon"]
    D --> E["4. Collect URLs, JS files, endpoints, technologies, emails"]
    E --> F{"New in-scope assets found?"}
    F -- "Yes (within depth limit)" --> C
    F -- "No" --> G["5. Service/technology-to-CVE correlation"]
    G --> H["6. Safe verification"]
    H --> I["7. Prioritized HTML + JSON report"]
    I --> J[("8. Store results in local database")]
    J --> K["9. Diff against previous scans"]
    J -. "periodic" .-> L["10. CVE monitor: match new CVEs to stored technologies"]
    L --> M(["🔔 Alert"])

    classDef startEnd fill:#123B5D,stroke:#16A6A1,color:#FFFFFF
    classDef process fill:#10283F,stroke:#3D7894,color:#FFFFFF
    class A,M startEnd
    class B,C,D,E,F,G,H,I,J,K,L process
```

### What gets collected

| Category | Examples |
| --- | --- |
| Assets | Subdomains, DNS records, resolved IPs, ASN / network owner, CDN detection |
| Services | Open ports, service names and versions, banners |
| Technologies | Web servers, frameworks, CMS, JavaScript libraries and their versions where detectable |
| Web surface | URLs (including archived ones), JavaScript files, endpoints and parameters found in JS and crawling |
| People data | Public email addresses (public sources only, see the privacy note below) |

### Recursive recon, safely

Every new asset discovered (a subdomain mentioned in a JavaScript file, a new host behind a redirect) goes back through the pipeline, but only after it passes the scope check. Recursion is bounded by a configurable **depth limit** and **de-duplication**, so the process ends and does not wander into third-party infrastructure such as CDNs, analytics or other external services referenced by the target.

## 🎚️ Finding confidence

A version match alone does **not** prove a target is vulnerable. The confidence model makes the available evidence explicit.

| Evidence | Confidence | Meaning |
| --- | --- | --- |
| Version match only | 🟡 **Possible · Low** | Potential match; needs more evidence |
| Template or banner-specific match | 🟠 **Likely · Medium** | Stronger indication, but not definitive |
| Safe check demonstrates the issue | 🟢 **Confirmed · High** | Supported by non-destructive verification |

Distribution backports, inaccurate banners and other version-matching pitfalls must be taken into account.

### Detection, not exploitation

Every check Marsadix runs — from a Nuclei template to a custom XSS/SQLi probe — stops at **verification**. No payload extracts data, changes state or executes code. Every finding carries `exploited: false`, always.

Results use three states instead of a binary "vulnerable / not vulnerable":

| Status | Meaning |
| --- | --- |
| 🔴 **Detected** | Clear evidence found (a payload reflected unescaped, a response delay matching a time-based probe, an exposed panel responding) |
| 🟠 **Needs Review** | A partial signal (unusual timing or response-size change) — inconclusive, worth a manual look |
| ⚪ **No Indicators** | The automated checks found nothing. This is **not** the same as "not vulnerable" — detection relies on a fixed set of payloads and can miss custom logic, WAF-filtered variants, or anything outside what was tested |

Every report includes a **Detection Limitations** section making this explicit, instead of letting a clean scan be read as a clean bill of health.

### Source confidence

A subdomain found by one passive source is weaker evidence than one confirmed by several independent tools *and* DNS resolution *and* a live HTTP response. Marsadix records **every source that found each asset** and derives a 0–100 confidence score from that, rather than treating "discovered" as a single yes/no fact.

## 🔔 CVE monitor

Reconnaissance is usually a one-time snapshot, but new vulnerabilities are published every day. The CVE monitor turns the technology inventory into a watch list.

1. During scans, Marsadix stores each asset with its detected technology, version (when available) and confidence.
2. A periodic job fetches newly published or updated CVEs from public sources such as the **NVD API** and **CISA KEV** (and optionally other advisory databases).
3. New CVEs are matched against the stored technologies (CPE matching).
4. When a match is found, an alert is sent through a configured channel (planned: Telegram, Discord, email or webhook).

Alerts carry the **confidence level** of the match and a priority based on severity and known-exploitation status, so a technology detected without an exact version does not create the same urgency as a confirmed version match.

> **Limitations to keep in mind:** newly published CVEs sometimes appear in NVD before their product (CPE) data is complete, so matching can lag. An NVD API key is recommended to avoid rate limits.

## 🔁 Scan diffing

Each scan is stored, and Marsadix compares it with previous ones to answer: *what is new, what disappeared, and what changed?* Examples include new subdomains, newly opened ports, changed technologies and versions, and newly detected findings. This turns a one-off scan into continuous attack-surface monitoring.

## 🛡️ Safety-first by design

- **Scope filtering:** targets and every newly discovered asset are validated against the authorized scope before active scanning.
- **CDN and shared-hosting awareness:** a CDN or hosting provider's IP is never treated as permission to scan unrelated assets, and ASN ownership is checked rather than assumed.
- **Verify-only approach:** no exploitation is performed by the tool.
- **Passive by default:** `--mode passive` (the default) sends no traffic to the target; `standard` and `full` require an explicit `--scope`, and injection-style checks additionally require `--allow-injection`.
- **Configurable rates:** request rates are adjustable to reduce load on target systems.
- **Evidence-driven output:** uncertainty is communicated instead of treating every match as confirmed.
- **Privacy:** email addresses are personal data. Collect them from public sources only, store the minimum needed, and do not publish them in reports or repositories.

> Only test systems you own or have explicit permission to assess. Follow the target's rules of engagement and bug bounty scope.

## 💻 Command-line interface

Marsadix is a command-line tool, designed to run in terminals, scripts and automation pipelines. The commands below are **implemented and working today**; a command whose underlying module isn't written yet (see [Roadmap](#️-roadmap)) reports that explicitly instead of silently doing nothing.

```bash
# Run a scope-checked scan on an authorized domain
marsadix scan example.com --scope scope.txt

# Compare the latest scan with the previous one (or two specific scan IDs)
marsadix diff example.com
marsadix diff example.com --old 3 --new 7

# Generate the HTML + JSON report for the latest scan
marsadix report example.com --out output

# Show the stored knowledge graph / list every scan of a target
marsadix graph example.com
marsadix snapshots example.com

# Stream Certificate Transparency logs for new subdomains
marsadix ct-monitor example.com

# Check new CVEs against stored technologies and send alerts
# (the monitor module is not implemented yet; exits 3 with a clear message)
marsadix monitor --dry-run

# Check whether hosts fall inside an authorized scope file
marsadix scope scope.txt dev.example.com api.example.com

# Check which external tools (subfinder, nmap, nuclei...) are installed
marsadix doctor
```

Every scan is scope-checked before anything runs, is stored so it can be diffed against later scans, and automatically raises an alert the moment a new subdomain or newly opened port appears (deduplicated, so re-running never re-sends the same alert).

## 🧰 Planned technology stack

These are candidate building blocks from the project plan; integrations may change after evaluation.

| Purpose | Candidate tools / sources |
| --- | --- |
| Passive discovery | [Subfinder](https://github.com/projectdiscovery/subfinder), [OWASP Amass](https://github.com/owasp-amass/amass), [crt.sh](https://crt.sh/), [Wayback Machine](https://web.archive.org/) |
| DNS / resolution | [dnsx](https://github.com/projectdiscovery/dnsx), CDN detection, ASN ownership lookup |
| Ports / services | [Naabu](https://github.com/projectdiscovery/naabu), [Nmap](https://nmap.org/), [httpx](https://github.com/projectdiscovery/httpx) |
| URLs / JS / endpoints | [gau](https://github.com/lc/gau) for passive archived URLs (scope-filtered and stored in `web_items`); [katana](https://github.com/projectdiscovery/katana) for active crawling in `full` mode; JavaScript endpoint extractors such as [jsluice](https://github.com/BishopFox/jsluice) or LinkFinder remain future integrations |
| Technology detection | httpx technology detection, Wappalyzer-style rules, [retire.js](https://retirejs.github.io/retire.js/) data for JavaScript libraries |
| Emails (public sources) | [theHarvester](https://github.com/laramies/theHarvester) or similar OSINT sources |
| Web verification | [Nuclei](https://github.com/projectdiscovery/nuclei) |
| CVE data | [NVD](https://nvd.nist.gov/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), CPE matching, SearchSploit database |
| Optional network scanner | [OpenVAS / Greenbone](https://www.greenbone.net/) |
| Storage / reporting | Python, Jinja2, SQLite and/or JSON |
| Packaging | Docker |

## 📈 Reports

The intended output helps answer:

- What assets, technologies and services were discovered?
- Which findings have the strongest evidence?
- What deserves attention first?
- Which results are possible matches versus safely confirmed issues?
- What changed since the previous scan?

**Outputs:** a readable, filterable HTML report, structured JSON results and scan-to-scan differences. CVE alerts are planned with the monitor module.

## 🔎 Related projects

Marsadix builds on ideas from, and is meant to be compared against, existing reconnaissance and scanning projects, including [FinalRecon](https://github.com/thewhiteh4t/FinalRecon), [reconFTW](https://github.com/six2dez/reconftw), [BBOT](https://github.com/blacklanternsecurity/bbot), [Osmedeus](https://github.com/j3ssie/osmedeus), [driftmux](https://pypi.org/project/driftmux/) and [ScopeSentry](https://github.com/Autumn-27/ScopeSentry). Several of them already cover parts of this workflow, and reusing their strengths is part of the plan.

The differences this project aims for are the combination of recursive recon with enforced scope safety, confidence-scored correlation with verify-only checks, scan-to-scan diffing, and a CVE monitor built on the discovered technology inventory. Any claim about another tool's limitations will be published only after it has been reproduced and documented in the benchmarks.

## 🗺️ Roadmap

### Core engine

- [x] Authorization-first scope manager (wildcards, CIDR ranges, exclusions)
- [x] Scan pipeline: stages auto-discovered, missing ones skip cleanly, a crash in one never stops the others
- [x] Local SQLite database: assets, services, technologies, findings, CVEs, alerts, scan history
- [x] Confidence levels (possible / likely / confirmed) and alert priority scoring
- [x] Alert deduplication (never resend the same alert twice)
- [x] Scan-to-scan diffing (new/removed assets, ports, technologies, findings)
- [x] Automatic new-asset / new-port alerts after every scan
- [x] HTML report (Triage + Engagement views) and JSON report
- [x] OWASP Top 10 (2021) coverage mapping, with a Detection Limitations disclosure
- [x] Three-state detection status (Detected / Needs Review / No Indicators) — never reports absence of evidence as absence of risk
- [x] Source-confidence scoring per discovered asset
- [x] Docker packaging
- [x] Schema-version check with an actionable error message instead of a raw SQL error
- [x] Knowledge Graph (link assets/services/technologies/CVEs; "what else shares this?" queries)
- [x] `--mode passive/standard/full` enforcement and an explicit opt-in flag for injection checks
- [ ] SARIF and PDF report export (CSV export is done)
- [ ] Reproducible benchmarks against existing tools

### Discovery and detection modules (built on the engine above)

- [x] Passive and active reconnaissance (subfinder, amass, crt.sh, dnsx, httpx, naabu, nmap, CDN/ASN detection)
- [x] Recursive recon with scope enforcement and depth limit
- [x] Permutation (alterx/dnsgen) and DNS bruteforcing with wildcard filtering
- [x] Collection of URLs, JavaScript files, endpoints and technologies
- [ ] Public email collection
- [ ] Web checks using Nuclei (takeover, exposures, CVE templates) plus custom detection skills (XSS, SQLi, SSTI...) sourced from documented methodologies (PortSwigger, PayloadsAllTheThings, OWASP Testing Guide)
- [ ] CVE monitor: NVD + CISA KEV sync, EPSS scoring, CPE matching
- [ ] Alert delivery: Discord, Telegram, email, generic webhook

### Stretch goals

- [ ] OpenVAS integration through GMP
- [ ] Import `.nessus` exports
- [ ] Deeper network assessment module
- [ ] Scheduled scans
- [ ] Attack Path Time Machine (visualize how the attack surface evolved scan over scan)
- [ ] Misconfiguration Pattern Hunter (cluster related findings into one root-cause issue instead of listing each separately)

## 🧪 Testing & evaluation

The core engine is covered by an automated test suite (`python -m pytest -q`) that runs on every change — no real network calls, no external tools required to run it.

Planned testing environments for the discovery/detection modules, once written, include:

- Local labs such as [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) and [DVWA](https://github.com/digininja/DVWA).
- Personal lab infrastructure.
- Public test targets only within their published usage limits.
- Bug bounty assets that are explicitly in scope.

The project plan includes benchmarking selected existing tools on the same authorized targets (time, number of findings, accuracy and false positives).

## 🚀 Getting started

**Docker (fastest, every tool pre-installed):**

```bash
docker build -t marsadix .
docker run --rm -v marsadix-data:/data marsadix doctor
docker run --rm -v marsadix-data:/data marsadix scan example.com
docker run --rm -v marsadix-data:/data marsadix report example.com --out /data/output
```

**From source** (for development — see [`TEAM_GUIDE.md`](TEAM_GUIDE.md) for the full step-by-step, including installing the external recon tools):

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -e .
cp .env.example .env        # fill in whichever API keys you have; empty ones are skipped
marsadix doctor             # check which external tools are found
marsadix scan example.com --scope scope.txt
marsadix report example.com --out output
```

## 🤝 Contributing

Potential contribution areas include:

- Scope validation, CDN safety and recursion limits.
- Service and technology fingerprinting, and CVE correlation.
- Confidence scoring and false-positive reduction.
- Safe verification checks.
- Reporting, scan-diff accuracy and CVE-monitor matching.
- Reproducible benchmarks and documentation.

For substantial changes, open an issue first to discuss the approach. Any reused upstream code must retain its license notices and attribution requirements.

## ⚖️ Responsible use

Marsadix is intended to support defensive security work, authorized penetration testing and attack-surface monitoring. The operator is responsible for confirming authorization, respecting scope, setting safe request rates and complying with applicable laws and program rules.

The project is not intended to exploit vulnerabilities or access data without permission.

## 🛰️ Why "Marsadix"?

**Marsadix** takes inspiration from the Arabic word **مرصد (marsad)**, an observatory or monitoring post, combined with a technical suffix. It reflects the project's central idea: continuously observe an attack surface and notice what changes.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&height=120&section=footer&color=0:16A6A1,100:081A2F" width="100%" alt="Decorative footer" />

### **Marsadix**
**Recon smarter. Verify safely. Track every change.**

<sub>Open-source security tooling · Scope-aware by design · Evidence-driven assessments</sub>

</div>
