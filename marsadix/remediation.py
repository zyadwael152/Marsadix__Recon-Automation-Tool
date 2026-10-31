"""
Remediation database (M19): what to DO about a finding.

    get_remediation(finding) -> str | None

`finding` is a dict (as in the report) or a Finding model. The reports use this
automatically (Engagement view, PDF, SARIF help text can build on it).

Lookup order, most specific first:
  1. the detection skill that produced it            (xss, sqli, ssti ...)
  2. keywords in the Nuclei template id / title       (takeover, exposed .env, panel ...)
  3. a CVE id                                         (patch/upgrade guidance)
  4. its OWASP Top 10 category                        (general guidance)

The text is deliberately short, actionable and vendor-neutral. It tells the owner
what to change, not how to attack anything.
"""

from __future__ import annotations

import re
from typing import Optional

# --- 1. by detection skill ------------------------------------------------------------
SKILL_FIXES = {
    "xss": "Encode all user-controlled data for the exact output context (HTML body, attribute, JavaScript, URL) "
           "with your framework's auto-escaping; never build HTML with string concatenation. Add a strict "
           "Content-Security-Policy as defence in depth and set cookies HttpOnly and SameSite.",
    "sqli": "Use parameterized queries / prepared statements for every database call; never concatenate input into "
            "SQL. Run the application with a least-privilege database account, hide database error messages from "
            "users and log them server-side.",
    "ssti": "Never pass user input into a template as template source. Render it only as data (context variables). "
            "If users must author templates, use a logic-less or sandboxed engine and keep the template engine up to date.",
    "open-redirect": "Do not redirect to a URL taken from a parameter. Redirect to fixed routes or look the target up from "
                     "a server-side allow-list (by id), and reject absolute URLs and '//' prefixes.",
    "crlf": "Reject or strip CR (%0d) and LF (%0a) from any value placed into a response header or redirect Location; "
            "use your framework's header API, which rejects them. Update the web server / framework.",
    "host-header": "Do not build absolute URLs (password-reset links, redirects, canonical tags) from the Host or "
                   "X-Forwarded-Host header. Use a configured canonical base URL and validate Host against an allow-list "
                   "at the reverse proxy.",
    "jwt": "Reject tokens with alg 'none'; pin the expected algorithm server-side; always require and verify exp (short "
           "lifetime) and aud/iss; use a long random key (or asymmetric keys) and rotate it; validate the kid header "
           "against known keys only.",
    "git-env-exposure": "Remove the exposed file from the web root now and block dot-files at the web server "
                        "(deny /.git, /.env, /.svn). Treat everything the file contained as compromised: rotate every "
                        "secret and key, and review access logs for earlier downloads. Deploy from a build artifact, "
                        "not a git checkout.",
}

# --- 2. by Nuclei template keywords (first match wins) ----------------------------------
KEYWORD_FIXES = [
    (("takeover",), "Remove the dangling DNS record (CNAME/A/NS) that points to a service you no longer control, or "
                    "re-claim the resource at the provider. Audit DNS for other records pointing at deprovisioned services."),
    (("default-login", "default-credentials", "default-password"),
     "Change the default credentials immediately, remove unused accounts, enforce strong unique passwords and MFA, and "
     "restrict the login page to trusted networks / a VPN."),
    (("exposed-panel", "panel", "login-page", "admin-panel"),
     "Do not expose administration interfaces to the internet: restrict by IP allow-list or VPN, require MFA, and keep the "
     "product patched."),
    (("env", "dotenv", "git-config", "git-exposure", "svn", "backup", "config-file", "exposed-file", "ds-store"),
     "Remove the file from the web root, block access to dot-files and backup extensions at the web server, and rotate any "
     "secrets it contained."),
    (("directory-listing", "dir-listing", "autoindex"),
     "Disable directory indexing (autoindex off / Options -Indexes) and make sure no sensitive files sit in web-served folders."),
    (("cors",), "Replace wildcard or reflected CORS origins with an explicit allow-list; never combine "
                "Access-Control-Allow-Credentials with a broad origin."),
    (("missing-security-headers", "security-header", "missing-header"),
     "Set HSTS, X-Content-Type-Options: nosniff, a Content-Security-Policy, frame-ancestors / X-Frame-Options and a "
     "Referrer-Policy at the web server or CDN."),
    (("ssl", "tls", "certificate"),
     "Serve only TLS 1.2+ with strong ciphers, renew expired certificates, and enable automatic renewal."),
    (("phpinfo", "debug", "stacktrace", "actuator", "server-status", "swagger", "graphql"),
     "Disable debug / diagnostic endpoints in production or restrict them to internal networks; they disclose "
     "configuration that makes other attacks easier."),
    (("wordpress", "wp-plugin", "wp-theme"),
     "Update WordPress core, the named plugin/theme and all other extensions; remove ones you do not use."),
]

# --- 4. by OWASP category (generic fallback) -----------------------------------------------
OWASP_FIXES = {
    "A01:2021-Broken_Access_Control": "Enforce authorization on the server for every request (deny by default), check object ownership "
                                      "on each access, and validate redirect/forward targets against an allow-list.",
    "A02:2021-Cryptographic_Failures": "Use TLS everywhere with current protocol versions, store passwords with a slow salted hash "
                                       "(Argon2/bcrypt), and never keep secrets in code or web-served files.",
    "A03:2021-Injection": "Separate code from data: parameterized queries, context-aware output encoding, and server-side input "
                          "validation by allow-list.",
    "A04:2021-Insecure_Design": "Add threat modelling and abuse-case tests to the design phase; enforce limits and trust boundaries "
                                "in the architecture, not only in code.",
    "A05:2021-Security_Misconfiguration": "Harden the configuration: remove default accounts, sample files and debug features, disable "
                                          "directory listing, set security headers, and automate configuration review.",
    "A06:2021-Vulnerable_and_Outdated_Components": "Inventory components and versions, subscribe to their advisories, and patch or "
                                                   "upgrade to a fixed release; remove components you do not use.",
    "A07:2021-Identification_Authentication_Failures": "Require MFA where possible, rate-limit and lock out brute force, use secure "
                                                       "session handling, and validate tokens fully (signature, expiry, audience).",
    "A08:2021-Software_Data_Integrity_Failures": "Verify the integrity of updates, packages and serialized data (signatures, pinned "
                                                 "hashes) and secure the CI/CD pipeline.",
    "A09:2021-Security_Logging_Monitoring_Failures": "Log authentication and access-control events centrally, alert on anomalies, and "
                                                     "rehearse incident response.",
    "A10:2021-Server_Side_Request_Forgery": "Validate and allow-list outbound destinations, block internal address ranges and metadata "
                                            "endpoints at the network layer, and do not return raw upstream responses.",
}


def _get(finding, key):
    if isinstance(finding, dict):
        return finding.get(key)
    val = getattr(finding, key, None)
    return getattr(val, "value", val)


def get_remediation(finding) -> Optional[str]:
    template = str(_get(finding, "template_id") or "").lower()
    title = str(_get(finding, "title") or "").lower()
    if template in SKILL_FIXES:
        return SKILL_FIXES[template]

    haystack = f"{template} {title}"
    tokens = set(re.split(r"[^a-z0-9]+", haystack))
    for words, text in KEYWORD_FIXES:
        # whole words only ("env" must not match "environment"); hyphenated keys match as a phrase
        if any((w in haystack) if "-" in w else (w in tokens) for w in words):
            return text

    cve = _get(finding, "cve_id")
    if cve:
        tech = _get(finding, "technology")
        what = f"the affected {tech} installation" if tech else "the affected component"
        return (f"Upgrade {what} to a release that fixes {cve} (see the vendor advisory and "
                f"https://nvd.nist.gov/vuln/detail/{cve}). If you cannot patch yet, restrict network access to it "
                f"and apply the vendor's mitigation. If it is listed in CISA KEV, treat it as urgent.")

    return OWASP_FIXES.get(str(_get(finding, "owasp_category") or ""))
