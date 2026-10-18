"""
Fixed mapping: finding type -> OWASP Top 10 (2021) category. (A7)

This is NOT exploitation. It only classifies a Finding's `title`/`template_id`
under the OWASP bucket it belongs to, so the report can show coverage %.
Marsadix detects with evidence; it never exploits (see Finding.exploited).
"""

from __future__ import annotations

OWASP_MAPPING: dict[str, str] = {
    "sqli_detected": "A03:2021-Injection",
    "xss_detected": "A03:2021-Injection",
    "ssti_detected": "A03:2021-Injection",
    "crlf_injection": "A03:2021-Injection",
    "open_redirect": "A01:2021-Broken_Access_Control",
    "idor_pattern": "A01:2021-Broken_Access_Control",
    "exposed_panel": "A05:2021-Security_Misconfiguration",
    "missing_security_headers": "A05:2021-Security_Misconfiguration",
    "git_env_exposure": "A05:2021-Security_Misconfiguration",
    "outdated_component": "A06:2021-Vulnerable_and_Outdated_Components",
    "cve_match": "A06:2021-Vulnerable_and_Outdated_Components",
    "weak_tls": "A02:2021-Cryptographic_Failures",
    "login_panel_found": "A07:2021-Identification_Authentication_Failures",
    "jwt_weakness": "A07:2021-Identification_Authentication_Failures",
    "host_header_injection": "A07:2021-Identification_Authentication_Failures",
    "ssrf_callback_hit": "A10:2021-Server_Side_Request_Forgery",
    "subdomain_takeover": "A05:2021-Security_Misconfiguration",
    "graphql_introspection": "A05:2021-Security_Misconfiguration",
}

# All 10 categories, used to compute coverage % even for buckets with 0 findings (M20)
ALL_CATEGORIES = [
    "A01:2021-Broken_Access_Control",
    "A02:2021-Cryptographic_Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure_Design",
    "A05:2021-Security_Misconfiguration",
    "A06:2021-Vulnerable_and_Outdated_Components",
    "A07:2021-Identification_Authentication_Failures",
    "A08:2021-Software_Data_Integrity_Failures",
    "A09:2021-Security_Logging_Monitoring_Failures",
    "A10:2021-Server_Side_Request_Forgery",
]


def get_owasp_category(finding_type: str) -> str | None:
    return OWASP_MAPPING.get(finding_type)