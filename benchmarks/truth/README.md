# Detection benchmark ground truth (C14b)

`marsadix benchmark detection <target> --truth <file>` compares one finished scan with a list
of issues you KNOW exist on a deliberately vulnerable training target (DVWA, OWASP Juice Shop).

```json
{
  "target_name": "DVWA (security level low)",
  "entries": [
    {"id": "dvwa-xss-reflected", "owasp_category": "A03:2021-Injection", "url_contains": "/vulnerabilities/xss_r"},
    {"id": "dvwa-sqli",          "template_id": "sqli",                    "url_contains": "/vulnerabilities/sqli"}
  ]
}
```

An entry matches a finding when the finding's status is `detected` and EVERY key you wrote matches:

| key | matches when |
|---|---|
| `template_id` | equals the finding's template/skill id (case-insensitive) |
| `owasp_category` | equals the finding's OWASP category exactly |
| `url_contains` | appears in the finding's URL or host |

* **Detection Rate** = entries matched / entries in the file.
* **Precision** = detected findings that match some entry / all detected findings.
* `needs_review` findings are listed but never counted as hits.

`dvwa.example.json` is a starting point only: the paths are DVWA's usual ones, but you must check
them against YOUR install and security level before quoting any number. Run the scan only against a
target you started yourself, in a lab, with `--scope` and `--mode full --allow-injection`.
