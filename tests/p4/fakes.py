import json
from marsadix.alerts.base import AlertPayload
from marsadix.alerts.http import HttpResponse, TransportError, TransportTimeout


class FakeClient:
    """Scripted HTTP client: items are HttpResponse, or exceptions to raise."""
    def __init__(self, *script):
        self.script = list(script) or [HttpResponse(204)]
        self.calls = []

    def post(self, url, body, headers, timeout):
        self.calls.append({"url": url, "body": body, "headers": headers, "timeout": timeout})
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, Exception):
            raise item
        return item

    def json(self, i=-1):
        return json.loads(self.calls[i]["body"])


class Sleeper:
    def __init__(self):
        self.delays = []

    def __call__(self, d):
        self.delays.append(d)


def payload(**kw):
    base = dict(cve_id="CVE-2021-41773", host="www.example.com", product="http_server", technology="Apache", version="2.4.49",
                cvss=9.8, epss=0.94, kev=True, confidence="high", priority_level="critical", priority_score=97.0,
                risk_score=91.5, remediation_title="Patch Apache", remediation_text="Upgrade to 2.4.51",
                description="Path traversal", reasons=["CVSS 9.8"])
    base.update(kw)
    return AlertPayload(**base)
