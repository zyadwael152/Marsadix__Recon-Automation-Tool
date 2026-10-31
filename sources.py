"""Passive CVE intelligence clients: NVD, CISA KEV and FIRST EPSS."""
from __future__ import annotations
import json
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS = 'https://api.first.org/data/v1/epss'

def request_json(url, headers=None, retries=3, timeout=30):
    """Retry transient errors, obey Retry-After, fail closed on malformed data."""
    hdr = {'User-Agent': 'Marsadix-CVE-Monitor/0.1', 'Accept': 'application/json'}
    hdr.update(headers or {})
    for attempt in range(retries+1):
        try:
            with urlopen(Request(url, headers=hdr), timeout=timeout) as response:
                return json.load(response)
        except HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == retries:
                raise
            delay = exc.headers.get('Retry-After', '')
            try: wait = min(120, max(0, int(delay)))
            except ValueError: wait = min(60, 2 ** attempt)
        except (URLError, TimeoutError):
            if attempt == retries: raise
            wait = min(60, 2 ** attempt)
        time.sleep(wait)

def parse_nvd(item):
    c = item['cve']
    descriptions = c.get('descriptions') or []
    description = next((d.get('value', '') for d in descriptions if d.get('lang') == 'en'), '')
    scores = []
    for version in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        for metric in c.get('metrics', {}).get(version, []):
            data = metric.get('cvssData', {})
            if data.get('baseScore') is not None:
                scores.append((metric.get('type') != 'Primary', float(data['baseScore'])))
        if scores: break
    score = sorted(scores)[0][1] if scores else None
    severity = ('critical' if score >= 9 else 'high' if score >= 7 else
                'medium' if score >= 4 else 'low') if score is not None else 'info'
    # Preserve AND/OR trees and negated CPE matches; the matcher owns their semantics.
    return dict(cve_id=c['id'], description=description, cvss_score=score, severity=severity,
                published=c.get('published'), modified=c.get('lastModified'),
                cpe_matches=c.get('configurations', []),
                references=[r['url'] for r in c.get('references', []) if r.get('url')])

def fetch_nvd(start, end, api_key='', page_size=2000):
    """Yield NVD CVEs in lastModified windows, paginating until complete."""
    if end <= start: return
    headers = {'apiKey': api_key} if api_key else {}
    cursor = start
    while cursor < end:
        window_end = min(end, cursor + timedelta(days=119))
        base = {'lastModStartDate': cursor.isoformat(timespec='milliseconds'),
                'lastModEndDate': window_end.isoformat(timespec='milliseconds'),
                'resultsPerPage': min(2000, page_size)}
        index = 0
        while True:
            payload = request_json(NVD + '?' + urlencode({**base, 'startIndex': index}), headers)
            records = payload.get('vulnerabilities', [])
            for record in records: yield parse_nvd(record)
            index += len(records)
            if not records or index >= int(payload.get('totalResults', 0)): break
            time.sleep(.6 if api_key else 6)
        cursor = window_end  # overlap at the boundary, safe via upsert

def fetch_kev():
    data = request_json(KEV)
    return {v['cveID'] for v in data['vulnerabilities'] if v.get('cveID')}

def fetch_epss(ids, batch_size=100):
    """Return probability 0..1 for known CVEs; no exploit requests."""
    result = {}
    unique = sorted(set(ids))
    for i in range(0, len(unique), batch_size):
        chunk = unique[i:i+batch_size]
        payload = request_json(EPSS + '?' + urlencode({'cve': ','.join(chunk)}))
        for record in payload.get('data', []):
            try:
                value = float(record['epss'])
                if 0 <= value <= 1: result[record['cve']] = value
            except (KeyError, TypeError, ValueError): continue
    return result
