"""NVD downloads survive transient 503s / timeouts (network mocked)."""
import io
import urllib.error

import pytest

sources = pytest.importorskip("marsadix.monitor.sources")


def _err(code, headers=None):
    return urllib.error.HTTPError("http://x", code, "err", headers or {}, io.BytesIO(b""))


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _script(monkeypatch, outcomes):
    """urlopen returns / raises the scripted outcomes in order; time.sleep is recorded, never waited."""
    sleeps, calls = [], {"n": 0}

    def fake_urlopen(req, timeout=0):
        out = outcomes[calls["n"]]; calls["n"] += 1
        if isinstance(out, Exception): raise out
        return _Resp(out)

    monkeypatch.setattr(sources, "urlopen", fake_urlopen)
    monkeypatch.setattr(sources.time, "sleep", lambda s: sleeps.append(s))
    return sleeps, calls


def test_503_is_retried_with_growing_waits_until_it_succeeds(monkeypatch, capsys):
    sleeps, calls = _script(monkeypatch, [_err(503), _err(503), b'{"ok": 1}'])
    assert sources.request_json("http://x", retries=6, backoff=5) == {"ok": 1}
    assert sleeps == [5, 10] and calls["n"] == 3
    err = capsys.readouterr().err
    assert "HTTP 503; retrying in 5s (attempt 1/6)" in err and "retrying in 10s (attempt 2/6)" in err


def test_waits_are_capped_and_it_finally_gives_up(monkeypatch):
    sleeps, calls = _script(monkeypatch, [_err(503)] * 7)
    with pytest.raises(urllib.error.HTTPError):
        sources.request_json("http://x", retries=6, backoff=5)
    assert calls["n"] == 7 and sleeps == [5, 10, 20, 40, 60, 60]


def test_retry_after_header_is_honoured(monkeypatch):
    sleeps, _ = _script(monkeypatch, [_err(503, {"Retry-After": "17"}), b"{}"])
    sources.request_json("http://x", retries=3, backoff=5)
    assert sleeps == [17]


def test_timeouts_are_retried_too(monkeypatch):
    sleeps, calls = _script(monkeypatch, [TimeoutError(), urllib.error.URLError("boom"), b"{}"])
    assert sources.request_json("http://x", retries=3, backoff=5) == {}
    assert sleeps == [5, 10] and calls["n"] == 3


def test_a_404_is_not_retried(monkeypatch):
    sleeps, calls = _script(monkeypatch, [_err(404)])
    with pytest.raises(urllib.error.HTTPError):
        sources.request_json("http://x", retries=6, backoff=5)
    assert calls["n"] == 1 and sleeps == []


def test_retry_messages_never_contain_the_url_or_api_key(monkeypatch, capsys):
    _script(monkeypatch, [_err(503), b"{}"])
    sources.request_json("http://x/?apiKey=SECRETKEY", {"apiKey": "SECRETKEY"}, retries=3, backoff=5)
    assert "SECRETKEY" not in capsys.readouterr().err


def test_nvd_requests_use_patient_settings_and_smaller_pages(monkeypatch):
    from datetime import datetime, timezone
    seen = {}

    def fake(url, headers=None, **kw):
        seen["url"], seen["kw"] = url, kw
        return {"vulnerabilities": [], "totalResults": 0}

    monkeypatch.setattr(sources, "request_json", fake)
    monkeypatch.setattr(sources.time, "sleep", lambda s: None)
    list(sources.fetch_nvd(datetime(2025, 1, 1, tzinfo=timezone.utc), datetime(2025, 1, 2, tzinfo=timezone.utc), "k"))
    assert seen["kw"] == {"retries": 6, "timeout": 60, "extra_retry": (403,), "backoff": 5}
    assert "resultsPerPage=1000" in seen["url"]
