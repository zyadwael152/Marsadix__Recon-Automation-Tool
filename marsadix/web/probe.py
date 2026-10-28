"""
Thin async wrappers around httpx and katana.

Both tools send traffic to the target. `rate_limit` (requests per second) is
passed straight to their `-rl` flag. It matters more than it looks: without it
httpx and katana both default to 150 requests/second, far more than the
config.toml / --rate value the user asked for would suggest, and enough to
knock over a small server. (Flags checked against httpx v1.12 and katana v1.8.)

What to expect from the number: it is the tools' own limiter, so it is an
AVERAGE. Measured against a local server with -rl 5, the busiest 1-second
window still saw 9-10 requests (about 2x), while without the flag the same run
peaked at 30-36 req/s. Treat --rate as "about N per second, short bursts up to
roughly 2N", and pick a lower number for fragile targets.
"""

import asyncio
import json
import logging
from contextlib import suppress
from typing import List, Optional, Set

logger = logging.getLogger(__name__)


def _rate_args(rate_limit: Optional[int]) -> List[str]:
    return ["-rl", str(int(rate_limit))] if rate_limit else []


async def _read_all(stream, sink: List[bytes]) -> None:
    """Drain one pipe into `sink` until EOF (or until the task is cancelled)."""
    if stream is None:
        return
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return
        sink.append(chunk)


async def _feed_stdin(process, input_data: bytes) -> None:
    """Write the tool's input and close stdin, tolerating an early exit."""
    stdin = process.stdin
    if stdin is None:
        return
    try:
        if input_data:
            stdin.write(input_data)
            await stdin.drain()
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        with suppress(Exception):
            stdin.close()


async def _communicate_with_partial(process, input_data: bytes, timeout: int):
    """
    Like process.communicate(), but keep whatever was streamed before a timeout.

    communicate() buffers internally, so cancelling it on TimeoutError throws
    away every line the tool had already printed -- exactly the preliminary
    discovery data a recon pipeline wants to keep. Here stdout/stderr are read
    concurrently, so after kill() we can still parse the partial output.

    Returns (stdout, stderr, timed_out).
    """
    stdout_parts: List[bytes] = []
    stderr_parts: List[bytes] = []
    readers = [
        asyncio.create_task(_read_all(process.stdout, stdout_parts)),
        asyncio.create_task(_read_all(process.stderr, stderr_parts)),
    ]
    writer = asyncio.create_task(_feed_stdin(process, input_data))
    timed_out = False
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        with suppress(ProcessLookupError):
            process.kill()
        await process.wait()
    finally:
        if not writer.done():
            writer.cancel()
        with suppress(asyncio.CancelledError):
            await writer
        # A killed child normally closes its pipes immediately. Bound the wait
        # anyway: a grandchild can inherit the pipe and keep it open forever.
        try:
            await asyncio.wait_for(
                asyncio.gather(*readers, return_exceptions=True), timeout=5)
        except asyncio.TimeoutError:
            for task in readers:
                task.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
    return b"".join(stdout_parts), b"".join(stderr_parts), timed_out


GAU_MAX_URLS = 100_000
GAU_MAX_OUTPUT_BYTES = 20 * 1024 * 1024


async def run_gau(domain: str, timeout: int = 180) -> Optional[List[str]]:
    """Collect archived URLs passively with gau. None means the binary is absent.

    Output is streamed and bounded so a very large archive result cannot consume
    unbounded memory. gau queries archive providers; it does not crawl the target.
    """
    import shutil
    from urllib.parse import urlsplit, urlunsplit

    if shutil.which("gau") is None:
        logger.info("[-] gau is not installed - archived URL collection skipped.")
        return None

    try:
        process = await asyncio.create_subprocess_exec(
            "gau", domain, "--subs", "--threads", "5", "--timeout", "30", "--retries", "2",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            limit=1024 * 1024,
        )
    except Exception as exc:
        logger.warning("[-] Could not start gau: %s", type(exc).__name__)
        return []

    urls = set()
    output_bytes = 0
    truncated = False

    async def collect():
        nonlocal output_bytes, truncated
        assert process.stdout is not None
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            output_bytes += len(line)
            if output_bytes > GAU_MAX_OUTPUT_BYTES or len(urls) >= GAU_MAX_URLS:
                truncated = True
                with suppress(ProcessLookupError):
                    process.kill()
                break
            raw = line.decode("utf-8", errors="replace").strip()
            if not raw or len(raw) > 16_384:
                continue
            try:
                parts = urlsplit(raw)
                host = parts.hostname
                if parts.scheme.lower() not in {"http", "https"} or not host:
                    continue
                if parts.username or parts.password:
                    continue
                # Drop fragments: they are client-side and do not identify a
                # distinct HTTP resource. Keep query strings as endpoint evidence.
                normalized = urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                                         parts.path or "/", parts.query, ""))
                urls.add(normalized)
            except ValueError:
                continue

    try:
        await asyncio.wait_for(collect(), timeout=max(1, int(timeout)))
    except asyncio.TimeoutError:
        truncated = True
        with suppress(ProcessLookupError):
            process.kill()
    finally:
        with suppress(Exception):
            await asyncio.wait_for(process.wait(), timeout=5)

    if truncated:
        logger.warning("[-] gau output was bounded by timeout/size limits; retaining %d URL(s).", len(urls))
    elif process.returncode not in (0, None):
        logger.warning("[-] gau exited with code %s; retaining %d URL(s).", process.returncode, len(urls))
    logger.info("[+] gau collected %d archived URL(s).", len(urls))
    return sorted(urls)


async def run_httpx(domains: List[str], rate_limit: Optional[int] = None,
                    timeout: int = 300) -> List[dict]:
    """
    Probe hosts with httpx (-td technology detection, -server header; CDN
    detection is on by default). Returns one record per live web server:

        {"url": "https://a.example.com", "input": "a.example.com", "status_code": 200,
         "ip": "93.184.216.34", "webserver": "nginx/1.18.0", "tech": ["Nginx:1.18.0", "PHP"],
         "cdn": False, "cdn_name": None}

    status_code is None when httpx did not report an integer.
    """
    if not domains:
        return []

    logger.info("[*] Running httpx on %d host(s) (rate limit: %s req/s)...",
                len(domains), rate_limit or "tool default")
    input_data = "\n".join(domains).encode()
    live: List[dict] = []

    try:
        process = await asyncio.create_subprocess_exec(
            "httpx", "-silent", "-json", "-td", "-server", *_rate_args(rate_limit),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr, timed_out = await _communicate_with_partial(
            process, input_data, timeout)
        if timed_out:
            logger.warning("[-] httpx timed out after %ss - parsing %d partial output byte(s).",
                           timeout, len(stdout))
            if stderr:
                logger.debug("[-] httpx stderr before timeout: %s",
                             stderr.decode(errors="replace").strip()[:500])

        for line in stdout.decode(errors="replace").splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            if not isinstance(data, dict) or not data.get("url") or data.get("failed"):
                continue
            status = data.get("status_code")
            addresses = data.get("a") if isinstance(data.get("a"), list) else []
            live.append({
                "url": data["url"],
                "input": str(data.get("input") or "").strip().lower() or None,
                "status_code": status if isinstance(status, int) else None,
                "ip": data.get("host_ip") or (addresses[0] if addresses else None),
                "webserver": data.get("webserver") or None,
                "tech": [str(t) for t in data.get("tech") or []],
                "cdn": bool(data.get("cdn")),
                "cdn_name": data.get("cdn_name") or None,
            })

        logger.info("[+] httpx found %d live web servers.", len(live))
    except Exception as e:
        logger.error("[-] httpx failed: %s", e)

    return live


async def run_katana(urls: List[str], rate_limit: Optional[int] = None,
                     timeout: int = 300) -> List[str]:
    """Crawl live URLs with katana (JS parsing on, depth 2). Returns unique URLs found."""
    if not urls:
        return []

    logger.info("[*] Running katana on %d live URL(s) (rate limit: %s req/s)...",
                len(urls), rate_limit or "tool default")
    input_data = "\n".join(urls).encode()
    endpoints: Set[str] = set()

    try:
        process = await asyncio.create_subprocess_exec(
            "katana", "-silent", "-jc", "-d", "2", *_rate_args(rate_limit),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr, timed_out = await _communicate_with_partial(
            process, input_data, timeout)
        if timed_out:
            logger.warning("[-] katana timed out after %ss - parsing %d partial output byte(s).",
                           timeout, len(stdout))
            if stderr:
                logger.debug("[-] katana stderr before timeout: %s",
                             stderr.decode(errors="replace").strip()[:500])

        for line in stdout.decode(errors="replace").splitlines():
            url = line.strip()
            if url:
                endpoints.add(url)

        logger.info("[+] Katana extracted %d unique endpoints/URLs.", len(endpoints))
    except Exception as e:
        logger.error("[-] Katana failed: %s", e)

    return sorted(endpoints)
