"""Browser sandbox — fetch a suspicious URL in headless Chromium and report.

Payload:
    {
      "url":          "https://...",
      "timeout_ms":   10000     # optional (default 10000, capped 30000)
    }

Returns:
    {
      "verdict": "clean" | "suspicious" | "malicious" | "failed",
      "result": {
        "input_url":     "...",
        "final_url":     "...",
        "redirects":     [...],
        "title":         "...",
        "status":        200,
        "screenshot_b64": "...",   # PNG (downscaled to 1024x768)
        "render_ms":     1234,
        "reasons":       ["redirected to different domain", ...]
      }
    }

Verdict rules:
  malicious  → final URL host matches URLhaus, or page asks for credentials and
               the form action goes to a different domain
  suspicious → password field, cross-origin form, navigation error, or a
               credential-themed redirect to an untrusted host
  clean      → loaded without phishing indicators, including normal brand
               redirects to trusted final hosts
  failed     → navigation error / timeout

URLhaus check is deliberately re-implemented here instead of imported from the
light worker — keeps sandbox-worker importable without the light worker's
pyzbar/Pillow deps.
"""

from __future__ import annotations

import base64
import os
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog
from playwright.sync_api import Error as PlaywrightError, TimeoutError as PWTimeoutError, sync_playwright

log = structlog.get_logger()

URLHAUS_URL = os.environ.get("URLHAUS_FEED_URL", "https://urlhaus.abuse.ch/downloads/text/")
SCREENSHOT_WIDTH = 1024
SCREENSHOT_HEIGHT = 768
MAX_TIMEOUT_MS = 30_000
DEFAULT_TIMEOUT_MS = 10_000

_urlhaus_cache: dict[str, Any] = {"loaded": False, "urls": set(), "fetched_at": 0.0}
_URLHAUS_TTL = 900

TRUSTED_REDIRECT_DOMAINS = {
    "microsoft.com",
    "live.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "windows.com",
    "microsoftonline.com",
    "facebook.com",
    "facebookmail.com",
    "fb.com",
}

CREDENTIAL_PATH_RE = re.compile(
    r"(?:^|[/_.-])(?:login|signin|sign-in|verify|account|password|secure|review)(?:$|[/_.?&=-])",
    re.IGNORECASE,
)


def _urlhaus_ensure(client: httpx.Client) -> None:
    now = time.time()
    if _urlhaus_cache["loaded"] and (now - _urlhaus_cache["fetched_at"]) < _URLHAUS_TTL:
        return
    try:
        r = client.get(URLHAUS_URL, timeout=20.0)
        if r.status_code != 200:
            log.warning("urlhaus.status", status=r.status_code)
            return
        urls = {
            line.strip().lower()
            for line in r.text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        if urls:
            _urlhaus_cache["urls"] = urls
            _urlhaus_cache["fetched_at"] = now
            _urlhaus_cache["loaded"] = True
            log.info("urlhaus.refreshed", count=len(urls))
    except httpx.HTTPError as e:
        log.warning("urlhaus.error", err=str(e))


def _urlhaus_hit(url: str) -> bool:
    return url.lower() in _urlhaus_cache["urls"] if _urlhaus_cache["loaded"] else False


def _trusted_redirect_host(host: str) -> bool:
    host = (host or "").lower().strip(".")
    return any(host == trusted or host.endswith("." + trusted) for trusted in TRUSTED_REDIRECT_DOMAINS)


def _credential_themed_url(url: str) -> bool:
    parsed = urlparse(url)
    haystack = f"{parsed.path}?{parsed.query}"
    return bool(CREDENTIAL_PATH_RE.search(haystack))


def _classify_sandbox_result(
    input_url: str,
    final_url: str,
    has_password_field: bool,
    cross_origin_form: bool,
    feed_hits: list[str],
    reasons: list[str],
) -> str:
    final_host = urlparse(final_url).netloc.lower()
    input_host = urlparse(input_url).netloc.lower()

    if feed_hits or (has_password_field and cross_origin_form):
        return "malicious"
    if cross_origin_form:
        return "suspicious"
    if has_password_field and not _trusted_redirect_host(final_host):
        return "suspicious"
    if final_host != input_host:
        if _trusted_redirect_host(final_host):
            return "clean"
        if _credential_themed_url(final_url):
            return "suspicious"
        return "clean"
    if reasons:
        # Navigation errors are interesting (might be evasive).
        return "suspicious"
    return "clean"


def handle_sandbox(payload: dict[str, Any], http: httpx.Client) -> dict[str, Any]:
    url = (payload.get("url") or "").strip()
    if not url:
        return {"verdict": "failed", "error": "url required"}
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"verdict": "failed", "error": "only http/https supported"}

    timeout_ms = max(1000, min(MAX_TIMEOUT_MS, int(payload.get("timeout_ms") or DEFAULT_TIMEOUT_MS)))

    redirects: list[str] = []
    final_url = url
    title = ""
    status = 0
    shot_b64 = ""
    reasons: list[str] = []
    has_password_field = False
    cross_origin_form = False
    render_ms = 0

    start = time.time()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=[
                "--no-sandbox",            # required in containerised non-root
                "--disable-dev-shm-usage", # /dev/shm sometimes too small in docker
                "--disable-gpu",
            ])
            ctx = browser.new_context(
                viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT},
                user_agent="Mozilla/5.0 (compatible; SentinelMail-Sandbox/1.0)",
                # Block downloads — we are inspecting, not collecting payloads.
                accept_downloads=False,
            )
            page = ctx.new_page()
            page.on("framenavigated", lambda fr: fr is page.main_frame and redirects.append(fr.url))

            try:
                resp = page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                status = resp.status if resp else 0
            except PWTimeoutError:
                reasons.append(f"timeout after {timeout_ms}ms")
            except PlaywrightError as e:
                reasons.append(f"navigation error: {e}")

            try:
                final_url = page.url
                title = (page.title() or "")[:200]
            except PlaywrightError:
                pass

            # Heuristic: any password input is interesting.
            try:
                has_password_field = page.locator("input[type=password]").count() > 0
            except PlaywrightError:
                pass

            # Heuristic: form action that crosses away from the rendered page.
            # Compare against the final page host, not the original tracking
            # link host, or legitimate marketing redirects to social/login
            # pages are mislabeled as credential theft.
            try:
                form_actions = page.evaluate(
                    "() => Array.from(document.forms).map(f => f.action || '')"
                )
                page_host = urlparse(final_url).netloc.lower()
                for action in form_actions or []:
                    if not action:
                        continue
                    action_host = urlparse(action).netloc.lower()
                    if action_host and page_host and action_host != page_host:
                        cross_origin_form = True
                        reasons.append(f"form posts to different domain: {action_host}")
                        break
            except PlaywrightError:
                pass

            # Screenshot — small + clipped so the payload stays under the
            # API's 8 MiB cap with margin.
            try:
                png = page.screenshot(full_page=False, type="png")
                shot_b64 = base64.b64encode(png).decode()
            except PlaywrightError as e:
                reasons.append(f"screenshot failed: {e}")

            browser.close()
    except Exception as e:                                  # noqa: BLE001
        log.exception("sandbox.crash", url=url)
        return {"verdict": "failed", "error": f"sandbox crash: {e}"}
    finally:
        render_ms = int((time.time() - start) * 1000)

    # Threat scoring.
    _urlhaus_ensure(http)
    final_host = urlparse(final_url).netloc.lower()
    input_host = urlparse(url).netloc.lower()
    feed_hits = []
    if _urlhaus_hit(final_url):
        feed_hits.append(final_url)
    if _urlhaus_hit(url):
        feed_hits.append(url)

    if final_host != input_host:
        reasons.append(f"redirected to different host: {final_host}")
    if has_password_field:
        reasons.append("page contains password input")
    if feed_hits:
        reasons.append(f"URLhaus match: {feed_hits[0]}")
    verdict = _classify_sandbox_result(url, final_url, has_password_field, cross_origin_form, feed_hits, reasons)

    return {
        "verdict": verdict,
        "result": {
            "input_url": url,
            "final_url": final_url,
            "redirects": redirects[:20],
            "title": title,
            "status": status,
            "render_ms": render_ms,
            "screenshot_b64": shot_b64,
            "reasons": reasons,
            "feed_hits": feed_hits,
        },
    }
