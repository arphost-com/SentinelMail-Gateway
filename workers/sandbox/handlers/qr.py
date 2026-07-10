"""QR / barcode decoder with URLhaus feed lookup."""

from __future__ import annotations

import base64
import io
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog
from PIL import Image
from pyzbar import pyzbar

log = structlog.get_logger()

URLHAUS_URL = os.environ.get("URLHAUS_FEED_URL", "https://urlhaus.abuse.ch/downloads/text/")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)


@dataclass
class URLHausFeed:
    last_pull_ts: float = 0.0
    ttl_s: int = 900
    urls: set[str] = field(default_factory=set)
    loaded: bool = False

    def ensure(self, client: httpx.Client) -> None:
        now = time.time()
        if self.loaded and (now - self.last_pull_ts) < self.ttl_s:
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
                self.urls = urls
                self.last_pull_ts = now
                self.loaded = True
                log.info("urlhaus.refreshed", count=len(urls))
        except httpx.HTTPError as e:
            log.warning("urlhaus.error", err=str(e))

    def hit(self, url: str) -> bool:
        return url.lower() in self.urls if self.loaded else False


URLHAUS = URLHausFeed()


def handle_qr(payload: dict[str, Any], client: httpx.Client) -> dict[str, Any]:
    b64 = payload.get("image_b64") or ""
    if not b64:
        return {"verdict": "clean", "result": {"reason": "no image_b64 in payload"}}

    try:
        raw = base64.b64decode(b64, validate=True)
        img = Image.open(io.BytesIO(raw))
    except Exception as e:                              # noqa: BLE001
        return {"verdict": "failed", "error": f"decode error: {e}"}

    decoded = []
    for sym in pyzbar.decode(img):
        try:
            text = sym.data.decode("utf-8", errors="replace")
        except Exception:                               # noqa: BLE001
            text = ""
        decoded.append({"type": sym.type, "text": text})

    urls = [m for d in decoded for m in URL_RE.findall(d["text"])]
    URLHAUS.ensure(client)
    hits = [u for u in urls if URLHAUS.hit(u)]

    if hits:
        verdict = "malicious"
    elif urls or decoded:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "result": {
            "decoded": decoded,
            "urls": urls,
            "feed_hits": hits,
            "feed": "urlhaus",
            "urlhaus_known": URLHAUS.loaded,
        },
    }
