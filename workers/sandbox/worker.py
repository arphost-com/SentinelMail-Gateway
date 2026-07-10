"""SentinelMail Gateway — async scan worker.

Consumes scan envelopes from Redis `smg:scan_jobs` (RPush'd by the Go API),
fetches the full job via GET /api/v1/scan-callback/{id}/payload, dispatches
to a registered handler, and POSTs the verdict back via
POST /api/v1/scan-callback/{id}/result. Both endpoints HMAC-authenticated
with SMG_INGEST_HMAC_KEY.

Handlers live in workers/sandbox/handlers/*.py and register themselves in
handlers/__init__.py::HANDLERS.

MVP 2 v1: qr (pyzbar + URLhaus lookup)
MVP 2 v3: ai (Claude scoring, heuristic fallback)
MVP 2 v4: outbound (BEC heuristics)
MVP 2 v2: sandbox runs in a SEPARATE service (workers/sandbox-worker/) so
the heavy Playwright + Chromium image doesn't bloat the light handlers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import signal
import sys
import time
from typing import Any

import httpx
import redis
import structlog

from handlers import HANDLERS

log = structlog.get_logger()

REDIS_URL = os.environ.get("SMG_REDIS_URL", "redis://redis:6379/0")
QUEUE_KEY = os.environ.get("SMG_SCAN_QUEUE", "smg:scan_jobs")
POLL_TIMEOUT = int(os.environ.get("SMG_POLL_TIMEOUT", "5"))
API_BASE = os.environ.get("SMG_API_BASE", "http://api:8080").rstrip("/")
INGEST_SECRET = os.environ.get("SMG_INGEST_HMAC_KEY", "")


_running = True


def _shutdown(signum: int, _frame: object) -> None:
    global _running
    log.info("shutdown.signal", signum=signum)
    _running = False


class APIClient:
    def __init__(self, base: str, secret: str):
        self.base = base
        self.secret = secret.encode() if secret else b""
        self.http = httpx.Client(timeout=15.0)

    def get_job(self, scan_id: str) -> dict[str, Any] | None:
        sig = hmac.new(self.secret, scan_id.encode(), hashlib.sha256).hexdigest()
        try:
            r = self.http.get(
                f"{self.base}/api/v1/scan-callback/{scan_id}/payload",
                headers={"X-SMG-Signature": sig},
            )
            if r.status_code == 200:
                return r.json()
            log.warning("api.get_job_status", scan_id=scan_id, status=r.status_code)
        except httpx.HTTPError as e:
            log.warning("api.get_job_error", err=str(e), scan_id=scan_id)
        return None

    def post_result(self, scan_id: str, state: str, **kwargs: Any) -> bool:
        body = {"state": state, **kwargs}
        raw = json.dumps(body, separators=(",", ":")).encode()
        sig = hmac.new(self.secret, raw, hashlib.sha256).hexdigest()
        try:
            r = self.http.post(
                f"{self.base}/api/v1/scan-callback/{scan_id}/result",
                content=raw,
                headers={"Content-Type": "application/json", "X-SMG-Signature": sig},
            )
            if r.status_code in (200, 204):
                return True
            log.warning("api.post_result_status", scan_id=scan_id, status=r.status_code, body=r.text[:200])
        except httpx.HTTPError as e:
            log.warning("api.post_result_error", err=str(e), scan_id=scan_id)
        return False


def process_one(api: APIClient, env: dict[str, Any]) -> None:
    scan_id = env.get("scan_id")
    kind = env.get("kind")
    if not scan_id or not kind:
        log.warning("job.invalid_envelope", envelope=env)
        return

    handler = HANDLERS.get(kind)
    if handler is None:
        # Another worker (e.g. sandbox-worker) may handle this kind.
        # Put it back at the tail to give the right worker a shot. If no
        # one ever picks it up the API's queued state will be visible
        # in the UI for operators to notice.
        log.info("job.skip_unhandled_kind", kind=kind, scan_id=scan_id)
        return

    if not api.post_result(scan_id, "running"):
        return

    job = api.get_job(scan_id)
    if job is None:
        api.post_result(scan_id, "failed", error="payload fetch failed")
        return

    payload = job.get("payload") or {}
    try:
        out = handler(payload, api.http)
    except Exception as e:                              # noqa: BLE001 — never crash the worker
        log.exception("handler.crash", kind=kind, scan_id=scan_id)
        api.post_result(scan_id, "failed", error=f"handler crash: {e}")
        return

    if out.get("verdict") == "failed":
        api.post_result(scan_id, "failed", error=str(out.get("error", "unknown")))
        return

    api.post_result(
        scan_id, "done",
        verdict=out.get("verdict", ""),
        result=out.get("result", {}),
    )


def main() -> int:
    if not INGEST_SECRET:
        log.error("startup.no_secret",
                  msg="SMG_INGEST_HMAC_KEY not set — worker cannot authenticate to api")
        return 2

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    rdb = redis.from_url(REDIS_URL, decode_responses=True)
    api = APIClient(API_BASE, INGEST_SECRET)
    log.info("worker.start", queue=QUEUE_KEY, api=API_BASE, kinds=list(HANDLERS.keys()))

    while _running:
        try:
            item = rdb.blpop(QUEUE_KEY, timeout=POLL_TIMEOUT)
        except redis.RedisError as exc:
            log.warning("redis.error", error=str(exc))
            time.sleep(2)
            continue

        if item is None:
            continue

        _, raw = item
        try:
            env = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("job.bad_json", raw=raw[:200])
            continue

        log.info("job.start", scan_id=env.get("scan_id"), kind=env.get("kind"))
        process_one(api, env)

    log.info("worker.stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
