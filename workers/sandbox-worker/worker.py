"""Sandbox worker entrypoint.

Same loop as the light worker (workers/sandbox/worker.py) but:
  - reads from a different Redis queue (smg:scan_jobs_sandbox)
  - only knows the `sandbox` kind (handler is Playwright + Chromium)

Splitting keeps the heavy ~1.2 GB Playwright image off the light worker.
The Go API routes by kind on enqueue (internal/scan/scan.go), so jobs
land in the right queue without coordination here.
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

from handler import handle_sandbox

log = structlog.get_logger()

REDIS_URL = os.environ.get("SMG_REDIS_URL", "redis://redis:6379/0")
QUEUE_KEY = os.environ.get("SMG_SANDBOX_QUEUE", "smg:scan_jobs_sandbox")
POLL_TIMEOUT = int(os.environ.get("SMG_POLL_TIMEOUT", "5"))
API_BASE = os.environ.get("SMG_API_BASE", "http://api:8080").rstrip("/")
INGEST_SECRET = os.environ.get("SMG_INGEST_HMAC_KEY", "")

HANDLERS = {"sandbox": handle_sandbox}

_running = True


def _shutdown(signum: int, _frame: object) -> None:
    global _running
    log.info("shutdown.signal", signum=signum)
    _running = False


class APIClient:
    def __init__(self, base: str, secret: str):
        self.base = base
        self.secret = secret.encode() if secret else b""
        self.http = httpx.Client(timeout=45.0)  # screenshots can be large

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
        log.info("job.skip_unhandled_kind", kind=kind, scan_id=scan_id)
        return
    if not api.post_result(scan_id, "running"):
        return
    job = api.get_job(scan_id)
    if job is None:
        api.post_result(scan_id, "failed", error="payload fetch failed")
        return
    try:
        out = handler(job.get("payload") or {}, api.http)
    except Exception as e:                                  # noqa: BLE001
        log.exception("handler.crash", kind=kind, scan_id=scan_id)
        api.post_result(scan_id, "failed", error=f"handler crash: {e}")
        return
    if out.get("verdict") == "failed":
        api.post_result(scan_id, "failed", error=str(out.get("error", "unknown")))
        return
    api.post_result(scan_id, "done", verdict=out.get("verdict", ""), result=out.get("result", {}))


def main() -> int:
    if not INGEST_SECRET:
        log.error("startup.no_secret",
                  msg="SMG_INGEST_HMAC_KEY not set — sandbox-worker cannot authenticate to api")
        return 2

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    rdb = redis.from_url(REDIS_URL, decode_responses=True)
    api = APIClient(API_BASE, INGEST_SECRET)
    log.info("sandbox-worker.start", queue=QUEUE_KEY, api=API_BASE)

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

    log.info("sandbox-worker.stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
