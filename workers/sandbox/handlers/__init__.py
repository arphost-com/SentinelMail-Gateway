"""Scan handler registry.

Each handler is a callable (payload: dict, http: httpx.Client) -> dict where
the returned dict shape is {"verdict": str, "result": dict, "error"?: str}.
Verdict labels: "clean" | "suspicious" | "malicious" | "failed".
"""

from typing import Any, Callable

import httpx

from .qr import handle_qr
from .ai import handle_ai
from .outbound import handle_outbound

HandlerFn = Callable[[dict[str, Any], httpx.Client], dict[str, Any]]

HANDLERS: dict[str, HandlerFn] = {
    "qr": handle_qr,
    "ai": handle_ai,
    "outbound": handle_outbound,
    # "sandbox": registered in the sandbox-worker image (heavy)
}
