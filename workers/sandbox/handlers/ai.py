"""AI phishing scoring via the Anthropic Claude API.

Payload:
    {
      "subject":           "...",
      "body_text":         "...",
      "from_addr":         "user@example.com",
      "from_display_name": "Optional Display",
      "headers":           {"Reply-To": "...", ...}   # optional
    }

If ANTHROPIC_API_KEY is unset we still return a coarse verdict from a tiny
keyword heuristic so the pipeline produces useful output in CI / dev.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx
import structlog

log = structlog.get_logger()

API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
MODEL = os.environ.get("SMG_AI_MODEL", "claude-haiku-4-5-20251001")
MAX_BODY = 8000     # chars; truncate to keep cost predictable

PHISH_KEYWORDS = re.compile(
    r"\b(?:urgent|verify your account|password expired|click here to|"
    r"wire transfer|invoice attached|reset your password|account suspended|"
    r"bitcoin|gift card|payroll change)\b",
    re.IGNORECASE,
)
DISPLAY_VS_DOMAIN = re.compile(r"\(([^)]+)\)")  # naive: "Bank of X (different-domain)"

_PROMPT = """You are an email security analyst. Score the following email as phishing on a 0.0 to 1.0 scale where:
- 0.0-0.3 = clearly legitimate (newsletters, transactional from a known service)
- 0.3-0.7 = suspicious (urgency, mismatched sender, asks for credentials but plausible)
- 0.7-1.0 = clearly phishing (impersonation, credential harvest, BEC, account takeover lure)

Reply with ONLY a JSON object: {"score": <0..1>, "label": "<one or two words>", "reasons": ["<short reason>", ...]}

Email:
From: {from_line}
Subject: {subject}

{body}
"""


def _client():
    """Lazy import so workers without the API key still start fast."""
    if not API_KEY:
        return None
    try:
        from anthropic import Anthropic
        return Anthropic(api_key=API_KEY)
    except Exception as e:                              # noqa: BLE001
        log.warning("anthropic.import_error", err=str(e))
        return None


def _heuristic_only(subject: str, body: str) -> dict[str, Any]:
    matches = sorted(set(m.lower() for m in PHISH_KEYWORDS.findall(subject + " " + body)))
    score = min(1.0, 0.25 * len(matches))
    if score >= 0.7:
        verdict = "malicious"
    elif score >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {
        "verdict": verdict,
        "result": {
            "engine": "heuristic-fallback",
            "score": round(score, 2),
            "label": "keyword-match" if matches else "no-signals",
            "reasons": matches,
            "model": None,
            "ai_available": bool(API_KEY),
        },
    }


def handle_ai(payload: dict[str, Any], _http: httpx.Client) -> dict[str, Any]:
    subject = (payload.get("subject") or "").strip()
    body = (payload.get("body_text") or "").strip()[:MAX_BODY]
    from_addr = (payload.get("from_addr") or "").strip()
    from_display = (payload.get("from_display_name") or "").strip()
    from_line = f"{from_display} <{from_addr}>" if from_display else from_addr

    if not subject and not body:
        return {"verdict": "clean", "result": {"reason": "empty subject and body"}}

    client = _client()
    if client is None:
        return _heuristic_only(subject, body)

    prompt = _PROMPT.format(from_line=from_line, subject=subject, body=body or "(no body)")
    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        # Concatenate any text blocks (Claude can return multiple).
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    except Exception as e:                              # noqa: BLE001
        log.warning("anthropic.api_error", err=str(e))
        out = _heuristic_only(subject, body)
        out["result"]["api_error"] = str(e)
        return out

    # Strip markdown fences if Claude wraps the JSON in ```json blocks.
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()

    try:
        parsed = json.loads(text)
        score = float(parsed.get("score", 0))
        label = str(parsed.get("label", "")).strip()[:64]
        reasons = [str(r)[:200] for r in parsed.get("reasons", [])][:5]
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        log.warning("anthropic.parse_error", err=str(e), raw=text[:200])
        out = _heuristic_only(subject, body)
        out["result"]["parse_error"] = str(e)
        out["result"]["raw"] = text[:500]
        return out

    if score >= 0.7:
        verdict = "malicious"
    elif score >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "result": {
            "engine": "claude",
            "model": MODEL,
            "score": round(score, 2),
            "label": label,
            "reasons": reasons,
            "ai_available": True,
        },
    }
