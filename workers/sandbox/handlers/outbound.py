"""Outbound compromise detection — heuristics on send patterns.

Payload:
    {
      "from_addr":    "alice@example.com",
      "to_addrs":     ["a@x.com", "b@y.com", ...],
      "subject":      "...",
      "sent_at":      "2026-05-22T15:30:00Z",   # ISO-8601 UTC
      "client_ip":    "1.2.3.4",                # optional
      "auth_user":    "alice",                  # SASL/submission user if known
    }

Each signal adds a fixed weight to the score. Verdicts:
  0.0-0.3  clean
  0.3-0.7  suspicious
  0.7+     malicious  (account-takeover / BEC pattern)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import httpx

# Subject keywords associated with BEC / wire-fraud lures.
BEC_KEYWORDS = re.compile(
    r"\b(?:urgent wire|update bank details|change payment|payroll change|"
    r"new account number|invoice attached|w-?9|w-?2|gift cards?)\b",
    re.IGNORECASE,
)


def _parse_ts(s: str) -> datetime | None:
    if not s:
        return None
    try:
        # Accept "Z" suffix as UTC (datetime.fromisoformat handles it from 3.11).
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def handle_outbound(payload: dict[str, Any], _http: httpx.Client) -> dict[str, Any]:
    to_addrs = [a.strip() for a in (payload.get("to_addrs") or []) if a and a.strip()]
    subject = payload.get("subject") or ""
    sent_at = _parse_ts(payload.get("sent_at") or "")

    score = 0.0
    reasons: list[str] = []

    # Recipient fan-out — a single sender blasting many people.
    if len(to_addrs) >= 20:
        score += 0.4
        reasons.append(f"high recipient count: {len(to_addrs)}")
    elif len(to_addrs) >= 10:
        score += 0.2
        reasons.append(f"elevated recipient count: {len(to_addrs)}")

    # Distinct domains — BEC often hits many companies at once.
    domains = {a.split("@", 1)[1].lower() for a in to_addrs if "@" in a}
    if len(domains) >= 10:
        score += 0.3
        reasons.append(f"recipients across {len(domains)} domains")
    elif len(domains) >= 5:
        score += 0.15
        reasons.append(f"recipients across {len(domains)} domains")

    # Off-hours sending (03:00-06:00 UTC). Tunable per-org later.
    if sent_at is not None:
        hour_utc = sent_at.astimezone(timezone.utc).hour
        if 3 <= hour_utc < 6:
            score += 0.2
            reasons.append(f"off-hours send (UTC {hour_utc:02d}:00)")

    # Subject keyword match.
    matched = sorted(set(m.lower() for m in BEC_KEYWORDS.findall(subject)))
    if matched:
        score += 0.3
        reasons.append("BEC keywords: " + ", ".join(matched))

    score = min(1.0, round(score, 2))

    if score >= 0.7:
        verdict = "malicious"
    elif score >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "result": {
            "engine": "heuristic-outbound",
            "score": score,
            "reasons": reasons,
            "recipient_count": len(to_addrs),
            "recipient_domain_count": len(domains),
            "subject_keyword_matches": matched,
        },
    }
