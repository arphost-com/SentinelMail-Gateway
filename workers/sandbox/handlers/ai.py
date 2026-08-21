"""Provider-selectable asynchronous AI phishing scoring.

Provider configuration is fetched per job from the HMAC-authenticated internal
API. Missing keys, unsupported provider names, request errors, and invalid
responses remain explicitly unavailable or inconclusive. The local heuristic is
supporting metadata only; it is never presented as a successful AI "clean"
verdict.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

log = structlog.get_logger()

DEFAULT_PROVIDER = "anthropic"
DEFAULT_MODELS = {
    "anthropic": "claude-haiku-4-5-20251001",
    "openai": "gpt-5-mini",
}
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
MAX_BODY = 8000

PHISH_KEYWORDS = re.compile(
    r"\b(?:urgent|verify your account|password expired|click here to|"
    r"wire transfer|invoice attached|reset your password|account suspended|"
    r"bitcoin|gift card|payroll change)\b",
    re.IGNORECASE,
)

_PROMPT = """You are an email security analyst. Score the following email as phishing on a 0.0 to 1.0 scale where:
- 0.0-0.3 = clearly legitimate (newsletters, transactional from a known service)
- 0.3-0.7 = suspicious (urgency, mismatched sender, asks for credentials but plausible)
- 0.7-1.0 = clearly phishing (impersonation, credential harvest, BEC, account takeover lure)

Reply with ONLY a JSON object: {{"score": <0..1>, "label": "<one or two words>", "reasons": ["<short reason>", ...]}}

Email:
From: {from_line}
Subject: {subject}

{body}
"""

_OPENAI_RESPONSE_FORMAT = {
    "type": "json_schema",
    "name": "email_security_score",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "score": {"type": "number", "minimum": 0, "maximum": 1},
            "label": {"type": "string"},
            "reasons": {
                "type": "array",
                "items": {"type": "string"},
                "maxItems": 5,
            },
        },
        "required": ["score", "label", "reasons"],
        "additionalProperties": False,
    },
}


@dataclass(frozen=True)
class ProviderSettings:
    name: str
    model: str
    api_key: str
    available: bool
    availability_reason: str


def provider_settings(payload: dict[str, Any]) -> ProviderSettings:
    """Read the ephemeral HMAC-fetched provider configuration for this job."""
    config = payload.get("_ai_config") or {}
    name = str(config.get("provider") or DEFAULT_PROVIDER).strip().lower()
    model = str(config.get("model") or DEFAULT_MODELS.get(name, "")).strip()
    return ProviderSettings(
        name=name,
        model=model,
        api_key=str(config.get("api_key") or "").strip(),
        available=bool(config.get("available")),
        availability_reason=str(config.get("availability_reason") or "AI provider is not configured"),
    )


def _provider_label(name: str) -> str:
    return "OpenAI" if name == "openai" else name.title()


def _heuristic_only(
    subject: str,
    body: str,
    *,
    provider: str,
    model: str | None,
    unavailable_reason: str,
    verdict: str = "unavailable",
) -> dict[str, Any]:
    matches = sorted(set(match.lower() for match in PHISH_KEYWORDS.findall(subject + " " + body)))
    score = min(1.0, 0.25 * len(matches))
    if score >= 0.7:
        heuristic_verdict = "malicious"
    elif score >= 0.3:
        heuristic_verdict = "suspicious"
    else:
        heuristic_verdict = "clean"
    return {
        "verdict": verdict,
        "result": {
            "engine": "heuristic-fallback",
            "provider": provider,
            "score": round(score, 2),
            "label": "keyword-match" if matches else "no-signals",
            "reasons": matches,
            "model": model,
            "ai_available": False,
            "availability_reason": unavailable_reason,
            "heuristic_verdict": heuristic_verdict,
        },
    }


def _anthropic_text(prompt: str, settings: ProviderSettings) -> str:
    """Call Anthropic lazily so other provider selections start normally."""
    from anthropic import Anthropic

    client = Anthropic(api_key=settings.api_key)
    response = client.messages.create(
        model=settings.model,
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    )


def _openai_text(prompt: str, settings: ProviderSettings, http: httpx.Client) -> str:
    """Call the fixed OpenAI Responses endpoint using the worker HTTP client."""
    response = http.post(
        OPENAI_RESPONSES_URL,
        headers={
            "Authorization": f"Bearer {settings.api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": settings.model,
            "input": prompt,
            "max_output_tokens": 400,
            "store": False,
            "text": {"format": _OPENAI_RESPONSE_FORMAT},
        },
    )
    response.raise_for_status()
    payload = response.json()
    for item in payload.get("output", []):
        for content in item.get("content", []):
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                return content["text"]
    raise ValueError("OpenAI response did not contain output_text")


def _parse_score(text: str) -> tuple[float, str, list[str]]:
    normalized = text.strip()
    if normalized.startswith("```"):
        normalized = normalized.strip("`")
        if normalized.lower().startswith("json"):
            normalized = normalized[4:]
        normalized = normalized.strip()
    parsed = json.loads(normalized)
    score = max(0.0, min(1.0, float(parsed.get("score", 0))))
    label = str(parsed.get("label", "")).strip()[:64]
    reasons = [str(reason)[:200] for reason in parsed.get("reasons", [])][:5]
    return score, label, reasons


def handle_ai(payload: dict[str, Any], http: httpx.Client) -> dict[str, Any]:
    subject = (payload.get("subject") or "").strip()
    body = (payload.get("body_text") or "").strip()[:MAX_BODY]
    from_addr = (payload.get("from_addr") or "").strip()
    from_display = (payload.get("from_display_name") or "").strip()
    from_line = f"{from_display} <{from_addr}>" if from_display else from_addr

    if not subject and not body:
        return {"verdict": "clean", "result": {"reason": "empty subject and body"}}

    settings = provider_settings(payload)
    if settings.name not in DEFAULT_MODELS:
        return _heuristic_only(
            subject,
            body,
            provider=settings.name,
            model=settings.model or None,
            unavailable_reason=f"Unsupported AI provider: {settings.name or '(empty)'}",
        )
    if not settings.available or not settings.api_key:
        return _heuristic_only(
            subject,
            body,
            provider=settings.name,
            model=settings.model,
            unavailable_reason=settings.availability_reason,
        )

    prompt = _PROMPT.format(from_line=from_line, subject=subject, body=body or "(no body)")
    try:
        if settings.name == "anthropic":
            text = _anthropic_text(prompt, settings)
            engine = "claude"
        else:
            text = _openai_text(prompt, settings, http)
            engine = "openai"
    except Exception as exc:  # noqa: BLE001 -- provider failure must not crash worker
        log.warning("ai.provider_error", provider=settings.name, error_type=type(exc).__name__)
        return _heuristic_only(
            subject,
            body,
            provider=settings.name,
            model=settings.model,
            verdict="inconclusive",
            unavailable_reason=f"{_provider_label(settings.name)} request failed",
        )

    try:
        score, label, reasons = _parse_score(text)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        log.warning("ai.parse_error", provider=settings.name, error_type=type(exc).__name__)
        return _heuristic_only(
            subject,
            body,
            provider=settings.name,
            model=settings.model,
            verdict="inconclusive",
            unavailable_reason=f"{_provider_label(settings.name)} returned an invalid response",
        )

    if score >= 0.7:
        verdict = "malicious"
    elif score >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "result": {
            "engine": engine,
            "provider": settings.name,
            "model": settings.model,
            "score": round(score, 2),
            "label": label,
            "reasons": reasons,
            "ai_available": True,
        },
    }
