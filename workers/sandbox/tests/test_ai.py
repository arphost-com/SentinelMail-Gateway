from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest import mock


def load_ai_module():
    httpx = types.ModuleType("httpx")
    httpx.Client = object
    structlog = types.ModuleType("structlog")
    structlog.get_logger = lambda: mock.Mock()
    with mock.patch.dict(sys.modules, {"httpx": httpx, "structlog": structlog}):
        path = Path(__file__).parents[1] / "handlers" / "ai.py"
        spec = importlib.util.spec_from_file_location("sentinelmail_test_ai", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load SentinelMail AI handler test module")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self.payload


class AIProviderTests(unittest.TestCase):
    def test_missing_anthropic_key_is_unavailable_not_clean(self) -> None:
        module = load_ai_module()
        result = module.handle_ai(
            {
                "subject": "Ordinary receipt",
                "body_text": "Thank you",
                "_ai_config": {"provider": "anthropic", "model": "claude-test", "available": False, "availability_reason": "anthropic API key is not configured"},
            },
            mock.Mock(),
        )

        self.assertEqual(result["verdict"], "unavailable")
        self.assertFalse(result["result"]["ai_available"])
        self.assertEqual(result["result"]["provider"], "anthropic")
        self.assertEqual(result["result"]["heuristic_verdict"], "clean")
        self.assertEqual(
            result["result"]["availability_reason"],
            "anthropic API key is not configured",
        )

    def test_missing_openai_key_reports_selected_provider(self) -> None:
        module = load_ai_module()
        result = module.handle_ai(
            {
                "subject": "Ordinary receipt",
                "body_text": "Thank you",
                "_ai_config": {"provider": "openai", "model": "gpt-5-mini", "available": False, "availability_reason": "openai API key is not configured"},
            },
            mock.Mock(),
        )

        self.assertEqual(result["verdict"], "unavailable")
        self.assertEqual(result["result"]["provider"], "openai")
        self.assertEqual(result["result"]["model"], "gpt-5-mini")
        self.assertEqual(
            result["result"]["availability_reason"],
            "openai API key is not configured",
        )

    def test_openai_responses_success_uses_structured_output_without_storage(self) -> None:
        api_payload = {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": '{"score":0.88,"label":"phishing","reasons":["credential lure"]}',
                        }
                    ],
                }
            ]
        }
        http = mock.Mock()
        http.post.return_value = FakeResponse(api_payload)
        module = load_ai_module()
        result = module.handle_ai(
            {
                "subject": "Urgent account notice",
                "body_text": "Verify your account.",
                "from_addr": "sender@example.test",
                "_ai_config": {"provider": "openai", "model": "gpt-5-mini-test", "api_key": "test-openai-key", "available": True},
            },
            http,
        )

        self.assertEqual(result["verdict"], "malicious")
        self.assertTrue(result["result"]["ai_available"])
        self.assertEqual(result["result"]["engine"], "openai")
        self.assertEqual(result["result"]["provider"], "openai")
        call = http.post.call_args
        self.assertEqual(call.args[0], "https://api.openai.com/v1/responses")
        self.assertEqual(call.kwargs["headers"]["Authorization"], "Bearer test-openai-key")
        self.assertFalse(call.kwargs["json"]["store"])
        self.assertEqual(call.kwargs["json"]["text"]["format"]["type"], "json_schema")

    def test_openai_request_failure_is_inconclusive(self) -> None:
        http = mock.Mock()
        http.post.side_effect = RuntimeError("provider unavailable")
        module = load_ai_module()
        result = module.handle_ai(
            {"subject": "Urgent: verify your account", "body_text": "Click here to continue.", "_ai_config": {"provider": "openai", "model": "gpt-5-mini", "api_key": "test-openai-key", "available": True}},
            http,
        )

        self.assertEqual(result["verdict"], "inconclusive")
        self.assertFalse(result["result"]["ai_available"])
        self.assertEqual(result["result"]["availability_reason"], "OpenAI request failed")
        self.assertIn(result["result"]["heuristic_verdict"], {"suspicious", "malicious"})

    def test_unsupported_provider_is_explicitly_unavailable(self) -> None:
        module = load_ai_module()
        result = module.handle_ai(
            {"subject": "Ordinary receipt", "body_text": "Thank you", "_ai_config": {"provider": "other", "available": False}},
            mock.Mock(),
        )

        self.assertEqual(result["verdict"], "unavailable")
        self.assertEqual(result["result"]["provider"], "other")
        self.assertEqual(result["result"]["availability_reason"], "Unsupported AI provider: other")

if __name__ == "__main__":
    unittest.main()
