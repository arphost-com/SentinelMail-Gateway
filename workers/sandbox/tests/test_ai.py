from __future__ import annotations

import importlib.util
import os
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
        spec.loader.exec_module(module)
        return module


class AIAvailabilityTests(unittest.TestCase):
    def test_missing_key_is_unavailable_not_clean(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False):
            module = load_ai_module()
            result = module.handle_ai(
                {"subject": "Ordinary receipt", "body_text": "Thank you"},
                mock.Mock(),
            )

        self.assertEqual(result["verdict"], "unavailable")
        self.assertFalse(result["result"]["ai_available"])
        self.assertEqual(result["result"]["heuristic_verdict"], "clean")

    def test_unavailable_result_preserves_heuristic_warning_as_metadata(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False):
            module = load_ai_module()
            result = module.handle_ai(
                {
                    "subject": "Urgent: verify your account",
                    "body_text": "Reset your password and click here to continue.",
                },
                mock.Mock(),
            )

        self.assertEqual(result["verdict"], "unavailable")
        self.assertIn(result["result"]["heuristic_verdict"], {"suspicious", "malicious"})


if __name__ == "__main__":
    unittest.main()
