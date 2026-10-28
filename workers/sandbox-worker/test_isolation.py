"""Regression tests for the browser worker's hard time limit."""

import sys
import time
import unittest

from isolation import run_isolated


class IsolationTests(unittest.TestCase):
    def test_successful_child_result(self):
        command = [sys.executable, "-c", "import json,sys; print(json.dumps(json.load(sys.stdin)))"]
        self.assertEqual(run_isolated({"verdict": "clean"}, command, 2), {"verdict": "clean"})

    def test_hung_child_is_stopped(self):
        start = time.monotonic()
        command = [sys.executable, "-c", "import time; time.sleep(60)"]
        self.assertEqual(run_isolated({}, command, 1),
                         {"verdict": "failed", "error": "sandbox exceeded time limit"})
        self.assertLess(time.monotonic() - start, 4)

    def test_invalid_child_result_fails_closed(self):
        command = [sys.executable, "-c", "print('not json')"]
        self.assertEqual(run_isolated({}, command, 2),
                         {"verdict": "failed", "error": "sandbox returned invalid result"})


if __name__ == "__main__":
    unittest.main()
