"""Wall clock and process group isolation for untrusted browser scans."""

import json
import os
import signal
import subprocess  # nosec B404 - the fixed child command isolates untrusted browser work
import sys
from pathlib import Path
from typing import Any

JOB_TIMEOUT_SECONDS = 75
SCAN_COMMAND = [sys.executable, str(Path(__file__).with_name("scan_once.py"))]


def run_isolated(payload: dict[str, Any], command: list[str] | None = None,
                 timeout: int = JOB_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Bound one Chromium scan and kill its whole process group on a hang."""
    proc = subprocess.Popen(command or SCAN_COMMAND, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)  # nosec B603 - no shell; URL arrives on stdin
    try:
        stdout, _ = proc.communicate(json.dumps(payload).encode(), timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        return {"verdict": "failed", "error": "sandbox exceeded time limit"}
    if proc.returncode != 0:
        return {"verdict": "failed", "error": "sandbox process failed"}
    try:
        result = json.loads(stdout)
    except (ValueError, UnicodeDecodeError):
        return {"verdict": "failed", "error": "sandbox returned invalid result"}
    if not isinstance(result, dict):
        return {"verdict": "failed", "error": "sandbox returned invalid result"}
    return result
