"""Run one browser scan in a child process so the worker can enforce a wall clock limit."""

import json
import sys
from contextlib import redirect_stdout

import httpx

from handler import handle_sandbox


def main() -> int:
    payload = json.load(sys.stdin)
    with redirect_stdout(sys.stderr), httpx.Client(timeout=45.0) as client:
        result = handle_sandbox(payload, client)
    json.dump(result, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
