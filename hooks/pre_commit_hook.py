#!/usr/bin/env python3
"""
Git pre-commit hook for SecretGuard-AI.

This script is invoked by git's pre-commit hook lifecycle.  It delegates
to ``secretguard hook`` which performs the full detection pipeline on
staged files.

Installation (manual):
    cp hooks/pre_commit_hook.py .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit

Or use the pre-commit framework (recommended) — see .pre-commit-config.yaml.
"""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    """Invoke ``secretguard hook`` and propagate its exit code."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "secretguard.cli", "hook"],
            capture_output=False,
        )
        return result.returncode
    except FileNotFoundError:
        print(
            "⚠️  SecretGuard-AI is not installed.\n"
            "   Install with: pip install -e .\n"
            "   Skipping secret scan.",
            file=sys.stderr,
        )
        return 0
    except Exception as exc:
        print(f"⚠️  SecretGuard hook error: {exc}", file=sys.stderr)
        return 0  # Don't block commits on hook infrastructure failures.


if __name__ == "__main__":
    sys.exit(main())
