"""Shared command helpers for Docker test-runner diagnostics."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence


def clean_command_text(text: str) -> str:
    """Normalize command output from Windows tools that may emit UTF-16 fragments."""
    return text.replace("\x00", "").strip()


def command_error_text(result: subprocess.CompletedProcess[str]) -> str:
    """Return the most useful failure text from a CLI command."""
    details = "\n".join(
        cleaned for text in (result.stderr, result.stdout) if (cleaned := clean_command_text(text))
    )
    if details:
        return details
    return f"command exited with status {result.returncode}"


def probe_command(command: Sequence[str], timeout: float) -> tuple[int | None, str]:
    """Run a diagnostic command and return its exit status plus normalized output."""
    try:
        result = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError:
        return None, f"{command[0]} command not found."
    except subprocess.TimeoutExpired:
        return None, f"{' '.join(command)} timed out after {timeout:.1f}s."

    output = command_error_text(result)
    return result.returncode, output
