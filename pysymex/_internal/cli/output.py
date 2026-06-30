# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Shared CLI output helpers for consistent status, error, and progress messages."""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import TextIO

from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)


def _error_line(message: str) -> str:
    """Return a standardized CLI error line."""
    return f"Error: {message}"


def _warning_line(message: str) -> str:
    """Return a standardized CLI warning line."""
    return f"Warning: {message}"


def _error(message: str, *, stream: TextIO | None = None) -> None:
    """Print a standardized CLI error line to stderr by default."""
    logger.debug("CLI error: %s", message, category="cli")
    target_stream = stream if stream is not None else sys.stderr
    print(CliOutput.error_line(message), file=target_stream)


def _warning(message: str, *, stream: TextIO | None = None) -> None:
    """Print a standardized CLI warning line to stderr by default."""
    logger.debug("CLI warning: %s", message, category="cli")
    target_stream = stream if stream is not None else sys.stderr
    print(CliOutput.warning_line(message), file=target_stream)


def _progress_line(
    completed: int,
    total: int,
    file_path: object,
    status: str,
) -> str:
    """Build a single normalized CLI progress line."""
    percent = completed * 100 // total if total else 0
    file_name = Path(str(file_path)).name if file_path else "?"
    return f"Progress: [{completed}/{total}] {percent}% {file_name} {status}"


def _emit(
    content: str,
    *,
    output_path: str | None,
    verbose: bool,
) -> None:
    """Write CLI output to file or print to stdout with consistent save messages."""
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
        logger.verbose("Wrote CLI report: %s", output_path)
        if verbose:
            _safe_print(f"Report saved to: {output_path}")
        return
    _safe_print(content)


_PRINT_LOCK = threading.Lock()


def _safe_print(message: str = "") -> None:
    """Print text safely across console encodings (e.g. cp1252 on Windows)."""
    with _PRINT_LOCK:
        try:
            sys.stdout.write(message + "\n")
            sys.stdout.flush()
        except UnicodeEncodeError:
            encoding = sys.stdout.encoding or "utf-8"
            try:
                fallback = message.encode(encoding, errors="replace").decode(
                    encoding,
                    errors="replace",
                )
                sys.stdout.write(fallback + "\n")
                sys.stdout.flush()
            except Exception:
                # Final fallback: strip all non-ascii
                try:
                    ascii_fallback = message.encode("ascii", errors="replace").decode("ascii")
                    sys.stdout.write(ascii_fallback + "\n")
                    sys.stdout.flush()
                except Exception:
                    logger.trace("CLI ascii stdout fallback failed", exc_info=True)
        except Exception:
            # If even writing fails (e.g. broken pipe), don't crash the whole engine
            logger.trace("CLI stdout write failed", exc_info=True)


def _safe_print_public(message: str = "") -> None:
    """Public wrapper for safe console output."""
    _safe_print(message)


class CliOutput:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    error_line = staticmethod(_error_line)
    warning_line = staticmethod(_warning_line)
    error = staticmethod(_error)
    warning = staticmethod(_warning)
    progress_line = staticmethod(_progress_line)
    emit = staticmethod(_emit)
    safe_print = staticmethod(_safe_print_public)
