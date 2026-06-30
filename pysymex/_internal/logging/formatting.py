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

"""Text and JSON formatting for diagnostics."""

from __future__ import annotations

import json
import sys
import time
from typing import TYPE_CHECKING, TextIO

from pysymex._internal.logging.levels import LogLevel

if TYPE_CHECKING:
    from pysymex._internal.logging.entry import LogEntry


class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"


def supports_color(stream: TextIO) -> bool:
    """Check if the given stream supports ANSI color codes."""
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False
    if sys.platform == "win32":
        try:
            import os

            return bool(os.environ.get("TERM") or "ANSICON" in os.environ)
        except OSError:
            return True
    return True


def format_log_entry(entry: LogEntry, *, color: bool, show_time: bool) -> str:
    """Format one enabled event as a progress-safe terminal line."""
    parts: list[str] = []
    if show_time:
        timestamp = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
        parts.append(f"{Colors.GRAY}{timestamp}{Colors.RESET}" if color else timestamp)

    badge, badge_color = _badge_for(entry)
    if color and badge_color:
        parts.append(f"{badge_color}{badge}{Colors.RESET}")
    else:
        parts.append(badge)

    if entry.category not in {"general", "success", "warning", "error"}:
        category_label = entry.category
        if entry.category == "python":
            category_label = entry.source_module or entry.logger_name
        parts.append(
            f"{Colors.CYAN}[{category_label}]{Colors.RESET}" if color else f"[{category_label}]",
        )

    parts.append(entry.message)
    return " ".join(parts)


def format_json_entry(entry: LogEntry, *, include_exception: bool) -> str:
    """Format one event as compact JSONL."""
    payload: dict[str, object] = {
        "timestamp": entry.timestamp,
        "level": entry.level.name,
        "category": entry.category,
        "logger": entry.logger_name,
        "message": entry.message,
    }
    if entry.source_module is not None:
        payload["source_module"] = entry.source_module
    if entry.event_name is not None:
        payload["event_name"] = entry.event_name
    if entry.metadata:
        payload["metadata"] = {key: _json_safe(value) for key, value in entry.metadata.items()}
    if include_exception and entry.exception is not None:
        payload["exception"] = {
            "type": entry.exception.exc_type.__name__,
            "message": str(entry.exception.exc_value),
            "traceback": entry.exception.format(),
        }
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _badge_for(entry: LogEntry) -> tuple[str, str]:
    """Determine the badge string and ANSI color sequence for a log entry.

    Args:
        entry: The LogEntry object to extract badge metadata from.

    Returns:
        A tuple containing the badge text (e.g., "[OK]", "[ERR]") and the
        associated ANSI escape color code.

    """
    if entry.event_name == "success":
        return "[OK]", Colors.GREEN
    if entry.event_name == "warning":
        return "[WARN]", Colors.YELLOW
    if entry.event_name == "error":
        return "[ERR]", Colors.RED
    if entry.level == LogLevel.TRACE:
        return "[TRACE]", Colors.GRAY
    if entry.level == LogLevel.DEBUG:
        return "[DEBUG]", Colors.MAGENTA
    if entry.level == LogLevel.VERBOSE:
        return "[VERBOSE]", Colors.BLUE
    if entry.level == LogLevel.QUIET:
        return "[ERR]", Colors.RED
    return "[INFO]", Colors.WHITE


def _json_safe(value: object) -> object:
    """Coerce a value to a JSON-safe type.

    Basic primitive types (None, str, int, float, bool) are returned unmodified.
    Any other object type is converted to its string representation.

    Args:
        value: The object to convert.

    Returns:
        A JSON-serializable primitive or string representation of the object.

    """
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return str(value)
