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

"""Streaming event reader for trace analyzer JSONL inputs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterable, Iterator

logger = get_logger(__name__)


def _from_path(
    path: str,
    *,
    on_malformed_line: Callable[[json.JSONDecodeError], None] | None = None,
) -> Generator[tuple[str, dict[str, object]]]:
    """Yield ``(raw_line, parsed_event)`` tuples from a JSONL trace file.

    The file is read one line at a time, ensuring O(1) heap allocation
    regardless of trace file size.  Blank lines are silently skipped.
    Lines that are not valid JSON emit a warning to *stderr* and are
    **skipped** — the stream never terminates on corrupt input.

    Args:
        path: Filesystem path to the ``.jsonl`` trace file.
        on_malformed_line: Optional callback invoked when a non-empty line
            cannot be decoded as JSON.

    Yields:
        ``(raw_line, parsed_event)`` where *raw_line* is the untransformed
        UTF-8 string (used when ``--format jsonl`` re-emits the line
        unchanged) and *parsed_event* is the decoded JSON dict.

    """
    handle: Iterator[str]
    is_gz = str(path).endswith(".gz")

    if is_gz:
        import gzip

        handle = gzip.open(path, "rt", encoding="utf-8")
    else:
        handle = open(path, encoding="utf-8")

    try:
        yield from TraceEvents.from_lines(
            handle,
            source=path,
            on_malformed_line=on_malformed_line,
        )
    finally:
        try:
            close_fn = getattr(handle, "close", None)
            if callable(close_fn):
                close_fn()
        except Exception:
            logger.debug("Failed to close trace input stream %s", path, exc_info=True)


def _from_lines(
    lines: Iterable[str],
    *,
    source: str = "<stream>",
    on_malformed_line: Callable[[json.JSONDecodeError], None] | None = None,
) -> Generator[tuple[str, dict[str, object]]]:
    """Yield parsed trace events from an iterable of JSONL lines."""
    for raw in lines:
        raw = raw.rstrip("\n\r")
        raw = raw.removeprefix("\ufeff")
        if not raw:
            continue
        try:
            event: dict[str, object] = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping malformed trace line in %s: %s", source, exc)
            if on_malformed_line is not None:
                on_malformed_line(exc)
            continue
        yield raw, event


class TraceEvents:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    from_path = staticmethod(_from_path)
    from_lines = staticmethod(_from_lines)
