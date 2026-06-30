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

"""Public diagnostics, logging, and summary helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, TextIO

from pysymex._internal.logging.categories import LogCategory
from pysymex._internal.logging.levels import LogLevel
from pysymex._internal.logging.logger import PysymexLogger

if TYPE_CHECKING:
    from pathlib import Path

Logger = PysymexLogger


def get(name: str = "pysymex") -> Logger:
    """Return the shared logger, optionally named for source metadata."""
    from pysymex._internal.logging.root import get_logger

    return get_logger(name)


def configure(
    level: LogLevel | None = None,
    color: bool = True,
    file_path: Path | None = None,
    *,
    stream: TextIO | None = None,
    categories: set[LogCategory | str] | frozenset[LogCategory | str] | None = None,
    history_capacity: int = 0,
    jsonl_path: Path | None = None,
    deterministic: bool = False,
    show_time: bool = True,
) -> Logger:
    """Configure and return the process-wide logger."""
    from pysymex._internal.logging.root import configure_logging

    return configure_logging(
        level=level if level is not None else LogLevel.NORMAL,
        color=color,
        file_path=file_path,
        stream=stream,
        categories=categories,
        history_capacity=history_capacity,
        jsonl_path=jsonl_path,
        deterministic=deterministic,
        show_time=show_time,
    )


__all__ = [
    "LogCategory",
    "LogLevel",
    "Logger",
    "configure",
    "get",
]
