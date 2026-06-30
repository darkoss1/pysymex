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

"""Configuration for pysymex diagnostics."""

from __future__ import annotations

from dataclasses import dataclass

from pysymex._internal.logging.categories import CategoryInput, normalize_categories
from pysymex._internal.logging.levels import LogLevel


@dataclass(slots=True)
class LoggerConfig:
    """Mutable diagnostics configuration shared by child loggers."""

    level: LogLevel = LogLevel.NORMAL
    color: bool = True
    enabled_categories: frozenset[str] | None = None
    show_time: bool = True
    deterministic: bool = False
    capture_stack: bool = False

    @classmethod
    def create(
        cls,
        *,
        level: LogLevel = LogLevel.NORMAL,
        color: bool = True,
        categories: set[CategoryInput] | frozenset[CategoryInput] | None = None,
        show_time: bool = True,
        deterministic: bool = False,
        capture_stack: bool = False,
    ) -> LoggerConfig:
        """Create a config while normalizing categories once."""
        return cls(
            level=level,
            color=color,
            enabled_categories=normalize_categories(categories) if categories is not None else None,
            show_time=show_time,
            deterministic=deterministic,
            capture_stack=capture_stack,
        )
