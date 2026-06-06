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

"""Diagnostic categories used by the symbolic execution engine."""

from __future__ import annotations

from enum import StrEnum


class LogCategory(StrEnum):
    """Structured event categories for pysymex diagnostics."""

    GENERAL = "general"
    OPCODE = "opcode"
    SOLVER = "solver"
    PATH = "path"
    STATE = "state"
    DETECTOR = "detector"
    MODEL = "model"
    SANDBOX = "sandbox"
    BYTECODE = "bytecode"
    CLI = "cli"
    PERFORMANCE = "performance"
    SECURITY = "security"
    IO = "io"
    CONFIG = "config"
    PYTHON = "python"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"


CategoryInput = LogCategory | str


def normalize_category(category: CategoryInput) -> str:
    """Return the stable lowercase category value."""
    if isinstance(category, LogCategory):
        return category.value
    return category.lower()


def normalize_categories(
    categories: set[CategoryInput] | frozenset[CategoryInput],
) -> frozenset[str]:
    """Normalize a set of categories once at configuration time."""
    return frozenset(normalize_category(category) for category in categories)


__all__ = ["CategoryInput", "LogCategory", "normalize_categories", "normalize_category"]
