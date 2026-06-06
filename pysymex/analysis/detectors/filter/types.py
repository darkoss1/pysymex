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

"""Shared types for the issue-filter pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, TypeVar


class IssueLike(Protocol):
    """Protocol defining structural fields of a scan-issue-like object."""

    @property
    def kind(self) -> object:
        """The kind or category of the issue."""
        ...

    @property
    def message(self) -> str:
        """The user-facing message describing the issue."""
        ...

    @property
    def function_name(self) -> str | None:
        """The name of the function where the issue was detected, if available."""
        ...

    @property
    def model(self) -> object | None:
        """The Z3 solver model providing counterexample evidence, if any."""
        ...

    @property
    def line_number(self) -> int | None:
        """The source code line number where the issue was detected, if available."""
        ...

    @property
    def pc(self) -> int:
        """The VM bytecode program counter offset where the issue was detected."""
        ...


class ModelDeclLike(Protocol):
    """Small protocol for Z3 model declarations."""

    def name(self) -> str:
        """Return the name of the model declaration."""
        ...


TIssue = TypeVar("TIssue", bound=IssueLike)


class Confidence(Enum):
    """Confidence level for a detected issue."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssertionContext(Enum):
    """Context for assertion-related issues."""

    SECURITY_GUARD = "security_guard"
    VALIDATION = "validation"
    INVARIANT = "invariant"
    ACCIDENTAL = "accidental"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FilterResult:
    """Result of applying filters to an issue."""

    should_filter: bool
    reason: str | None = None
    confidence: Confidence = Confidence.HIGH
    context: AssertionContext = AssertionContext.UNKNOWN


__all__ = [
    "AssertionContext",
    "Confidence",
    "FilterResult",
    "IssueLike",
    "ModelDeclLike",
    "TIssue",
]
