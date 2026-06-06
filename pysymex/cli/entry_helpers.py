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

"""CLI entrypoint normalization helpers."""

from __future__ import annotations

from typing import Protocol, TypeGuard, cast, runtime_checkable


@runtime_checkable
class IssueLike(Protocol):
    """Protocol representing an issue-like object that can be serialized."""

    def to_dict(self) -> dict[str, object]:
        """Serialize the issue details to a dictionary.

        Returns:
            dict[str, object]: A dictionary containing serializable issue attributes.
        """
        ...


@runtime_checkable
class SymbolicResultLike(Protocol):
    """Protocol representing a symbolic execution result containing findings.

    Attributes:
        issues (list[IssueLike]): A list of issue-like findings discovered during execution.
    """

    issues: list[IssueLike]

    def to_dict(self) -> dict[str, object]:
        """Serialize the symbolic execution result to a dictionary.

        Returns:
            dict[str, object]: A dictionary containing serializable execution result attributes.
        """
        ...


def is_issue_like_list(value: object) -> TypeGuard[list[IssueLike]]:
    """Return whether value is a list of issue-like objects."""
    if not isinstance(value, list):
        return False
    issue_items = cast("list[object]", value)
    return all(isinstance(item, IssueLike) for item in issue_items)


_SUBCOMMANDS = frozenset(
    {
        "scan",
        "analyze",
        "verify",
        "benchmark",
        "check",
    }
)


def normalize_argv(argv: list[str]) -> list[str]:
    """Return argv unchanged; callers must use explicit subcommands."""
    return argv


__all__ = ["IssueLike", "SymbolicResultLike", "is_issue_like_list", "normalize_argv"]
