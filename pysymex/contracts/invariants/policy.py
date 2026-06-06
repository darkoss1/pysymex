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

"""Class invariant execution-point policy.

This module owns the stable policy that decides which method lifecycle points
produce class-invariant obligations. It does not inspect VM state or query the
solver.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class InvariantCheckPoint(Enum):
    """Method lifecycle point for a class invariant obligation."""

    ENTRY = "entry"
    EXIT = "exit"


def _default_dunder_allowlist() -> frozenset[str]:
    """Return the dunder methods that participate in invariant checking."""
    return frozenset({"__init__"})


@dataclass(frozen=True, slots=True)
class InvariantPolicy:
    """Policy for generating class-invariant entry and exit obligations.

    Public methods require invariants at entry and normal exit. Constructors
    require invariants only at normal exit because the receiver may be partially
    initialized at entry. Private and non-allowlisted dunder methods are off for
    this initial runtime slice.
    """

    check_private_methods: bool = False
    dunder_allowlist: frozenset[str] = field(default_factory=_default_dunder_allowlist)

    def checkpoints_for_method(self, method_name: str) -> tuple[InvariantCheckPoint, ...]:
        """Return enabled invariant checkpoints for one method name."""
        if method_name == "__init__":
            return (InvariantCheckPoint.EXIT,)
        if _is_dunder_name(method_name):
            if method_name not in self.dunder_allowlist:
                return ()
            return (InvariantCheckPoint.ENTRY, InvariantCheckPoint.EXIT)
        if method_name.startswith("_") and not self.check_private_methods:
            return ()
        return (InvariantCheckPoint.ENTRY, InvariantCheckPoint.EXIT)


def _is_dunder_name(method_name: str) -> bool:
    """Return whether *method_name* has Python dunder spelling."""
    return len(method_name) > 4 and method_name.startswith("__") and method_name.endswith("__")


DEFAULT_INVARIANT_POLICY = InvariantPolicy()


__all__ = ["DEFAULT_INVARIANT_POLICY", "InvariantCheckPoint", "InvariantPolicy"]
