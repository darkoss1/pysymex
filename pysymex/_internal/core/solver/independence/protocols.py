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

"""Protocols and guards for solver independence expressions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, TypeGuard

if TYPE_CHECKING:
    import z3


class Z3Convertible(Protocol):
    """Protocol for symbolic objects that can expose a Z3 expression."""

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 expression represented by this object."""
        msg = "Protocol method Z3Convertible.to_z3() is not callable at runtime"
        raise TypeError(msg)


def has_to_z3(value: object) -> TypeGuard[Z3Convertible]:
    """Return True when a value has a callable to_z3 method."""
    return hasattr(value, "to_z3") and callable(getattr(value, "to_z3", None))
