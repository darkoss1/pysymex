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

"""Structural protocols used by exception analyzer checks."""

from __future__ import annotations

from typing import Protocol

import z3


class HasLengthProtocol(Protocol):
    """Structural requirement for modeled containers exposing ``length``."""

    length: object


class ContainsKeyProtocol(Protocol):
    """Structural requirement for modeled key-membership queries."""

    def contains_key(self, key: object) -> object:
        """Return modeled membership evidence for ``key``."""
        ...


class HasAttributeProtocol(Protocol):
    """Structural requirement for modeled attribute-membership queries."""

    def has_attribute(self, attr: str) -> object:
        """Return modeled membership evidence for attribute ``attr``."""
        ...


class CouldBeFalsyProtocol(Protocol):
    """Structural requirement for symbolic falsiness conditions."""

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the condition under which this value is falsy."""
        ...


__all__ = [
    "ContainsKeyProtocol",
    "CouldBeFalsyProtocol",
    "HasAttributeProtocol",
    "HasLengthProtocol",
]
