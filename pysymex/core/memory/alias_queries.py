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

"""Structured alias-query evidence shared by core memory owners."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class AliasQueryStatus(Enum):
    """Truth status for a queried alias predicate."""

    ESTABLISHED = auto()
    REFUTED = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class AliasQueryResult:
    """Structured alias-query evidence without collapsing solver UNKNOWN."""

    status: AliasQueryStatus
    reason: str | None = None

    @property
    def is_established(self) -> bool:
        """Return true only when the queried alias predicate is established."""
        return self.status is AliasQueryStatus.ESTABLISHED

    @property
    def is_unknown(self) -> bool:
        """Return true when solver or model uncertainty prevented a definite answer."""
        return self.status is AliasQueryStatus.UNKNOWN

    @staticmethod
    def established() -> AliasQueryResult:
        """Create an established alias-query result."""
        return AliasQueryResult(AliasQueryStatus.ESTABLISHED)

    @staticmethod
    def refuted(reason: str | None = None) -> AliasQueryResult:
        """Create a refuted alias-query result."""
        return AliasQueryResult(AliasQueryStatus.REFUTED, reason)

    @staticmethod
    def unknown(reason: str) -> AliasQueryResult:
        """Create an inconclusive alias-query result."""
        return AliasQueryResult(AliasQueryStatus.UNKNOWN, reason)
