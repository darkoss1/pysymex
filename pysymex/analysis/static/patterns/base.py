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

"""Abstract base class for pattern-matching handlers."""

from __future__ import annotations

import dis
from abc import ABC, abstractmethod
from collections.abc import Sequence

from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import TypeEnvironment


class PatternHandler(ABC):
    """Base class for pattern handlers."""

    @abstractmethod
    def pattern_kinds(self) -> set[PatternKind]:
        """Return the kinds of patterns this handler recognizes."""

    @abstractmethod
    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Try to match a pattern starting at the given instruction index."""

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Check if a matched pattern can raise a specific error."""
        return True


__all__ = ["PatternHandler"]
