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

"""Abstract :class:`Detector` base contract for symbolic-execution bug detectors.

All runtime, logical, and static detectors subclass :class:`Detector` and
implement :meth:`Detector.check` to inspect a VM state + instruction.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import (
    DetectorFn,
    DetectorInfo,
    IsSatFn,
    Issue,
)
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState


class Detector(ABC):
    """Abstract base class for symbolic-execution bug detectors.

    Subclasses declare :attr:`name`, :attr:`description`, :attr:`issue_kind`,
    and :attr:`relevant_opcodes`, then implement :meth:`check`.
    """

    name: str = "base"
    description: str = "Base detector"
    issue_kind: IssueKind = IssueKind.UNHANDLED_EXCEPTION

    relevant_opcodes: frozenset[str] = frozenset()

    @abstractmethod
    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Inspect *state* at *instruction* and return an :class:`Issue`, or ``None``."""

    def to_info(self) -> DetectorInfo:
        """Return an immutable :class:`DetectorInfo` for this detector."""
        return DetectorInfo(
            name=self.name,
            description=self.description,
            issue_kind=self.issue_kind,
            relevant_opcodes=self.relevant_opcodes,
        )

    def as_fn(self) -> DetectorFn:
        """Return the ``check`` method as a plain :data:`DetectorFn`."""
        return self.check
