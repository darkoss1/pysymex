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

"""Detect ``ValueError`` exceptions from conversions, empty iterables, and shifts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.runtime.value.calls import call_value_error_issue
from pysymex._internal.analysis.detectors.runtime.value.markers import potential_marker_issue
from pysymex._internal.analysis.detectors.runtime.value.shifts import check_negative_shift
from pysymex._internal.core.bytecode import DIRECT_CALL_OPCODES
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
    from pysymex._internal.core.state.record import VMState


class ValueErrorDetector(Detector):
    """Detect ``ValueError`` exceptions from type conversions and sequence operations.

    Bug class:
        ``ValueError`` from: ``int()``/``float()``/``bytes.fromhex()`` called
        with an invalid literal, ``min()``/``max()`` on an empty sequence, or
        left/right bit-shift with a negative shift count.

    Evidence:
        Satisfiable path constraints when the bad-value condition holds.

    Issue kind:
        ``IssueKind.VALUE_ERROR``.

    Known false-positive conditions:
        - Invalid-literal checks are purely syntactic; symbolic strings that
          happen to be invalid are detected but concrete-valid strings are not.
        - Empty-sequence check delegates to :func:`is_known_empty_iterable`;
          dynamic/unknown-length iterables are not checked.
    """

    name = "value-error"
    description = "Detects potential ValueError exceptions"
    issue_kind = IssueKind.VALUE_ERROR
    relevant_opcodes = frozenset(("BINARY_OP", *DIRECT_CALL_OPCODES))

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Inspect *instruction* for a potential ``ValueError``."""
        return _check_value_error(state, instruction, _solver_check)


def _check_value_error(
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
) -> Issue | None:
    """Inspect an instruction for a potential ``ValueError``."""
    if instruction.opname == "BINARY_OP":
        return check_negative_shift(state, instruction, solver_check)
    if instruction.opname not in DIRECT_CALL_OPCODES:
        return None

    marker_issue = potential_marker_issue(state, solver_check)
    if marker_issue is not None:
        return marker_issue
    return call_value_error_issue(state, instruction, solver_check)
