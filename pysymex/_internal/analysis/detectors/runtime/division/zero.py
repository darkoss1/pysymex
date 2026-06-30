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

"""Division by zero and modulo zero error detector module.

This module owns the division runtime detector. Zero-divisor feasibility evidence lives in
:mod:`pysymex._internal.analysis.detectors.runtime.division.evidence`; opcode and call-target
classification lives in :mod:`pysymex._internal.analysis.detectors.runtime.division.targets`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.runtime.division.targets import (
    BINARY_OP_DIVISION_ARGS as _BINARY_OP_DIVISION_ARGS,
)
from pysymex._internal.analysis.detectors.runtime.division.targets import (
    BINARY_OP_DIVISION_SYMBOLS as _BINARY_OP_DIVISION_SYMBOLS,
)
from pysymex._internal.analysis.detectors.runtime.division.targets import (
    DIVISION_CALL_SUFFIXES as _DIVISION_CALL_SUFFIXES,
)
from pysymex._internal.analysis.detectors.runtime.division.targets import (
    DIVISION_OPS as _DIVISION_OPS,
)
from pysymex._internal.analysis.detectors.runtime.division.targets import (
    DIVISION_RELEVANT_OPCODES as _DIVISION_RELEVANT_OPCODES,
)
from pysymex._internal.analysis.detectors.runtime.division.targets import (
    check_division_by_zero,
)
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
    from pysymex._internal.core.state.record import VMState


class DivisionByZeroDetector(Detector):
    """Detect division-by-zero and modulo-by-zero on feasible paths.

    Bug class:
        ``ZeroDivisionError`` from ``/``, ``//``, ``%``, and their
        in-place variants. Also catches dunder calls (``__truediv__``,
        ``__floordiv__``, ``__mod__``).

    Evidence:
        Concrete divisor of ``0``, or a satisfiable path constraint
        with the divisor constrained to zero.

    Issue kinds:
        ``IssueKind.DIVISION_BY_ZERO``, ``IssueKind.MODULO_BY_ZERO``.

    Known false-positive suppression:
        Skipped when both operands have overloaded arithmetic or when
        the dividend is a string (``%``-formatting).
    """

    name = "division-by-zero"
    description = "Detects division by zero"
    issue_kind = IssueKind.DIVISION_BY_ZERO
    relevant_opcodes = _DIVISION_RELEVANT_OPCODES
    DIVISION_OPS = _DIVISION_OPS
    DIVISION_CALL_SUFFIXES = _DIVISION_CALL_SUFFIXES
    BINARY_OP_DIVISION_SYMBOLS = _BINARY_OP_DIVISION_SYMBOLS
    BINARY_OP_DIVISION_ARGS = _BINARY_OP_DIVISION_ARGS

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Inspect one division/modulo instruction for feasible zero-divisor evidence."""
        return check_division_by_zero(state, instruction, _solver_check)
