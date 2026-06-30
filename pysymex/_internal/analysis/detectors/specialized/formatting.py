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

"""Format String vulnerability detector module.

Detects format string injections by checking if unconstrained inputs (havoc values)
are passed to string formatting operations.

Bug Class Detected:
    Format String Vulnerability.

Required Evidence:
    Havoc or unconstrained input passed into string formatting opcodes.

Issue Kinds:
    IssueKind.INVALID_ARGUMENT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.havoc import is_havoc

if TYPE_CHECKING:
    import dis
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState


class FormatStringDetector(Detector):
    """Detects format string vulnerabilities."""

    name = "format-string"
    description = "Detects format string vulnerabilities"
    issue_kind = IssueKind.INVALID_ARGUMENT
    relevant_opcodes = frozenset(
        (
            "BUILD_STRING",
            "CONVERT_VALUE",
            "FORMAT_SIMPLE",
            "FORMAT_VALUE",
            "FORMAT_WITH_SPEC",
        ),
    )

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for format string issues."""
        _ = is_satisfiable_fn
        if instruction.opname in self.relevant_opcodes:
            if any(is_havoc(value) for value in _format_operands(state.stack, instruction)):
                return Issue(
                    kind=IssueKind.INVALID_ARGUMENT,
                    message="Potential format string vulnerability: unconstrained input used in string formatting",
                    pc=state.pc,
                    confidence=0.5,
                )
        return None


def _format_operands(stack: Sequence[object], instruction: dis.Instruction) -> tuple[object, ...]:
    """Return stack operands consumed by one formatting-related opcode."""
    if not stack:
        return ()
    if instruction.opname == "FORMAT_WITH_SPEC":
        if len(stack) < 2:
            return ()
        return stack[-2], stack[-1]
    if instruction.opname == "FORMAT_VALUE":
        flags = int(instruction.arg) if instruction.arg is not None else 0
        has_spec = bool(flags & 0x04)
        if has_spec:
            if len(stack) < 2:
                return ()
            return stack[-2], stack[-1]
    if instruction.opname == "BUILD_STRING":
        count = int(instruction.arg or 0)
        if count <= 0 or len(stack) < count:
            return ()
        return tuple(stack[-count:])
    return (stack[-1],)
