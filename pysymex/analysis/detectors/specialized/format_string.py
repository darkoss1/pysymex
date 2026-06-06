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
    Havoc or unconstrained input passed into string formatting opcodes (FORMAT_VALUE, BUILD_STRING).

Issue Kinds:
    IssueKind.INVALID_ARGUMENT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.havoc import is_havoc
from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.types import DisInstruction, IsSatFn, Issue, IssueKind

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


class FormatStringDetector(Detector):
    """Detects format string vulnerabilities."""

    name = "format-string"
    description = "Detects format string vulnerabilities"
    issue_kind = IssueKind.INVALID_ARGUMENT
    relevant_opcodes = frozenset({"FORMAT_VALUE", "FORMAT_SIMPLE", "BUILD_STRING"})

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for format string issues."""
        if instruction.opname in self.relevant_opcodes:
            if not state.stack:
                return None
            val = state.stack[-1]
            if is_havoc(val):
                return Issue(
                    kind=IssueKind.INVALID_ARGUMENT,
                    message="Potential format string vulnerability: unconstrained input used in string formatting",
                    pc=state.pc,
                    confidence=0.5,
                )
        return None
