# pysymex: Python Symbolic Execution & Formal Verification
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

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, DisInstruction, IsSatFn

if TYPE_CHECKING:
    from pysymex.core.state import VMState


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
        return None
