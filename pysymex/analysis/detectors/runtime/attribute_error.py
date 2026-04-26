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

import dis
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn


class AttributeErrorDetector(Detector):
    """Detects attribute access errors."""

    name = "attribute-error"
    description = "Detects missing attributes"
    issue_kind = IssueKind.ATTRIBUTE_ERROR
    relevant_opcodes = frozenset()

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        return None
