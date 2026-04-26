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

import logging

logger = logging.getLogger(__name__)


from pysymex.analysis.detectors.types import DetectionContext, Issue, IssueKind, StaticDetector


class StaticAssertionErrorDetector(StaticDetector):
    """
    Enhanced detector for assertion failures.
    Checks if assert conditions are always false.
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.ASSERTION_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.instruction.opname == "LOAD_ASSERTION_ERROR"

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
        condition_info = self._get_assertion_condition(ctx)
        if condition_info:
            condition_text, is_always_false = condition_info
            if is_always_false:
                return self.create_issue(
                    ctx,
                    message=f"Assertion always fails: `{condition_text}`",
                    confidence=0.95,
                )
        return None

    def _get_assertion_condition(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, bool] | None:
        """Get the assertion condition and check if always false."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None:
            return None
        for i in range(idx - 1, max(0, idx - 10), -1):
            instr = instructions[i]
            if instr.opname == "LOAD_CONST":
                if instr.argval is False:
                    return ("False", True)
            if instr.opname == "POP_JUMP_IF_TRUE":
                break
        return None
