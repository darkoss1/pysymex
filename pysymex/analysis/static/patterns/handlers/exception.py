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

"""Pattern handler for try/except blocks that guard operations."""

from __future__ import annotations

import dis
from collections.abc import Sequence

from pysymex.core.bytecode import get_starts_line
from pysymex.typing import to_string_set
from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import TypeEnvironment

_safe_line = get_starts_line


class TryExceptHandler(PatternHandler):
    """Handles try/except patterns."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.TRY_EXCEPT_PATTERN}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match try/except blocks."""
        _ = env
        if start_idx >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"SETUP_FINALLY", "PUSH_EXC_INFO"}:
            return None
        end_pc = instr.offset
        caught_exceptions: set[str] = set()
        for i in range(start_idx + 1, min(start_idx + 50, len(instructions))):
            check_instr = instructions[i]
            end_pc = check_instr.offset
            if check_instr.opname == "CHECK_EXC_MATCH" and i > 0:
                prev = instructions[i - 1]
                if prev.opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
                    caught_exceptions.add(str(prev.argval))
            if check_instr.opname in {"POP_EXCEPT", "CLEANUP_THROW"}:
                break
        return PatternMatch(
            kind=PatternKind.TRY_EXCEPT_PATTERN,
            confidence=0.95,
            start_pc=instr.offset,
            end_pc=end_pc,
            line=_safe_line(instr),
            variables={"caught_exceptions": caught_exceptions},
            guarantees=["exceptions_handled"],
        )

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        caught = to_string_set(match.variables.get("caught_exceptions", set[str]()))
        if error_type in caught:
            return False
        if "Exception" in caught or "BaseException" in caught:
            return False
        return True


__all__ = ["TryExceptHandler"]
