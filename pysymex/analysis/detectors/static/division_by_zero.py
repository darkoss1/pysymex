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


from pysymex.analysis.patterns import PatternKind
from pysymex.analysis.type_inference import PyType, TypeKind

from pysymex.analysis.detectors.types import DetectionContext, Issue, IssueKind, StaticDetector
from .helpers import caught_by_handler_reason


class StaticDivisionByZeroDetector(StaticDetector):
    """
    Enhanced detector for division by zero errors.
    Considers:
    - Constant divisors
    - Type constraints (non-zero proven by type)
    - Flow analysis (guards like `if x != 0`)
    - Loop context (divisor proven positive by iteration)
    """

    DIVISION_OPS = {"BINARY_OP"}
    DIVISION_ARGREPS = {"/", "//", "%"}

    def issue_kind(self) -> IssueKind:
        return IssueKind.DIVISION_BY_ZERO

    def should_check(self, ctx: DetectionContext) -> bool:
        """Should check."""
        instr = ctx.instruction
        if instr.opname == "BINARY_OP":
            return instr.argrepr in self.DIVISION_ARGREPS
        return False

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
        divisor_info = self._get_divisor_info(ctx)
        if divisor_info is None:
            return None
        divisor_value, divisor_var, divisor_type = divisor_info
        if divisor_type and not (
            divisor_type.is_numeric() or divisor_type.kind in (TypeKind.ANY, TypeKind.UNKNOWN)
        ):
            return None

        if divisor_value is not None:
            if not isinstance(divisor_value, (int, float, complex)):
                return None
            if divisor_value == 0:
                return self.create_issue(
                    ctx,
                    message="Division by zero: divisor is constant 0",
                    confidence=1.0,
                    explanation="The divisor is a literal 0, which will always cause a ZeroDivisionError.",
                    fix_suggestion="Check the divisor before division or use a non-zero value.",
                )
            else:
                return None
        if divisor_type and self._type_guarantees_nonzero(divisor_type):
            return None
        if divisor_var and self._is_guarded_by_zero_check(ctx, divisor_var):
            return None
        if ctx.is_in_try_block("ZeroDivisionError") or ctx.is_in_try_block("ArithmeticError"):
            issue = self.create_issue(
                ctx,
                message="Potential division by zero",
                confidence=0.4,
            )
            return self.suppress_issue(
                issue,
                caught_by_handler_reason(ctx.type_env),
            )
        if divisor_var and self._has_prior_assertion(ctx):
            return None
        if divisor_var:
            message = f"Potential division by zero: `{divisor_var}` may be zero"
        else:
            message = "Potential division by zero"
        return self.create_issue(
            ctx,
            message=message,
            confidence=0.7,
            explanation="The divisor could be zero at runtime, causing a ZeroDivisionError.",
            fix_suggestion="Add a check: `if divisor != 0:` before the division.",
        )

    def _get_divisor_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[object | None, str | None, PyType | None] | None:
        """Get information about the divisor."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 1:
            return None
        prev_instr = instructions[idx - 1]
        if prev_instr.opname == "LOAD_CONST":
            return (prev_instr.argval, None, None)
        if prev_instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            var_name = prev_instr.argval
            var_type = ctx.get_type(var_name)
            return (None, var_name, var_type)
        return (None, None, None)

    def _type_guarantees_nonzero(self, var_type: PyType) -> bool:
        """Check if type guarantees non-zero value."""
        if var_type.kind == TypeKind.BOOL:
            return False
        for constraint in var_type.value_constraints:
            if "> 0" in str(constraint) or ">= 1" in str(constraint):
                return True
        return False

    def _is_guarded_by_zero_check(
        self,
        ctx: DetectionContext,
        var_name: str,
    ) -> bool:
        """Check if variable is guarded by a zero check."""
        if ctx.pattern_info is None:
            return False
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.TRUTHY_CHECK:
                if pattern.variables.get("var_name") == var_name:
                    return True
        return False

    def _has_prior_assertion(
        self,
        ctx: DetectionContext,
    ) -> bool:
        """Check for prior assertion about the variable."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None:
            return False
        for i in range(idx - 1, max(0, idx - 20), -1):
            instr = instructions[i]
            if instr.opname in {
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
                "JUMP_FORWARD",
                "JUMP_BACKWARD",
                "JUMP_ABSOLUTE",
                "FOR_ITER",
            }:
                break
            if instr.opname == "LOAD_ASSERTION_ERROR":
                return True
        return False
