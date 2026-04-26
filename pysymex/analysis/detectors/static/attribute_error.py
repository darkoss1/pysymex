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


class StaticAttributeErrorDetector(StaticDetector):
    """
    Enhanced detector for AttributeError.
    Considers:
    - None checks before attribute access
    - hasattr patterns
    - Optional chaining (x and x.attr)
    - Type narrowing from isinstance
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.ATTRIBUTE_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.instruction.opname == "LOAD_ATTR"

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
        instr = ctx.instruction
        attr_name = instr.argval
        obj_info = self._get_object_info(ctx)
        if obj_info is None:
            return None
        obj_var, obj_type = obj_info
        if obj_type.kind == TypeKind.NONE:
            return self.create_issue(
                ctx,
                message=f"AttributeError: 'NoneType' object has no attribute '{attr_name}'",
                confidence=0.98,
            )
        if obj_type.is_optional():
            if self._has_none_check(ctx, obj_var):
                return None
            return self.create_issue(
                ctx,
                message=f"Potential AttributeError: `{obj_var}` may be None when accessing '.{attr_name}'",
                confidence=0.7,
                fix_suggestion=f"Add `if {obj_var} is not None:` check before accessing attribute.",
            )
        if ctx.can_pattern_suppress("AttributeError"):
            return None
        if self._has_hasattr_check(ctx, obj_var, attr_name):
            return None
        if self._in_optional_chain(ctx, obj_var):
            return None
        if ctx.is_in_try_block("AttributeError"):
            issue = self.create_issue(
                ctx,
                message=f"Potential AttributeError on `{obj_var}.{attr_name}`",
                confidence=0.3,
            )
            return self.suppress_issue(issue, "Caught by exception handler")
        return None

    def _get_object_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType] | None:
        """Get info about object being accessed."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 1:
            return None
        prev = instructions[idx - 1]
        if prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return (prev.argval, ctx.get_type(prev.argval))
        return None

    def _has_none_check(self, ctx: DetectionContext, var_name: str) -> bool:
        """Check for prior None check on variable."""
        if ctx.pattern_info is None:
            return False
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.NONE_CHECK:
                if pattern.variables.get("var_name") == var_name:
                    if pattern.variables.get("is_not_none", False):
                        return True
        return False

    def _has_hasattr_check(
        self,
        ctx: DetectionContext,
        var_name: str,
        attr_name: str,
    ) -> bool:
        """Check for prior hasattr check."""
        if ctx.pattern_info is None:
            return False
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.HASATTR_CHECK:
                return True
        return False

    def _in_optional_chain(self, ctx: DetectionContext, var_name: str) -> bool:
        """Check if in an optional chain pattern."""
        if ctx.pattern_info is None:
            return False
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.OPTIONAL_CHAIN:
                if pattern.variables.get("var_name") == var_name:
                    return True
        return False
