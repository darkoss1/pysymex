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


class StaticIndexErrorDetector(StaticDetector):
    """
    Enhanced detector for IndexError.
    Considers:
    - List/tuple bounds from type info
    - Safe iteration patterns (enumerate, zip, range)
    - Prior length checks
    - Negative indexing (which is often valid)
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.INDEX_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.instruction.opname == "BINARY_SUBSCR"

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
        container_info = self._get_container_info(ctx)
        if container_info is None:
            return None
        container_var, container_type, index_var, index_value = container_info

        if container_var and container_var in {
            "list",
            "dict",
            "tuple",
            "set",
            "frozenset",
            "type",
            "bytes",
            "bytearray",
            "memoryview",
            "range",
            "slice",
            "property",
            "classmethod",
            "staticmethod",
            "super",
            "object",
            "str",
            "int",
            "float",
            "bool",
            "complex",
            "Optional",
            "Union",
            "Callable",
            "Literal",
            "Annotated",
            "ClassVar",
            "Final",
            "Type",
            "Generic",
            "Protocol",
            "ParamSpec",
            "TypeVar",
            "Sequence",
            "Mapping",
            "Iterable",
            "Iterator",
            "Any",
        }:
            return None
        if container_type.kind not in {
            TypeKind.LIST,
            TypeKind.TUPLE,
            TypeKind.STR,
            TypeKind.BYTES,
            TypeKind.SEQUENCE,
            TypeKind.UNKNOWN,
        }:
            return None
        if ctx.can_pattern_suppress("IndexError"):
            return None
        if self._in_safe_iteration(ctx, container_var, index_var):
            return None
        if isinstance(index_value, int) and container_type.length is not None:
            if 0 <= index_value < container_type.length or (
                index_value < 0 and abs(index_value) <= container_type.length
            ):
                return None
        if self._has_bounds_check(ctx):
            return None
        if ctx.is_in_try_block("IndexError"):
            issue = self.create_issue(
                ctx,
                message=f"Potential IndexError accessing `{container_var}`",
                confidence=0.3,
            )
            return self.suppress_issue(
                issue,
                caught_by_handler_reason(ctx.type_env),
            )
        if self._is_safe_access_pattern(ctx, container_var, index_var, index_value):
            return None
        if index_value is not None:
            message = f"Potential IndexError: index {index_value} may be out of bounds for `{container_var}`"
        else:
            message = (
                f"Potential IndexError: `{index_var}` may be out of bounds for `{container_var}`"
            )
        return self.create_issue(
            ctx,
            message=message,
            confidence=0.5,
            explanation="List/tuple index may be out of bounds at runtime.",
            fix_suggestion="Check `if index < len(collection):` or use try/except.",
        )

    def _get_container_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType, str | None, object | None] | None:
        """Get information about container and index."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 2:
            return None
        container_var = None
        container_type = PyType.unknown()
        index_var = None
        index_value = None
        prev = instructions[idx - 1]
        if prev.opname == "LOAD_CONST":
            index_value = prev.argval
        elif prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            index_var = prev.argval
        for i in range(idx - 2, max(0, idx - 10), -1):
            instr = instructions[i]
            if instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                container_var = instr.argval
                container_type = ctx.get_type(container_var)
                break

        if container_var is None:
            return None
        return (container_var, container_type, index_var, index_value)

    def _in_safe_iteration(
        self,
        ctx: DetectionContext,
        container: str,
        index_var: str | None,
    ) -> bool:
        """Check if we're in a safe iteration pattern."""
        if not index_var:
            return False
        if ctx.pattern_info is None:
            return False
        patterns = ctx.pattern_info.patterns
        for pattern in patterns:
            if pattern.kind in {
                PatternKind.ENUMERATE_ITER,
                PatternKind.RANGE_ITER,
                PatternKind.ZIP_ITER,
            }:
                return True
        return False

    def _has_bounds_check(
        self,
        ctx: DetectionContext,
    ) -> bool:
        """Check for prior bounds checking."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None:
            return False
        for i in range(idx - 1, max(0, idx - 15), -1):
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
            if instr.opname == "COMPARE_OP":
                return True
        return False

    def _is_safe_access_pattern(
        self,
        ctx: DetectionContext,
        container: str,
        index_var: str | None,
        index_value: object | None,
    ) -> bool:
        """Check for common safe access patterns."""
        if index_value == 0 or index_value == -1:
            container_type = ctx.get_type(container)
            if container_type.length is not None and container_type.length > 0:
                return True
        return False
