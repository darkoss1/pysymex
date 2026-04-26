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


class StaticKeyErrorDetector(StaticDetector):
    """
    Enhanced detector for KeyError.
    Considers:
    - defaultdict (never raises KeyError)
    - Counter (returns 0 for missing)
    - dict.get(), dict.setdefault() patterns
    - Prior key existence checks
    - Iteration patterns (dict.items(), etc.)
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.KEY_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.instruction.opname == "BINARY_SUBSCR"

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
        container_info = self._get_container_info(ctx)
        if container_info is None:
            return None
        container_var, container_type, key_var, key_value = container_info
        if container_type.kind not in {
            TypeKind.DICT,
            TypeKind.DEFAULTDICT,
            TypeKind.COUNTER,
            TypeKind.ORDERED_DICT,
            TypeKind.CHAIN_MAP,
            TypeKind.UNKNOWN,
        }:
            return None
        if container_type.kind == TypeKind.DEFAULTDICT:
            return None
        if container_type.kind == TypeKind.COUNTER:
            return None
        if ctx.can_pattern_suppress("KeyError"):
            return None
        if self._key_known_to_exist(ctx, container_var, key_var, key_value):
            return None
        if ctx.is_in_try_block("KeyError"):
            issue = self.create_issue(
                ctx,
                message=f"Potential KeyError accessing `{container_var}`",
                confidence=0.3,
            )
            return self.suppress_issue(
                issue,
                caught_by_handler_reason(ctx.type_env),
            )
        if self._has_key_check(ctx, container_var, key_var, key_value):
            return None
        if key_value is not None:
            message = f"Potential KeyError: key `{key_value}` may not exist in `{container_var}`"
        elif key_var:
            message = f"Potential KeyError: `{key_var}` may not be a key in `{container_var}`"
        else:
            message = f"Potential KeyError accessing `{container_var}`"
        return self.create_issue(
            ctx,
            message=message,
            confidence=0.6,
            explanation="Dictionary access may raise KeyError if key doesn't exist.",
            fix_suggestion="Use `dict.get(key, default)` or check `if key in dict:` first.",
        )

    def _get_container_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType, str | None, object | None] | None:
        """Get information about the container and key."""
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
        key_var = None
        key_value = None
        prev = instructions[idx - 1]
        if prev.opname == "LOAD_CONST":
            key_value = prev.argval
        elif prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            key_var = prev.argval
        for i in range(idx - 2, max(0, idx - 10), -1):
            instr = instructions[i]
            if instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                container_var = instr.argval
                container_type = ctx.get_type(container_var)
                break
        if container_var is None:
            return None
        return (container_var, container_type, key_var, key_value)

    def _key_known_to_exist(
        self,
        ctx: DetectionContext,
        container: str,
        key_var: str | None,
        key_value: object | None,
    ) -> bool:
        """Check if key is known to exist in the container."""
        container_type = ctx.get_type(container)
        if container_type.known_keys and key_value is not None:
            if key_value in container_type.known_keys:
                return True
        return False

    def _has_key_check(
        self,
        ctx: DetectionContext,
        container_var: str,
        key_var: str | None,
        key_value: object | None,
    ) -> bool:
        """Check for prior `if key in dict:` check."""
        if ctx.pattern_info is None:
            return False
        patterns = ctx.pattern_info.matcher.get_patterns_at(ctx.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.KEY_CHECK:
                checked_container = pattern.variables.get("container")
                checked_key = pattern.variables.get("key")
                if checked_container == container_var:
                    if (key_var and checked_key == key_var) or (
                        key_value is not None and checked_key == key_value
                    ):
                        return True
        return False
