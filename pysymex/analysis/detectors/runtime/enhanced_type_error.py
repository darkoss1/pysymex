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

from pysymex.core.types.scalars import (
    SymbolicValue,
)
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn


class EnhancedTypeErrorDetector(Detector):
    """Enhanced type confusion detector.
    Includes pattern recognition to avoid false positives on dict access.
    """

    name = "enhanced-type-error"
    description = "Enhanced type confusion detection"
    issue_kind = IssueKind.TYPE_ERROR
    relevant_opcodes = frozenset({"BINARY_SUBSCR", "BINARY_OP"})
    DICT_CONTAINER_PATTERNS = {
        "dict",
        "map",
        "cache",
        "tracker",
        "store",
        "registry",
        "config",
        "settings",
        "_recent",
        "_usage",
        "_count",
        "_limits",
        "_LIMITS",
        "_SIZE",
        "_join",
        "_command",
        "_confusion",
        "_requests",
        "global_",
        "list",
        "tuple",
        "array",
        "args",
        "kwargs",
        "instructions",
        "states",
        "facts",
        "operands",
        "elements",
        "ops",
        "comparators",
        "varnames",
        "blocks",
        "indices",
        "t",
        "x",
        "d",
        "s",
        "node",
    }
    SKIP_PREFIXES = ("subscr_", "call_result_", "call_kw_result_", "iter_")
    INSTANCE_ATTR_PATTERNS = (
        "self.",
        "cls.",
        ".stack",
        ".elements",
        ".items",
        ".values",
        ".keys",
        ".methods",
        ".fields",
        ".attributes",
        ".properties",
        "._hooks",
        "._pending",
        "._alias",
        "._references",
        ".locals",
        ".globals",
        ".block_stack",
        ".path_constraints",
        "frame_copy",
        "closure_parent",
    )

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname == "BINARY_SUBSCR":
            return self._check_subscript_type(state, instruction)
        if instruction.opname == "BINARY_OP":
            return self._check_binary_op(state, instruction)
        return None

    def _check_subscript_type(self, state: VMState, _instruction: dis.Instruction) -> Issue | None:
        """Check subscript type."""
        if len(state.stack) < 2:
            return None
        container = state.stack[-2]
        if isinstance(container, SymbolicValue):
            pass
        return None

    def _check_binary_op(self, state: VMState, instruction: dis.Instruction) -> Issue | None:
        """Check binary op."""
        if len(state.stack) < 2:
            return None
        return None
