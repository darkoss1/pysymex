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
import z3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types.scalars import (
    SymbolicList,
    SymbolicValue,
)
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn


class EnhancedIndexErrorDetector(Detector):
    """
    Enhanced detector for out-of-bounds array/list access.
    Improvements over base:
    - Works with symbolic integer indexes
    - Tracks list length constraints
    - Handles negative indexing properly
    - Detects when index could exceed any reasonable bound
    - Skips likely dict access patterns to reduce false positives
    """

    name = "enhanced-index-error"
    description = "Enhanced out-of-bounds index detection"
    issue_kind = IssueKind.INDEX_ERROR
    relevant_opcodes = frozenset({"BINARY_SUBSCR"})
    MAX_REASONABLE_SIZE = 10000
    DICT_KEY_SUFFIXES = {
        "_id",
        "id",
        "key",
        "name",
        "feature",
        "tier",
        "type",
        "kind",
        "code",
        "mode",
        "command",
    }
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
    }
    SKIP_INDEX_PATTERNS = (
        "depth",
        "level",
        "count",
        "i",
        "j",
        "k",
        "n",
        "idx",
        "pos",
        "offset",
        "size",
        "length",
        "width",
        "height",
        "x",
        "y",
        "z",
    )
    INSTANCE_CONTAINER_PATTERNS = (
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
        "frame_copy",
        "closure_parent",
        "states",
    )

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname != "BINARY_SUBSCR":
            return None
        if len(state.stack) < 2:
            return None
        index = state.stack[-1]
        container = state.stack[-2]

        if is_type_subscription(container):
            return None
        if isinstance(container, SymbolicList):
            return self._check_symbolic_list(state, container, index)
        if isinstance(index, SymbolicValue):
            if self._is_likely_dict_access(container, index):
                return None
            return self._check_unbounded_index(state, index)
        return None

    def _is_likely_dict_access(self, container: object, index: object) -> bool:
        """Check if this subscript is likely dict[key] rather than list[index]."""
        container_name = getattr(container, "name", "") or ""
        index_name = getattr(index, "name", "") or ""
        container_looks_like_dict = any(
            pattern in container_name.lower() for pattern in self.DICT_CONTAINER_PATTERNS
        )
        index_looks_like_key = any(
            index_name.lower().endswith(suffix) or suffix in index_name.lower()
            for suffix in self.DICT_KEY_SUFFIXES
        )
        container_is_instance_attr = any(
            pattern in container_name for pattern in self.INSTANCE_CONTAINER_PATTERNS
        )
        index_is_common_var = any(
            index_name == pattern or index_name.endswith(f"_{pattern}")
            for pattern in self.SKIP_INDEX_PATTERNS
        )
        return (
            container_looks_like_dict
            or index_looks_like_key
            or container_is_instance_attr
            or index_is_common_var
        )

    def _check_symbolic_list(
        self, state: VMState, container: SymbolicList, index: object
    ) -> Issue | None:
        """Check symbolic list."""
        if isinstance(index, SymbolicValue):
            oob_constraint = [
                *state.path_constraints,
                z3.Or(
                    index.z3_int >= container.z3_len,
                    index.z3_int < -container.z3_len,
                ),
            ]
            if is_satisfiable(oob_constraint):
                return Issue(
                    kind=IssueKind.INDEX_ERROR,
                    message=f"Index {index.name} may be out of bounds for {container.name}",
                    constraints=oob_constraint,
                    model=get_model(oob_constraint),
                    pc=state.pc,
                )
        elif isinstance(index, (int, float)):
            try:
                idx_val = int(index)
                oob_constraint = [
                    *state.path_constraints,
                    z3.Or(
                        idx_val >= container.z3_len,
                        idx_val < -container.z3_len,
                    ),
                ]
                if is_satisfiable(oob_constraint):
                    return Issue(
                        kind=IssueKind.INDEX_ERROR,
                        message=f"Index {idx_val} may be out of bounds for {container.name}",
                        constraints=oob_constraint,
                        model=get_model(oob_constraint),
                        pc=state.pc,
                    )
            except (ValueError, TypeError):
                pass
        return None

    def _check_unbounded_index(self, state: VMState, index: SymbolicValue) -> Issue | None:
        """Check unbounded index."""
        large_constraint = [
            *state.path_constraints,
            index.is_int,
            index.z3_int >= self.MAX_REASONABLE_SIZE,
        ]
        if is_satisfiable(large_constraint):
            return Issue(
                kind=IssueKind.INDEX_ERROR,
                message=f"Index {index.name} could be unreasonably large (>= {self.MAX_REASONABLE_SIZE})",
                constraints=large_constraint,
                model=get_model(large_constraint),
                pc=state.pc,
                confidence=0.8,
            )
        return None
