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

from pysymex.core.types.havoc import is_havoc
from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types import (
    SymbolicList,
    SymbolicString,
    SymbolicTuple,
    SymbolicValue,
)
from pysymex.core.types import SymbolicObject
from pysymex.analysis.detectors.base import (
    Detector,
    Issue,
    IssueKind,
    IsSatFn,
    GetModelFn,
    is_list_of_objects,
    is_tuple_of_objects,
)
from pysymex.analysis.detectors.runtime.division_by_zero import (
    extract_argc,
    resolve_call_target_name,
)

CALL_OPCODES = frozenset({"CALL", "CALL_FUNCTION", "CALL_METHOD"})


def _unwrap_symbolic_sequence(container: object) -> object:
    """Return concrete sequence payloads stored in constant symbolic values."""
    if not isinstance(container, SymbolicValue):
        return container
    value: object = container.value
    if (
        is_list_of_objects(value)
        or is_tuple_of_objects(value)
        or isinstance(value, (SymbolicTuple, str, bytes, bytearray, range))
    ):
        return value
    return container


def pure_check_index_bounds(
    container: object,
    index: object,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn = is_satisfiable,
    get_model_fn: GetModelFn = get_model,
) -> Issue | None:
    """Pure: check if *index* can be out-of-bounds for *container*."""
    if is_type_subscription(container):
        return None
    if not isinstance(index, SymbolicValue):
        return None
    container = _unwrap_symbolic_sequence(container)

    lower_bound: z3.ArithRef
    upper_bound: z3.ArithRef
    container_name: str
    confidence = 1.0

    if isinstance(container, SymbolicList):
        lower_bound = -container.z3_len
        upper_bound = container.z3_len
        container_name = container.name
        if is_havoc(index) or is_havoc(container):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif isinstance(container, SymbolicTuple):
        concrete_len = len(container)
        lower_bound = z3.IntVal(-concrete_len)
        upper_bound = z3.IntVal(concrete_len)
        container_name = container.name
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif isinstance(container, SymbolicString):
        lower_bound = -container.z3_len
        upper_bound = container.z3_len
        container_name = container.name
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif isinstance(container, (str, bytes, bytearray, range)):
        concrete_len = len(container)
        lower_bound = z3.IntVal(-concrete_len)
        upper_bound = z3.IntVal(concrete_len)
        container_name = type(container).__name__
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif is_list_of_objects(container):
        concrete_len = len(container)
        lower_bound = z3.IntVal(-concrete_len)
        upper_bound = z3.IntVal(concrete_len)
        container_name = "list"
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif is_tuple_of_objects(container):
        concrete_len = len(container)
        lower_bound = z3.IntVal(-concrete_len)
        upper_bound = z3.IntVal(concrete_len)
        container_name = "list"
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    else:
        return None

    oob_constraint = [
        *path_constraints,
        index.is_int,
        z3.Or(
            index.z3_int < lower_bound,
            index.z3_int >= upper_bound,
        ),
    ]
    if is_satisfiable_fn(oob_constraint):
        return Issue(
            kind=IssueKind.INDEX_ERROR,
            message=f"Possible index out of bounds: {container_name}[{index.name}]",
            constraints=oob_constraint,
            model=get_model_fn(oob_constraint),
            pc=pc,
            confidence=confidence,
        )
    return None


class IndexErrorDetector(Detector):
    """Detects out-of-bounds array/list access."""

    name = "index-error"
    description = "Detects out-of-bounds indexing"
    issue_kind = IssueKind.INDEX_ERROR
    relevant_opcodes = frozenset(
        {"BINARY_SUBSCR", "DELETE_SUBSCR", "CALL", "CALL_FUNCTION", "CALL_METHOD"}
    )
    MAX_REASONABLE_SIZE = 10000
    TYPE_SUBSCRIPTION_CONTAINERS = frozenset(
        {
            "list",
            "dict",
            "tuple",
            "set",
            "frozenset",
            "type",
            "sequence",
            "mapping",
            "iterable",
            "typing",
        }
    )
    TYPE_SUBSCRIPTION_INDEXES = frozenset(
        {
            "int",
            "float",
            "str",
            "bool",
            "bytes",
            "object",
            "none",
            "nonetype",
            "list",
            "dict",
            "tuple",
            "set",
            "frozenset",
        }
    )
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
        """Check for concrete and symbolic out-of-bounds indexing scenarios."""
        container: object
        index: object
        if instruction.opname in {"BINARY_SUBSCR", "DELETE_SUBSCR"}:
            if len(state.stack) < 2:
                return None
            container = state.stack[-2]
            index = state.stack[-1]
        elif instruction.opname in CALL_OPCODES:
            argc = extract_argc(instruction)
            target_name = resolve_call_target_name(state, argc)
            if target_name is None:
                return None
            if not target_name.lower().endswith(".pop") and target_name.lower() != "pop":
                return None
            if argc < 1 or len(state.stack) < argc + 2:
                return None
            container = state.stack[-(argc + 1)]
            index = state.stack[-argc]
        else:
            return None
        if isinstance(container, SymbolicObject) and container.address != -1:
            mem_obj = state.memory.get(container.address)
            if mem_obj is not None:
                container = mem_obj

        bounds_issue = pure_check_index_bounds(
            container,
            index,
            list(state.path_constraints),
            state.pc,
            is_satisfiable_fn=_solver_check,
        )
        if bounds_issue is not None:
            return bounds_issue

        if not isinstance(index, SymbolicValue):
            return None
        if self._is_type_subscription_pattern(container, index):
            return None
        if self._is_likely_dict_access(container, index):
            return None
        return self._check_unbounded_index(state, index, _solver_check)

    @staticmethod
    def _normalize_symbolic_name(raw_name: str) -> str:
        """Normalize container/index names for type-subscription matching."""
        normalized = raw_name.strip()
        if normalized.startswith("global_"):
            normalized = normalized[7:]
        if normalized.startswith("import_"):
            normalized = normalized[7:]
        if normalized.startswith("builtins."):
            normalized = normalized[9:]
        if normalized.startswith("<class '") and normalized.endswith("'>"):
            normalized = normalized[8:-2]
        return normalized.lower()

    def _is_type_subscription_pattern(self, container: object, index: object) -> bool:
        """Return True when BINARY_SUBSCR matches `list[int]`-style type usage."""
        container_name = getattr(container, "name", "") or ""
        index_name = getattr(index, "name", "") or ""
        normalized_container = self._normalize_symbolic_name(container_name)
        normalized_index = self._normalize_symbolic_name(index_name)

        if normalized_container.startswith("typing."):
            return True
        if normalized_container.startswith("collections.abc."):
            return True
        return (
            normalized_container in self.TYPE_SUBSCRIPTION_CONTAINERS
            and normalized_index in self.TYPE_SUBSCRIPTION_INDEXES
        )

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

    def _check_unbounded_index(
        self,
        state: VMState,
        index: SymbolicValue,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check symbolic index growth when concrete container bounds are unavailable."""
        large_constraint = [
            *state.path_constraints,
            index.is_int,
            index.z3_int >= self.MAX_REASONABLE_SIZE,
        ]
        if is_satisfiable_fn(large_constraint):
            return Issue(
                kind=IssueKind.INDEX_ERROR,
                message=(
                    f"Index {index.name} could be unreasonably large "
                    f"(>= {self.MAX_REASONABLE_SIZE})"
                ),
                constraints=large_constraint,
                model=get_model(large_constraint),
                pc=state.pc,
                confidence=0.8,
            )
        return None
