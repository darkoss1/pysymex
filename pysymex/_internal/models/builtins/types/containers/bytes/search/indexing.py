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

"""Index-search symbolic bytes models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.types.containers.bytes_search import (
    bytes_slice_bounds_are_definitely_invalid,
    concrete_bytes_slice_args,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    concrete_bytes_literal,
    symbolic_bytes_length,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

_SLICE_INDEX_TYPE_ERROR = "slice indices must be integers or None or have an __index__ method"


class BytesFindModel(FunctionModel):
    """Model for bytes.find(sub)."""

    name = "find"
    qualname = "bytes.find"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        if bytes_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_find_result(args, reverse=False)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        length = symbolic_bytes_length(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic_int(f"bytes_find_{state.pc}")
        constraints = [constraint, result.z3_int >= -1]
        if length is not None:
            constraints.append(result.z3_int < length)
        return ModelResult(value=result, constraints=constraints)


class BytesRfindModel(FunctionModel):
    """Model for bytes.rfind(sub)."""

    name = "rfind"
    qualname = "bytes.rfind"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        if bytes_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_find_result(args, reverse=True)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        length = symbolic_bytes_length(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic_int(f"bytes_rfind_{state.pc}")
        constraints = [constraint, result.z3_int >= -1]
        if length is not None:
            constraints.append(result.z3_int < length)
        return ModelResult(value=result, constraints=constraints)


class BytesIndexModel(FunctionModel):
    """Model for bytes.index(sub)."""

    name = "index"
    qualname = "bytes.index"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        if bytes_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_find_result(args, reverse=False)
        if exact is not None:
            side_effects = _value_error_side_effect(exact, "subsection not found")
            return ModelResult(value=SymbolicValue.from_const(exact), side_effects=side_effects)
        length = symbolic_bytes_length(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic_int(f"bytes_index_{state.pc}")
        constraints = [constraint, result.z3_int >= 0]
        side_effects: dict[str, object] = {
            "potential_exception": {
                "type": "ValueError",
                "condition": z3.Bool(f"bytes_index_missing_{state.pc}"),
                "message": "subsection not found",
            },
        }
        if length is not None:
            constraints.append(result.z3_int < length)
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


class BytesRindexModel(FunctionModel):
    """Model for bytes.rindex(sub)."""

    name = "rindex"
    qualname = "bytes.rindex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        if bytes_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_find_result(args, reverse=True)
        if exact is not None:
            side_effects = _value_error_side_effect(exact, "subsection not found")
            return ModelResult(value=SymbolicValue.from_const(exact), side_effects=side_effects)
        length = symbolic_bytes_length(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic_int(f"bytes_rindex_{state.pc}")
        constraints = [constraint, result.z3_int >= 0]
        side_effects: dict[str, object] = {
            "potential_exception": {
                "type": "ValueError",
                "condition": z3.Bool(f"bytes_rindex_missing_{state.pc}"),
                "message": "subsection not found",
            },
        }
        if length is not None:
            constraints.append(result.z3_int < length)
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


def _exact_find_result(args: list[StackValue], *, reverse: bool) -> int | None:
    source = concrete_bytes_literal(args[0])
    needle = concrete_bytes_literal(args[1]) if len(args) > 1 else None
    slice_args = concrete_bytes_slice_args(args[2:])
    if source is None or needle is None or slice_args is None:
        return None
    return source.rfind(needle, *slice_args) if reverse else source.find(needle, *slice_args)


def _value_error_side_effect(result: int, message: str) -> dict[str, object]:
    if result != -1:
        return {}
    return {
        "potential_exception": {
            "type": "ValueError",
            "condition": Z3_TRUE,
            "message": message,
        },
    }
