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

"""Affix-search symbolic bytes models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.types.containers.bytes_search import (
    bytes_slice_bounds_are_definitely_invalid,
    bytes_type_name_if_definitely_not_bytes_like,
    concrete_optional_bytes_index,
)
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    concrete_bytes_literal,
    get_symbolic_bytes,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

_SLICE_INDEX_TYPE_ERROR = "slice indices must be integers or None or have an __index__ method"


def _exact_affix_result(
    args: list[StackValue],
    *,
    suffix: bool,
    qualname: str,
    state: VMState,
) -> ModelResult | None:
    source = concrete_bytes_literal(args[0])
    if len(args) <= 1:
        return None
    affix_arg = args[1]

    slice_args: list[int | None] = []
    for value in args[2:]:
        supported, concrete_index = concrete_optional_bytes_index(value)
        if not supported:
            return None
        slice_args.append(concrete_index)

    affix_items = _tuple_affix_items(affix_arg)
    if affix_items is not None:
        if source is None and args[2:]:
            return None
        if source is None:
            symbolic_result = _symbolic_tuple_affix_result(affix_items)
            if symbolic_result is None:
                return None
            return ModelResult(value=SymbolicValue.from_const(symbolic_result))
        for item in affix_items:
            affix = concrete_bytes_literal(item)
            if affix is None:
                invalid_type = bytes_type_name_if_definitely_not_bytes_like(item)
                if invalid_type is None:
                    return None
                return ModelResult.method_type_error(
                    qualname,
                    state,
                    message=f"a bytes-like object is required, not '{invalid_type}'",
                )
            if _matches_affix(source, affix, slice_args, suffix=suffix):
                return ModelResult(value=SymbolicValue.from_const(True))
        return ModelResult(value=SymbolicValue.from_const(False))

    affix = concrete_bytes_literal(affix_arg)
    if affix is None:
        return None
    if source is None:
        if args[2:]:
            return None
        if affix == b"":
            return ModelResult(value=SymbolicValue.from_const(True))
        return None
    return ModelResult(value=SymbolicValue.from_const(_matches_affix(source, affix, slice_args, suffix=suffix)))


def _matches_affix(source: bytes, affix: bytes, slice_args: list[int | None], *, suffix: bool) -> bool:
    if suffix:
        return source.endswith(affix, *slice_args)
    return source.startswith(affix, *slice_args)


def _symbolic_tuple_affix_result(affix_items: tuple[object, ...]) -> bool | None:
    if not affix_items:
        return False
    for item in affix_items:
        affix = concrete_bytes_literal(item)
        if affix is None:
            invalid_type = bytes_type_name_if_definitely_not_bytes_like(item)
            if invalid_type is not None:
                return None
            return None
        if affix == b"":
            return True
    return None


def _affix_operand_type_error(method: str, value: object) -> str | None:
    if concrete_bytes_literal(value) is not None:
        return None
    tuple_items = _tuple_affix_items(value)
    if tuple_items is None:
        invalid_type = bytes_type_name_if_definitely_not_bytes_like(value)
        if invalid_type is None:
            return None
        return f"{method} first arg must be bytes or a tuple of bytes, not {invalid_type}"
    return _tuple_affix_type_error(tuple_items)


def _tuple_affix_type_error(tuple_items: tuple[object, ...]) -> str | None:
    for item in tuple_items:
        affix = concrete_bytes_literal(item)
        if affix == b"":
            return None
        if affix is not None:
            return None
        invalid_type = bytes_type_name_if_definitely_not_bytes_like(item)
        if invalid_type is not None:
            return f"a bytes-like object is required, not '{invalid_type}'"
        return None
    return None


def _tuple_affix_items(value: object) -> tuple[object, ...] | None:
    if isinstance(value, tuple):
        return cast("tuple[object, ...]", value)
    if isinstance(value, SymbolicList) and getattr(value, "_type", None) == "tuple":
        items = value.concrete_items
        if items is None:
            return None
        return tuple(items)
    return None


class BytesStartswithModel(FunctionModel):
    """Model for bytes.startswith(prefix)."""

    name = "startswith"
    qualname = "bytes.startswith"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        operand_error = _affix_operand_type_error(self.name, args[1])
        if operand_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=operand_error)
        if bytes_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_affix_result(args, suffix=False, qualname=self.qualname, state=state)
        if exact is not None:
            return exact
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic_bool(f"bytes_startswith_{state.pc}")
        constraints = [constraint]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesEndswithModel(FunctionModel):
    """Model for bytes.endswith(suffix)."""

    name = "endswith"
    qualname = "bytes.endswith"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        operand_error = _affix_operand_type_error(self.name, args[1])
        if operand_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=operand_error)
        if bytes_slice_bounds_are_definitely_invalid(args[2:]):
            return ModelResult.method_type_error(
                self.qualname,
                state,
                message=_SLICE_INDEX_TYPE_ERROR,
            )
        exact = _exact_affix_result(args, suffix=True, qualname=self.qualname, state=state)
        if exact is not None:
            return exact
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic_bool(f"bytes_endswith_{state.pc}")
        constraints = [constraint]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)
