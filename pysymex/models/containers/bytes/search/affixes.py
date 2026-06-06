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

from typing import TYPE_CHECKING

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicValue,
    bytes_type_error_result,
    concrete_bytes_literal,
    get_symbolic_bytes,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def _exact_affix_result(args: list[StackValue], *, suffix: bool) -> bool | None:
    source = concrete_bytes_literal(args[0])
    affix = concrete_bytes_literal(args[1]) if len(args) > 1 else None
    if source is None or affix is None:
        return None

    slice_args: list[int | None] = []
    for value in args[2:]:
        supported, concrete_index = _concrete_optional_int(value)
        if not supported:
            return None
        slice_args.append(concrete_index)

    if suffix:
        return source.endswith(affix, *slice_args)
    return source.startswith(affix, *slice_args)


def _concrete_optional_int(value: object) -> tuple[bool, int | None]:
    if isinstance(value, SymbolicValue):
        value = value.value
    if value is None:
        return True, None
    if isinstance(value, bool):
        return True, int(value)
    if isinstance(value, int):
        return True, value
    return False, None


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
            return bytes_type_error_result(self.name, state)
        exact = _exact_affix_result(args, suffix=False)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_startswith_{state.pc}")
        constraints = [constraint, result.is_bool]
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
            return bytes_type_error_result(self.name, state)
        exact = _exact_affix_result(args, suffix=True)
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_endswith_{state.pc}")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)
