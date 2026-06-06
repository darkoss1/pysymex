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

"""Replacement symbolic bytes models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicList,
    SymbolicValue,
    bytearray_result,
    bytes_type_error_result,
    concrete_bytes_literal,
    symbolic_bytes_literal,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class BytesReplaceModel(FunctionModel):
    """Model for bytes.replace(old, new)."""

    name = "replace"
    qualname = "bytes.replace"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {3, 4} or kwargs:
            return bytes_type_error_result(self.name, state)
        exact = _exact_replace_result(args)
        if exact is not None:
            return ModelResult(value=symbolic_bytes_literal(exact))
        result, constraint = SymbolicList.symbolic(f"bytes_replace_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        return ModelResult(value=result, constraints=constraints)


def _exact_replace_result(args: list[StackValue]) -> bytes | None:
    source = concrete_bytes_literal(args[0])
    old = concrete_bytes_literal(args[1]) if len(args) > 1 else None
    new = concrete_bytes_literal(args[2]) if len(args) > 2 else None
    if source is None or old is None or new is None:
        return None
    count = _concrete_int(args[3]) if len(args) > 3 else -1
    if count is None:
        return None
    return source.replace(old, new, count)


def _concrete_int(value: object) -> int | None:
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


class BytearrayReplaceModel(BytesReplaceModel):
    """Model for bytearray.replace()."""

    qualname = "bytearray.replace"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))
