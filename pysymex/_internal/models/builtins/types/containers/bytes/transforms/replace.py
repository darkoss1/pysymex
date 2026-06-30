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

from pysymex._internal.core.types.containers.bytes_search import (
    bytes_index_type_name_if_definitely_invalid,
    bytes_type_name_if_definitely_not_bytes_like,
    concrete_bytes_index,
)
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    bytearray_result,
    concrete_bytes_literal,
    symbolic_bytes_literal,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


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
            return ModelResult.method_type_error(self.qualname, state)
        old_error = _bytes_like_type_error(args[1])
        if old_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=old_error)
        new_error = _bytes_like_type_error(args[2])
        if new_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=new_error)
        if len(args) == 4:
            count_error = _definite_invalid_count_error(args[3])
            if count_error is not None:
                return ModelResult.method_type_error(self.qualname, state, message=count_error)
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
    count = concrete_bytes_index(args[3]) if len(args) > 3 else -1
    if count is None:
        return None
    return source.replace(old, new, count)


def _bytes_like_type_error(value: object) -> str | None:
    invalid_type = bytes_type_name_if_definitely_not_bytes_like(value)
    if invalid_type is None:
        return None
    return f"a bytes-like object is required, not '{invalid_type}'"


def _definite_invalid_count_error(value: object) -> str | None:
    invalid_type = bytes_index_type_name_if_definitely_invalid(value)
    if invalid_type is None:
        return None
    return f"'{invalid_type}' object cannot be interpreted as an integer"


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
