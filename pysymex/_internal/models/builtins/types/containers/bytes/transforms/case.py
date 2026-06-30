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

"""Case-changing symbolic bytes models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    bytearray_result,
    concrete_bytes_literal,
    symbolic_bytes_length,
    symbolic_bytes_literal,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _exact_case_result(args: list[StackValue], method_name: str) -> SymbolicList | None:
    literal = concrete_bytes_literal(args[0])
    if literal is None:
        return None
    return symbolic_bytes_literal(getattr(literal, method_name)())


def _symbolic_case_result(args: list[StackValue], method_name: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicList.symbolic(f"bytes_{method_name}_{state.pc}")
    result.set_runtime_type("bytes")
    constraints = [constraint]
    length = symbolic_bytes_length(args[0], state)
    if length is not None:
        constraints.append(result.z3_len == length)
    return ModelResult(value=result, constraints=constraints)


class BytesUpperModel(FunctionModel):
    """Model for bytes.upper()."""

    name = "upper"
    qualname = "bytes.upper"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        exact = _exact_case_result(args, "upper")
        if exact is not None:
            return ModelResult(value=exact)
        return _symbolic_case_result(args, self.name, state)


class BytesLowerModel(FunctionModel):
    """Model for bytes.lower()."""

    name = "lower"
    qualname = "bytes.lower"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        exact = _exact_case_result(args, "lower")
        if exact is not None:
            return ModelResult(value=exact)
        return _symbolic_case_result(args, self.name, state)


class BytesTitleModel(FunctionModel):
    """Model for bytes.title()."""

    name = "title"
    qualname = "bytes.title"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        exact = _exact_case_result(args, "title")
        if exact is not None:
            return ModelResult(value=exact)
        return _symbolic_case_result(args, self.name, state)


class BytesCapitalizeModel(FunctionModel):
    """Model for bytes.capitalize()."""

    name = "capitalize"
    qualname = "bytes.capitalize"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        exact = _exact_case_result(args, "capitalize")
        if exact is not None:
            return ModelResult(value=exact)
        return _symbolic_case_result(args, self.name, state)


class BytesSwapcaseModel(FunctionModel):
    """Model for bytes.swapcase()."""

    name = "swapcase"
    qualname = "bytes.swapcase"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        exact = _exact_case_result(args, "swapcase")
        if exact is not None:
            return ModelResult(value=exact)
        return _symbolic_case_result(args, self.name, state)


class BytearrayUpperModel(BytesUpperModel):
    """Model for bytearray.upper()."""

    qualname = "bytearray.upper"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))


class BytearrayLowerModel(BytesLowerModel):
    """Model for bytearray.lower()."""

    qualname = "bytearray.lower"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))


class BytearrayTitleModel(BytesTitleModel):
    """Model for bytearray.title()."""

    qualname = "bytearray.title"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))


class BytearrayCapitalizedModel(BytesCapitalizeModel):
    """Model for bytearray.capitalize()."""

    qualname = "bytearray.capitalize"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))


class BytearraySwapcaseModel(BytesSwapcaseModel):
    """Model for bytearray.swapcase()."""

    qualname = "bytearray.swapcase"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))
