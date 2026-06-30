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

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.strings.shared import (
    SymbolicIsasciiModel,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

from .shared import (
    concrete_bytes_literal,
    symbolic_bytes_length,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Character-classification symbolic bytes models."""


def _exact_classification_result(args: list[StackValue], method_name: str) -> bool | None:
    literal = concrete_bytes_literal(args[0])
    if literal is None:
        return None
    return bool(getattr(literal, method_name)())


def _symbolic_classification_result(
    args: list[StackValue],
    *,
    method_name: str,
    state: VMState,
) -> ModelResult:
    exact = _exact_classification_result(args, method_name)
    if exact is not None:
        return ModelResult(value=SymbolicValue.from_const(exact))
    result, constraint = SymbolicValue.symbolic_bool(f"bytes_{method_name}_{state.pc}")
    constraints = [constraint]
    receiver_length = symbolic_bytes_length(args[0], state)
    if receiver_length is not None:
        constraints.append(z3.Implies(receiver_length == 0, z3.Not(result.z3_bool)))
    return ModelResult(value=result, constraints=constraints)


class BytesIsdigitModel(FunctionModel):
    """Model for bytes.isdigit()."""

    name = "isdigit"
    qualname = "bytes.isdigit"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        return _symbolic_classification_result(args, method_name=self.name, state=state)


class BytesIsalphaModel(FunctionModel):
    """Model for bytes.isalpha()."""

    name = "isalpha"
    qualname = "bytes.isalpha"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        return _symbolic_classification_result(args, method_name=self.name, state=state)


class BytesIsalnumModel(FunctionModel):
    """Model for bytes.isalnum()."""

    name = "isalnum"
    qualname = "bytes.isalnum"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        return _symbolic_classification_result(args, method_name=self.name, state=state)


class BytesIsspaceModel(FunctionModel):
    """Model for bytes.isspace()."""

    name = "isspace"
    qualname = "bytes.isspace"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        return _symbolic_classification_result(args, method_name=self.name, state=state)


class BytesIslowerModel(FunctionModel):
    """Model for bytes.islower()."""

    name = "islower"
    qualname = "bytes.islower"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        return _symbolic_classification_result(args, method_name=self.name, state=state)


class BytesIsupperModel(FunctionModel):
    """Model for bytes.isalpha()."""

    name = "isupper"
    qualname = "bytes.isupper"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        return _symbolic_classification_result(args, method_name=self.name, state=state)


class BytesIstitleModel(FunctionModel):
    """Model for bytes.istitle()."""

    name = "istitle"
    qualname = "bytes.istitle"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        return _symbolic_classification_result(args, method_name=self.name, state=state)


class BytesIsasciiModel(SymbolicIsasciiModel):
    name = "isascii"
    qualname = "bytes.isascii"


class BytearrayIsasciiModel(SymbolicIsasciiModel):
    name = "isascii"
    qualname = "bytearray.isascii"
