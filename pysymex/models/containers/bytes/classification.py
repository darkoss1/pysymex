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

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicIsasciiModel,
    SymbolicValue,
    bytes_type_error_result,
    concrete_bytes_literal,
    get_symbolic_bytes,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Character-classification symbolic bytes models."""


def _exact_classification_result(args: list[StackValue], method_name: str) -> bool | None:
    literal = concrete_bytes_literal(args[0])
    if literal is None:
        return None
    return bool(getattr(literal, method_name)())


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
            return bytes_type_error_result(self.name, state)
        exact = _exact_classification_result(args, "isdigit")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isdigit_{state.pc}")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


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
            return bytes_type_error_result(self.name, state)
        exact = _exact_classification_result(args, "isalpha")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isalpha_{state.pc}")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


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
            return bytes_type_error_result(self.name, state)
        exact = _exact_classification_result(args, "isalnum")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isalnum_{state.pc}")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


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
            return bytes_type_error_result(self.name, state)
        exact = _exact_classification_result(args, "isspace")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isspace_{state.pc}")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


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
            return bytes_type_error_result(self.name, state)
        exact = _exact_classification_result(args, "islower")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_islower_{state.pc}")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


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
            return bytes_type_error_result(self.name, state)
        exact = _exact_classification_result(args, "isupper")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isupper_{state.pc}")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


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
            return bytes_type_error_result(self.name, state)
        exact = _exact_classification_result(args, "istitle")
        if exact is not None:
            return ModelResult(value=SymbolicValue.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_istitle_{state.pc}")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesIsasciiModel(SymbolicIsasciiModel):
    name = "isascii"
    qualname = "bytes.isascii"


class BytearrayIsasciiModel(SymbolicIsasciiModel):
    name = "isascii"
    qualname = "bytearray.isascii"
