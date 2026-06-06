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

from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicList,
    SymbolicString,
    SymbolicValue,
    bytes_type_error_result,
    concrete_bytes_literal,
    get_symbolic_bytes,
    symbolic_bytes_literal,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Length, hex, and padding symbolic bytes models."""


class BytesLenModel(FunctionModel):
    """Model for len(bytes)."""

    name = "__len__"
    qualname = "bytes.__len__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = get_symbolic_bytes(args[0], state) if args else None
        if b is not None:
            result = SymbolicValue(
                _name=f"len_bytes_{state.pc}",
                z3_int=b.z3_len,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
            )
            return ModelResult(value=result, constraints=[])
        result, constraint = SymbolicValue.symbolic(f"bytes_len_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
        )


class BytesHexModel(FunctionModel):
    """Model for bytes.hex()."""

    name = "hex"
    qualname = "bytes.hex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2, 3}
            or set(kwargs) - {"sep", "bytes_per_sep"}
            or (len(args) > 1 and "sep" in kwargs)
            or (len(args) > 2 and "bytes_per_sep" in kwargs)
        ):
            return bytes_type_error_result(self.name, state)
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicString.symbolic(f"bytes_hex_{state.pc}")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len == b.z3_len * 2)
        return ModelResult(value=result, constraints=constraints)


class BytearrayHexModel(BytesHexModel):
    """Model for bytearray.hex()."""

    qualname = "bytearray.hex"


class BytesCenterModel(FunctionModel):
    """Model for bytes.center(width)."""

    name = "center"
    qualname = "bytes.center"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            return bytes_type_error_result(self.name, state)
        exact = _exact_padding_result(args, "center", self.name, state)
        if exact is not None:
            return exact
        b = get_symbolic_bytes(args[0], state) if args else None
        width = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"bytes_center_{state.pc}")
        constraints = [constraint]
        if b is not None and width is not None:
            w = getattr(width, "z3_int", None)
            if w is not None:
                constraints.append(result.z3_len == z3.If(w > b.z3_len, w, b.z3_len))
        return ModelResult(value=result, constraints=constraints)


class BytesLjustModel(FunctionModel):
    """Model for bytes.ljust(width)."""

    name = "ljust"
    qualname = "bytes.ljust"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            return bytes_type_error_result(self.name, state)
        exact = _exact_padding_result(args, "ljust", self.name, state)
        if exact is not None:
            return exact
        b = get_symbolic_bytes(args[0], state) if args else None
        width = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"bytes_ljust_{state.pc}")
        constraints = [constraint]
        if b is not None and width is not None:
            w = getattr(width, "z3_int", None)
            if w is not None:
                constraints.append(result.z3_len == z3.If(w > b.z3_len, w, b.z3_len))
        return ModelResult(value=result, constraints=constraints)


class BytesRjustModel(FunctionModel):
    """Model for bytes.rjust(width)."""

    name = "rjust"
    qualname = "bytes.rjust"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3} or kwargs:
            return bytes_type_error_result(self.name, state)
        exact = _exact_padding_result(args, "rjust", self.name, state)
        if exact is not None:
            return exact
        b = get_symbolic_bytes(args[0], state) if args else None
        width = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"bytes_rjust_{state.pc}")
        constraints = [constraint]
        if b is not None and width is not None:
            w = getattr(width, "z3_int", None)
            if w is not None:
                constraints.append(result.z3_len == z3.If(w > b.z3_len, w, b.z3_len))
        return ModelResult(value=result, constraints=constraints)


class BytesZfillModel(FunctionModel):
    """Model for bytes.zfill(width)."""

    name = "zfill"
    qualname = "bytes.zfill"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return bytes_type_error_result(self.name, state)
        literal = concrete_bytes_literal(args[0]) if args else None
        width = _concrete_int(args[1]) if len(args) > 1 else None
        if literal is not None and width is not None:
            return ModelResult(value=symbolic_bytes_literal(literal.zfill(width)))
        b = get_symbolic_bytes(args[0], state) if args else None
        width = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"bytes_zfill_{state.pc}")
        constraints = [constraint]
        if b is not None and width is not None:
            w = getattr(width, "z3_int", None)
            if w is not None:
                constraints.append(result.z3_len == z3.If(w > b.z3_len, w, b.z3_len))
        return ModelResult(value=result, constraints=constraints)


def _exact_padding_result(
    args: list[StackValue],
    method_name: str,
    model_name: str,
    state: VMState,
) -> ModelResult | None:
    literal = concrete_bytes_literal(args[0])
    width = _concrete_int(args[1]) if len(args) > 1 else None
    if literal is not None and width is None and len(args) > 1 and _definitely_not_int(args[1]):
        return bytes_type_error_result(model_name, state)
    if literal is None or width is None:
        return None

    fillchar = b" "
    if len(args) == 3:
        concrete_fillchar = concrete_bytes_literal(args[2])
        if concrete_fillchar is None and _definitely_not_bytes(args[2]):
            return bytes_type_error_result(model_name, state)
        if concrete_fillchar is None:
            return None
        if len(concrete_fillchar) != 1:
            return bytes_type_error_result(model_name, state)
        fillchar = concrete_fillchar

    padded = getattr(literal, method_name)(width, fillchar)
    return ModelResult(value=symbolic_bytes_literal(padded))


def _concrete_int(value: object) -> int | None:
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _definitely_not_int(value: object) -> bool:
    if isinstance(value, SymbolicValue):
        value = value.value
    return isinstance(value, (str, bytes, float, SymbolicString))


def _definitely_not_bytes(value: object) -> bool:
    if isinstance(value, SymbolicValue):
        value = value.value
    return not isinstance(value, bytes) and value is not None
