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

"""Trimming and affix-removal symbolic bytes models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    bytearray_result,
    concrete_bytes_literal,
    get_symbolic_bytes,
    symbolic_bytes_literal,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _concrete_strip_chars(args: list[StackValue]) -> tuple[bool, bytes | None]:
    if len(args) == 1:
        return True, None
    if args[1] is None:
        return True, None
    chars = concrete_bytes_literal(args[1])
    return (True, chars) if chars is not None else (False, None)


def _bytes_like_type_error(value: object) -> str | None:
    invalid_type = _definite_non_bytes_like_type_name(value)
    if invalid_type is None:
        return None
    return f"a bytes-like object is required, not '{invalid_type}'"


def _strip_chars_type_error(value: object) -> str | None:
    if _is_none_value(value):
        return None
    return _bytes_like_type_error(value)


def _definite_non_bytes_like_type_name(value: object) -> str | None:
    if concrete_bytes_literal(value) is not None:
        return None
    if isinstance(value, SymbolicValue):
        if value.value is not None:
            return type(value.value).__name__
        if z3.is_true(value.is_none):
            return "NoneType"
        if z3.is_true(value.is_bool):
            return "bool"
        if z3.is_true(value.is_int):
            return "int"
        if z3.is_true(value.is_str):
            return "str"
        return None
    if isinstance(value, SymbolicString):
        return "str"
    if isinstance(value, SymbolicNoneType) or value is None:
        return "NoneType"
    return type(value).__name__


def _is_none_value(value: object) -> bool:
    if isinstance(value, SymbolicNoneType) or value is None:
        return True
    return isinstance(value, SymbolicValue) and z3.is_true(value.is_none)


class BytesStripModel(FunctionModel):
    """Model for bytes.strip()."""

    name = "strip"
    qualname = "bytes.strip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        if len(args) == 2:
            chars_error = _strip_chars_type_error(args[1])
            if chars_error is not None:
                return ModelResult.method_type_error(
                    f"bytes.{self.name}",
                    state,
                    message=chars_error,
                )
        literal = concrete_bytes_literal(args[0]) if args else None
        has_concrete_chars, chars = _concrete_strip_chars(args)
        if literal is not None and has_concrete_chars:
            return ModelResult(value=symbolic_bytes_literal(literal.strip(chars)))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_strip_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesLstripModel(FunctionModel):
    """Model for bytes.lstrip()."""

    name = "lstrip"
    qualname = "bytes.lstrip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        if len(args) == 2:
            chars_error = _strip_chars_type_error(args[1])
            if chars_error is not None:
                return ModelResult.method_type_error(
                    f"bytes.{self.name}",
                    state,
                    message=chars_error,
                )
        literal = concrete_bytes_literal(args[0]) if args else None
        has_concrete_chars, chars = _concrete_strip_chars(args)
        if literal is not None and has_concrete_chars:
            return ModelResult(value=symbolic_bytes_literal(literal.lstrip(chars)))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_lstrip_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesRstripModel(FunctionModel):
    """Model for bytes.rstrip()."""

    name = "rstrip"
    qualname = "bytes.rstrip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        if len(args) == 2:
            chars_error = _strip_chars_type_error(args[1])
            if chars_error is not None:
                return ModelResult.method_type_error(
                    f"bytes.{self.name}",
                    state,
                    message=chars_error,
                )
        literal = concrete_bytes_literal(args[0]) if args else None
        has_concrete_chars, chars = _concrete_strip_chars(args)
        if literal is not None and has_concrete_chars:
            return ModelResult(value=symbolic_bytes_literal(literal.rstrip(chars)))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_rstrip_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesRemovePrefixModel(FunctionModel):
    """Model for bytes.removeprefix(prefix)."""

    name = "removeprefix"
    qualname = "bytes.removeprefix"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        prefix_error = _bytes_like_type_error(args[1])
        if prefix_error is not None:
            return ModelResult.method_type_error(
                f"bytes.{self.name}",
                state,
                message=prefix_error,
            )
        literal = concrete_bytes_literal(args[0]) if args else None
        prefix = concrete_bytes_literal(args[1]) if len(args) > 1 else None
        if literal is not None and prefix is not None:
            return ModelResult(value=symbolic_bytes_literal(literal.removeprefix(prefix)))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_removeprefix_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesRemoveSuffixModel(FunctionModel):
    """Model for bytes.removesuffix(suffix)."""

    name = "removesuffix"
    qualname = "bytes.removesuffix"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        suffix_error = _bytes_like_type_error(args[1])
        if suffix_error is not None:
            return ModelResult.method_type_error(
                f"bytes.{self.name}",
                state,
                message=suffix_error,
            )
        literal = concrete_bytes_literal(args[0]) if args else None
        suffix = concrete_bytes_literal(args[1]) if len(args) > 1 else None
        if literal is not None and suffix is not None:
            return ModelResult(value=symbolic_bytes_literal(literal.removesuffix(suffix)))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_removesuffix_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytearrayStripModel(BytesStripModel):
    """Model for bytearray.strip()."""

    qualname = "bytearray.strip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))


class BytearrayLstripModel(BytesLstripModel):
    """Model for bytearray.lstrip()."""

    qualname = "bytearray.lstrip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))


class BytearrayRstripModel(BytesRstripModel):
    """Model for bytearray.rstrip()."""

    qualname = "bytearray.rstrip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))


class BytearrayRemovePrefixModel(BytesRemovePrefixModel):
    """Model for bytearray.removeprefix()."""

    qualname = "bytearray.removeprefix"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))


class BytearrayRemoveSuffixModel(BytesRemoveSuffixModel):
    """Model for bytearray.removesuffix()."""

    qualname = "bytearray.removesuffix"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))
