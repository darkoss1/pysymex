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

import codecs
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.builtins.types.containers.bytes.shared import symbolic_bytes_literal

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicList,
    SymbolicValue,
)
from .translation_exact import exact_maketrans_result, exact_translate_result

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Encoding and translation symbolic string models."""


class StrEncodeModel(FunctionModel):
    """Model for str.encode() - returns bytes."""

    name = "encode"
    qualname = "str.encode"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2, 3}
            or set(kwargs) - {"encoding", "errors"}
            or (len(args) > 1 and "encoding" in kwargs)
            or (len(args) > 2 and "errors" in kwargs)
        ):
            return ModelResult.method_type_error(self.qualname, state)
        encoding, errors, invalid_args = _encode_arguments(args, kwargs)
        if invalid_args:
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_encode_result(args[0], encoding, errors)
        if exact is not None:
            return ModelResult(value=symbolic_bytes_literal(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"encode_{state.pc}")
        result.set_runtime_type("bytes")
        constraints = [constraint, result.z3_len >= 0]
        if original is not None and _strict_utf8_encode_preserves_min_length(encoding, errors):
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrExpandtabsModel(FunctionModel):
    """Model for str.expandtabs() - replaces tabs with spaces."""

    name = "expandtabs"
    qualname = "str.expandtabs"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2}
            or set(kwargs) - {"tabsize"}
            or (len(args) > 1 and "tabsize" in kwargs)
        ):
            return ModelResult.method_type_error(self.qualname, state)
        tabsize, invalid_args = _expandtabs_tabsize(args, kwargs)
        if invalid_args:
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_expandtabs_result(args[0], tabsize)
        if exact is not None:
            return ModelResult(value=SymbolicString.from_const(exact))
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"expandtabs_{state.pc}")
        constraints = [base_constraint, result.z3_len >= 0]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, result.z3_len == 0))
            if tabsize is not None and tabsize <= 0:
                constraints.append(result.z3_len <= original.z3_len)
            elif tabsize is not None:
                constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(value=result, constraints=constraints)


_MISSING = object()


def _encode_arguments(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> tuple[str | None, str | None, bool]:
    encoding_arg = args[1] if len(args) > 1 else kwargs.get("encoding", _MISSING)
    errors_arg = args[2] if len(args) > 2 else kwargs.get("errors", _MISSING)
    encoding = "utf-8"
    errors = "strict"
    if encoding_arg is not _MISSING:
        encoding_value, invalid = _required_text_argument(encoding_arg)
        if invalid:
            return None, None, True
        if encoding_value is None:
            encoding = None
        else:
            encoding = encoding_value
    if errors_arg is not _MISSING:
        errors_value, invalid = _required_text_argument(errors_arg)
        if invalid:
            return None, None, True
        if errors_value is None:
            errors = None
        else:
            errors = errors_value
    return encoding, errors, False


def _exact_encode_result(
    source_arg: StackValue,
    encoding: str | None,
    errors: str | None,
) -> bytes | None:
    source = SymbolicString.concrete_literal(source_arg)
    if source is None or encoding is None or errors is None:
        return None
    try:
        return source.encode(encoding, errors)
    except TypeError:
        return None
    except (LookupError, UnicodeError):
        return None


def _strict_utf8_encode_preserves_min_length(
    encoding: str | None,
    errors: str | None,
) -> bool:
    return encoding is not None and _is_utf8_encoding(encoding) and errors == "strict"


def _is_utf8_encoding(encoding: str) -> bool:
    try:
        return codecs.lookup(encoding).name == "utf-8"
    except LookupError:
        return False


def _required_text_argument(value: object) -> tuple[str | None, bool]:
    text = SymbolicString.concrete_literal(value)
    if text is not None:
        return text, False
    if isinstance(value, SymbolicValue):
        return None, value.value is not None
    if isinstance(value, SymbolicString):
        return None, False
    return None, True


def _expandtabs_tabsize(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> tuple[int | None, bool]:
    tabsize_arg = args[1] if len(args) > 1 else kwargs.get("tabsize", _MISSING)
    if tabsize_arg is _MISSING:
        return 8, False
    return _required_int_argument(tabsize_arg)


def _exact_expandtabs_result(source_arg: StackValue, tabsize: int | None) -> str | None:
    source = SymbolicString.concrete_literal(source_arg)
    if source is None or tabsize is None:
        return None
    return source.expandtabs(tabsize)


def _required_int_argument(value: object) -> tuple[int | None, bool]:
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value), False
    if isinstance(value, int):
        return value, False
    if isinstance(value, (SymbolicString, SymbolicNoneType)):
        return None, True
    if value is None:
        return None, True
    return None, True


class StrMaketransModel(FunctionModel):
    """Model for str.maketrans() - static method returning translation table."""

    name = "maketrans"
    qualname = "str.maketrans"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        receiver = SymbolicString.concrete_literal(args[0]) if args else None
        call_args = args[1:] if len(args) > 2 and receiver == "" else args
        if len(call_args) not in {1, 2, 3} or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        exact = exact_maketrans_result(call_args, state)
        if exact is not None:
            return exact
        result, constraint = SymbolicDict.symbolic(f"maketrans_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class StrTranslateModel(FunctionModel):
    """Model for str.translate(table) - applies translation table.
    Length stays same or decreases (deletions possible).
    """

    name = "translate"
    qualname = "str.translate"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(self.qualname, state)
        exact = exact_translate_result(args[0], args[1], state)
        if exact is not None:
            return exact
        original = SymbolicString.resolve(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"translate_{state.pc}")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)
