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

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

from .shared import (
    concrete_bytes_literal,
    symbolic_bytes_length,
    symbolic_bytes_literal,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Translation symbolic bytes models."""


class BytesTranslateModel(FunctionModel):
    """Model for bytes.translate(table)."""

    name = "translate"
    qualname = "bytes.translate"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {2, 3}
            or set(kwargs) - {"delete"}
            or (len(args) > 2 and "delete" in kwargs)
        ):
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        exact = _exact_translate_result(args, kwargs, state)
        if exact is not None:
            return exact
        length = symbolic_bytes_length(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_translate_{state.pc}")
        result.set_runtime_type("bytes")
        constraints = [constraint, result.z3_len >= 0]
        if length is not None:
            if _translate_preserves_length(args, kwargs):
                constraints.append(result.z3_len == length)
            else:
                constraints.append(result.z3_len <= length)
        return ModelResult(value=result, constraints=constraints)


class BytesMaketransModel(FunctionModel):
    """Model for bytes.maketrans(from, to)."""

    name = "maketrans"
    qualname = "bytes.maketrans"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        exact = _exact_maketrans_result(args, state)
        if exact is not None:
            return exact
        result, constraint = SymbolicList.symbolic(f"bytes_maketrans_{state.pc}")
        result.set_runtime_type("bytes")
        constraints = [constraint, result.z3_len == 256]
        return ModelResult(value=result, constraints=constraints)


class BytesExpandtabsModel(FunctionModel):
    """Model for bytes.expandtabs()."""

    name = "expandtabs"
    qualname = "bytes.expandtabs"

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
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        tabsize, invalid_args = _expandtabs_tabsize(args, kwargs)
        if invalid_args:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        exact = _exact_expandtabs_result(args[0], tabsize)
        if exact is not None:
            return ModelResult(value=symbolic_bytes_literal(exact))
        length = symbolic_bytes_length(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_expandtabs_{state.pc}")
        result.set_runtime_type("bytes")
        constraints = [constraint, result.z3_len >= 0]
        if length is not None:
            constraints.append(z3.Implies(length == 0, result.z3_len == 0))
            if tabsize is not None and tabsize <= 0:
                constraints.append(result.z3_len <= length)
            elif tabsize is not None:
                constraints.append(result.z3_len >= length)
        return ModelResult(value=result, constraints=constraints)


_MISSING = object()


def _exact_translate_result(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    state: VMState,
) -> ModelResult | None:
    source = concrete_bytes_literal(args[0])
    if source is None:
        return None
    table_arg = args[1]
    delete_arg = args[2] if len(args) > 2 else kwargs.get("delete", _MISSING)
    table, table_known = _optional_bytes_table(table_arg)
    if not table_known:
        return None
    delete = b""
    if delete_arg is not _MISSING:
        delete_value = concrete_bytes_literal(delete_arg)
        if delete_value is None:
            if _definitely_not_bytes(delete_arg):
                return ModelResult.method_type_error("bytes.translate", state)
            return None
        delete = delete_value
    try:
        return ModelResult(value=symbolic_bytes_literal(source.translate(table, delete)))
    except TypeError:
        return ModelResult.method_type_error("bytes.translate", state)
    except ValueError as exc:
        return _value_error_result("bytes_translate", str(exc), state)


def _translate_preserves_length(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> bool:
    table_arg = args[1]
    table, table_known = _optional_bytes_table(table_arg)
    if not table_known:
        return False
    if table is not None and len(table) != 256:
        return False
    delete_arg = args[2] if len(args) > 2 else kwargs.get("delete", _MISSING)
    return delete_arg is _MISSING or concrete_bytes_literal(delete_arg) == b""


def _exact_maketrans_result(args: list[StackValue], state: VMState) -> ModelResult | None:
    from_bytes = concrete_bytes_literal(args[0])
    to_bytes = concrete_bytes_literal(args[1])
    if from_bytes is None or to_bytes is None:
        if _definitely_not_bytes(args[0]) or _definitely_not_bytes(args[1]):
            return ModelResult.method_type_error("bytes.maketrans", state)
        return None
    try:
        return ModelResult(value=symbolic_bytes_literal(bytes.maketrans(from_bytes, to_bytes)))
    except ValueError as exc:
        return _value_error_result("bytes_maketrans", str(exc), state)


def _expandtabs_tabsize(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> tuple[int | None, bool]:
    tabsize_arg = args[1] if len(args) > 1 else kwargs.get("tabsize", _MISSING)
    if tabsize_arg is _MISSING:
        return 8, False
    return _required_int_argument(tabsize_arg)


def _exact_expandtabs_result(source_arg: StackValue, tabsize: int | None) -> bytes | None:
    source = concrete_bytes_literal(source_arg)
    if source is None or tabsize is None:
        return None
    return source.expandtabs(tabsize)


def _optional_bytes_table(value: object) -> tuple[bytes | None, bool]:
    if isinstance(value, SymbolicNoneType) or value is None:
        return None, True
    table = concrete_bytes_literal(value)
    if table is not None:
        return table, True
    return None, False


def _required_int_argument(value: object) -> tuple[int | None, bool]:
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value), False
    if isinstance(value, int):
        return value, False
    if isinstance(value, SymbolicNoneType) or value is None:
        return None, True
    return None, True


def _definitely_not_bytes(value: object) -> bool:
    if concrete_bytes_literal(value) is not None:
        return False
    if isinstance(value, SymbolicValue):
        return value.value is not None
    if isinstance(value, SymbolicList):
        return False
    if isinstance(value, SymbolicNoneType) or value is None:
        return True
    return True


def _value_error_result(name: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicList.symbolic(f"{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "potential_exception": {
                "type": "ValueError",
                "condition": Z3_TRUE,
                "message": message,
            },
        },
    )
