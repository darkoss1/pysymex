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

from pysymex.core.constants import Z3_TRUE
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicList,
    SymbolicValue,
    bytes_type_error_result,
    concrete_bytes_literal,
    get_symbolic_bytes,
    symbolic_bytes_literal,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

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
            return bytes_type_error_result(self.name, state)
        exact = _exact_translate_result(args, kwargs, state)
        if exact is not None:
            return exact
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_translate_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
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
            return bytes_type_error_result(self.name, state)
        exact = _exact_maketrans_result(args, state)
        if exact is not None:
            return exact
        result, constraint = SymbolicList.symbolic(f"bytes_maketrans_{state.pc}")
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
            return bytes_type_error_result(self.name, state)
        exact, invalid_args = _exact_expandtabs_result(args, kwargs)
        if invalid_args:
            return bytes_type_error_result(self.name, state)
        if exact is not None:
            return ModelResult(value=symbolic_bytes_literal(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_expandtabs_{state.pc}")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len >= b.z3_len)
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
                return bytes_type_error_result("translate", state)
            return None
        delete = delete_value
    try:
        return ModelResult(value=symbolic_bytes_literal(source.translate(table, delete)))
    except TypeError:
        return bytes_type_error_result("translate", state)
    except ValueError as exc:
        return _value_error_result("bytes_translate", str(exc), state)


def _exact_maketrans_result(args: list[StackValue], state: VMState) -> ModelResult | None:
    from_bytes = concrete_bytes_literal(args[0])
    to_bytes = concrete_bytes_literal(args[1])
    if from_bytes is None or to_bytes is None:
        if _definitely_not_bytes(args[0]) or _definitely_not_bytes(args[1]):
            return bytes_type_error_result("maketrans", state)
        return None
    try:
        return ModelResult(value=symbolic_bytes_literal(bytes.maketrans(from_bytes, to_bytes)))
    except ValueError as exc:
        return _value_error_result("bytes_maketrans", str(exc), state)


def _exact_expandtabs_result(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> tuple[bytes | None, bool]:
    source = concrete_bytes_literal(args[0])
    if source is None:
        return None, False
    tabsize_arg = args[1] if len(args) > 1 else kwargs.get("tabsize", _MISSING)
    tabsize = 8
    if tabsize_arg is not _MISSING:
        tabsize_value, invalid = _required_int_argument(tabsize_arg)
        if invalid:
            return None, True
        if tabsize_value is None:
            return None, False
        tabsize = tabsize_value
    return source.expandtabs(tabsize), False


def _optional_bytes_table(value: object) -> tuple[bytes | None, bool]:
    if isinstance(value, SymbolicNone) or value is None:
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
    if isinstance(value, SymbolicNone) or value is None:
        return None, True
    return None, True


def _definitely_not_bytes(value: object) -> bool:
    if concrete_bytes_literal(value) is not None:
        return False
    if isinstance(value, SymbolicValue):
        return value.value is not None
    if isinstance(value, SymbolicList):
        return False
    if isinstance(value, SymbolicNone) or value is None:
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
            }
        },
    )
