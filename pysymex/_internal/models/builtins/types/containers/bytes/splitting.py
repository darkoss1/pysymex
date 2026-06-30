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

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

from .shared import (
    concrete_bytes_literal,
    get_symbolic_bytes,
    symbolic_bytes_literal,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Split, join, and partition symbolic bytes models."""


class BytesJoinModel(FunctionModel):
    """Model for bytes.join(iterable)."""

    name = "join"
    qualname = "bytes.join"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        iterable_error = _definite_join_iterable_error(args[1])
        if iterable_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=iterable_error)
        exact = _exact_join_result(args[0], args[1], state)
        if exact is not None:
            return exact
        result, constraint = SymbolicList.symbolic(f"bytes_join_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        return ModelResult(value=result, constraints=constraints)


class BytesSplitModel(FunctionModel):
    """Model for bytes.split(sep)."""

    name = "split"
    qualname = "bytes.split"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2, 3}
            or set(kwargs) - {"sep", "maxsplit"}
            or (len(args) > 1 and "sep" in kwargs)
            or (len(args) > 2 and "maxsplit" in kwargs)
        ):
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        b = get_symbolic_bytes(args[0], state) if args else None
        sep_arg = args[1] if len(args) > 1 else kwargs.get("sep")
        maxsplit_arg = args[2] if len(args) > 2 else kwargs.get("maxsplit")
        maxsplit_supplied = len(args) > 2 or "maxsplit" in kwargs
        if maxsplit_supplied:
            maxsplit_error = _definite_invalid_maxsplit_error(maxsplit_arg)
            if maxsplit_error is not None:
                return ModelResult.method_type_error(
                    self.qualname,
                    state,
                    message=maxsplit_error,
                )
        separator_error = _definite_invalid_separator_error(sep_arg)
        if separator_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=separator_error)
        if _has_exact_empty_separator(sep_arg):
            return _value_error_result("bytes_split", "empty separator", state)
        exact = _exact_bytes_split_result(args[0], sep_arg, maxsplit_arg, reverse=False)
        if exact is not None:
            return ModelResult(value=exact)
        result, constraint = SymbolicList.symbolic(f"bytes_split_{state.pc}")
        constraints = [constraint, result.z3_len >= 1]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len + 1)
        return ModelResult(value=result, constraints=constraints)


class BytesRsplitModel(FunctionModel):
    """Model for bytes.rsplit(sep)."""

    name = "rsplit"
    qualname = "bytes.rsplit"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2, 3}
            or set(kwargs) - {"sep", "maxsplit"}
            or (len(args) > 1 and "sep" in kwargs)
            or (len(args) > 2 and "maxsplit" in kwargs)
        ):
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        b = get_symbolic_bytes(args[0], state) if args else None
        sep_arg = args[1] if len(args) > 1 else kwargs.get("sep")
        maxsplit_arg = args[2] if len(args) > 2 else kwargs.get("maxsplit")
        maxsplit_supplied = len(args) > 2 or "maxsplit" in kwargs
        if maxsplit_supplied:
            maxsplit_error = _definite_invalid_maxsplit_error(maxsplit_arg)
            if maxsplit_error is not None:
                return ModelResult.method_type_error(
                    self.qualname,
                    state,
                    message=maxsplit_error,
                )
        separator_error = _definite_invalid_separator_error(sep_arg)
        if separator_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=separator_error)
        if _has_exact_empty_separator(sep_arg):
            return _value_error_result("bytes_rsplit", "empty separator", state)
        exact = _exact_bytes_split_result(args[0], sep_arg, maxsplit_arg, reverse=True)
        if exact is not None:
            return ModelResult(value=exact)
        result, constraint = SymbolicList.symbolic(f"bytes_rsplit_{state.pc}")
        constraints = [constraint, result.z3_len >= 1]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len + 1)
        return ModelResult(value=result, constraints=constraints)


def _exact_bytes_split_result(
    source_arg: StackValue,
    sep_arg: StackValue | None,
    maxsplit_arg: StackValue | None,
    *,
    reverse: bool,
) -> SymbolicList | None:
    source = concrete_bytes_literal(source_arg)
    if source is None:
        return None
    sep = None if _is_none_value(sep_arg) else concrete_bytes_literal(sep_arg)
    if sep_arg is not None and not _is_none_value(sep_arg) and sep is None:
        return None
    if sep == b"":
        return None
    maxsplit = _concrete_int(maxsplit_arg) if maxsplit_arg is not None else -1
    if maxsplit is None:
        return None
    parts = source.rsplit(sep, maxsplit) if reverse else source.split(sep, maxsplit)
    return SymbolicList.from_const([symbolic_bytes_literal(part) for part in parts])


def _definite_invalid_separator_error(value: object) -> str | None:
    if _is_none_value(value) or concrete_bytes_literal(value) is not None:
        return None
    type_name = _definite_type_name(value)
    if type_name in {"NoneType", "bytes", "bytearray"}:
        return None
    if type_name is None:
        return None
    return f"a bytes-like object is required, not '{type_name}'"


def _definite_invalid_required_separator_error(value: object) -> str | None:
    if concrete_bytes_literal(value) is not None:
        return None
    type_name = _definite_type_name(value)
    if type_name in {"bytes", "bytearray"}:
        return None
    if type_name is None:
        return None
    return f"a bytes-like object is required, not '{type_name}'"


def _definite_invalid_maxsplit_error(value: object) -> str | None:
    type_name = _definite_type_name(value)
    if type_name == "NoneType":
        return "'NoneType' object cannot be interpreted as an integer"
    if type_name in {"bool", "int"}:
        return None
    if type_name is None:
        return None
    return f"'{type_name}' object cannot be interpreted as an integer"


def _definite_type_name(value: object) -> str | None:
    if isinstance(value, SymbolicValue):
        if value.value is not None:
            return type(value.value).__name__
        if value.affinity_type != "unknown":
            if value.affinity_type == "none":
                return "NoneType"
            if value.affinity_type == "obj":
                return "object"
            return value.affinity_type
        if z3.is_true(value.is_none):
            return "NoneType"
        if z3.is_true(value.is_bool):
            return "bool"
        if z3.is_true(value.is_int):
            return "int"
        if z3.is_true(value.is_float):
            return "float"
        if z3.is_true(value.is_str):
            return "str"
        if z3.is_true(value.is_bytes):
            return "bytes"
        return None
    if isinstance(value, SymbolicNoneType) or value is None:
        return "NoneType"
    if isinstance(value, bytearray):
        return "bytearray"
    if concrete_bytes_literal(value) is not None:
        return getattr(value, "_type", None) or "bytes"
    return type(value).__name__


def _has_exact_empty_separator(sep_arg: StackValue | None) -> bool:
    return concrete_bytes_literal(sep_arg) == b""


def _is_none_value(value: object) -> bool:
    return (
        value is None
        or isinstance(value, SymbolicNoneType)
        or isinstance(value, SymbolicValue)
        and z3.is_true(value.is_none)
    )


def _concrete_int(value: object) -> int | None:
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _exact_join_result(
    separator_arg: StackValue,
    iterable_arg: StackValue,
    state: VMState,
) -> ModelResult | None:
    separator = concrete_bytes_literal(separator_arg)
    if separator is None:
        return None
    items = IterationSources.iterable_items(iterable_arg, state)
    if items is None:
        return None
    parts: list[bytes] = []
    for index, item in enumerate(items):
        part = concrete_bytes_literal(item)
        if part is None:
            message = _definite_invalid_join_item_error(index, item)
            if message is not None:
                return ModelResult.method_type_error("bytes.join", state, message=message)
            return None
        parts.append(part)
    return ModelResult(value=symbolic_bytes_literal(separator.join(parts)))


def _definite_join_iterable_error(value: object) -> str | None:
    type_name = _definite_type_name(value)
    if type_name in {"bool", "float", "int", "NoneType"}:
        return "can only join an iterable"
    return None


def _definite_invalid_join_item_error(index: int, value: object) -> str | None:
    type_name = _definite_type_name(value)
    if type_name in {"bytes", "bytearray"}:
        return None
    if type_name is None:
        return None
    return f"sequence item {index}: expected a bytes-like object, {type_name} found"


class BytesPartitionModel(FunctionModel):
    """Model for bytes.partition(sep)."""

    name = "partition"
    qualname = "bytes.partition"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        separator_error = _definite_invalid_required_separator_error(args[1])
        if separator_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=separator_error)
        if _has_exact_empty_separator(args[1]):
            return _value_error_result("bytes_partition", "empty separator", state)
        exact, is_exact = _exact_partition_result(args[0], args[1], reverse=False)
        if is_exact:
            if exact is None:
                return _value_error_result("bytes_partition", "empty separator", state)
            return ModelResult(
                value=SymbolicList.from_const([symbolic_bytes_literal(part) for part in exact]),
            )
        result, constraint = SymbolicList.symbolic(f"bytes_partition_{state.pc}")
        constraints = [constraint, result.z3_len == 3]
        return ModelResult(value=result, constraints=constraints)


class BytesRpartitionModel(FunctionModel):
    """Model for bytes.rpartition(sep)."""

    name = "rpartition"
    qualname = "bytes.rpartition"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        separator_error = _definite_invalid_required_separator_error(args[1])
        if separator_error is not None:
            return ModelResult.method_type_error(self.qualname, state, message=separator_error)
        if _has_exact_empty_separator(args[1]):
            return _value_error_result("bytes_rpartition", "empty separator", state)
        exact, is_exact = _exact_partition_result(args[0], args[1], reverse=True)
        if is_exact:
            if exact is None:
                return _value_error_result("bytes_rpartition", "empty separator", state)
            return ModelResult(
                value=SymbolicList.from_const([symbolic_bytes_literal(part) for part in exact]),
            )
        result, constraint = SymbolicList.symbolic(f"bytes_rpartition_{state.pc}")
        constraints = [constraint, result.z3_len == 3]
        return ModelResult(value=result, constraints=constraints)


class BytesSplitlinesModel(FunctionModel):
    """Model for bytes.splitlines()."""

    name = "splitlines"
    qualname = "bytes.splitlines"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2}
            or set(kwargs) - {"keepends"}
            or (len(args) > 1 and "keepends" in kwargs)
        ):
            return ModelResult.method_type_error(f"bytes.{self.name}", state)
        keepends_arg = args[1] if len(args) > 1 else kwargs.get("keepends")
        exact = _exact_splitlines_result(args[0], keepends_arg)
        if exact is not None:
            return ModelResult(value=exact)
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_splitlines_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


def _exact_partition_result(
    source_arg: StackValue,
    sep_arg: StackValue,
    *,
    reverse: bool,
) -> tuple[tuple[bytes, bytes, bytes] | None, bool]:
    source = concrete_bytes_literal(source_arg)
    sep = concrete_bytes_literal(sep_arg)
    if source is None or sep is None:
        return None, False
    if sep == b"":
        return None, True
    parts = source.rpartition(sep) if reverse else source.partition(sep)
    return parts, True


def _exact_splitlines_result(
    source_arg: StackValue,
    keepends_arg: StackValue | None,
) -> SymbolicList | None:
    source = concrete_bytes_literal(source_arg)
    if source is None:
        return None
    keepends = _concrete_truth(keepends_arg) if keepends_arg is not None else False
    if keepends is None:
        return None
    return SymbolicList.from_const(
        [symbolic_bytes_literal(part) for part in source.splitlines(keepends)],
    )


def _concrete_truth(value: object) -> bool | None:
    if isinstance(value, SymbolicValue):
        value = value.value
    if value is None:
        return False
    if isinstance(value, SymbolicList):
        items = value.concrete_items
        if items is None:
            return None
        return len(items) > 0
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value != 0
    if isinstance(value, str | bytes | bytearray):
        return len(value) > 0
    if isinstance(value, list | tuple | dict | set | frozenset):
        container = cast(
            "list[object] | tuple[object, ...] | dict[object, object] | set[object] | frozenset[object]",
            value,
        )
        return len(container) > 0
    return None


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
