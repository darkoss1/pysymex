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
from pysymex.models.builtins.core.iterator_items import concrete_iterable_items

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
            return bytes_type_error_result(self.name, state)
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
            return bytes_type_error_result(self.name, state)
        b = get_symbolic_bytes(args[0], state) if args else None
        sep_arg = args[1] if len(args) > 1 else kwargs.get("sep")
        maxsplit_arg = args[2] if len(args) > 2 else kwargs.get("maxsplit")
        if _has_exact_empty_separator(args[0], sep_arg):
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
            return bytes_type_error_result(self.name, state)
        b = get_symbolic_bytes(args[0], state) if args else None
        sep_arg = args[1] if len(args) > 1 else kwargs.get("sep")
        maxsplit_arg = args[2] if len(args) > 2 else kwargs.get("maxsplit")
        if _has_exact_empty_separator(args[0], sep_arg):
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
    sep = None if sep_arg is None else concrete_bytes_literal(sep_arg)
    if sep_arg is not None and sep is None:
        return None
    if sep == b"":
        return None
    maxsplit = _concrete_int(maxsplit_arg) if maxsplit_arg is not None else -1
    if maxsplit is None:
        return None
    parts = source.rsplit(sep, maxsplit) if reverse else source.split(sep, maxsplit)
    return SymbolicList.from_const([symbolic_bytes_literal(part) for part in parts])


def _has_exact_empty_separator(source_arg: StackValue, sep_arg: StackValue | None) -> bool:
    if sep_arg is None or concrete_bytes_literal(sep_arg) != b"":
        return False
    return (
        get_symbolic_bytes(source_arg) is not None or concrete_bytes_literal(source_arg) is not None
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
    items = concrete_iterable_items(iterable_arg, state)
    if items is None:
        return None
    parts: list[bytes] = []
    for item in items:
        part = concrete_bytes_literal(item)
        if part is None:
            if _definitely_not_bytes(item):
                return bytes_type_error_result("join", state)
            return None
        parts.append(part)
    return ModelResult(value=symbolic_bytes_literal(separator.join(parts)))


def _definitely_not_bytes(value: object) -> bool:
    if concrete_bytes_literal(value) is not None:
        return False
    if isinstance(value, SymbolicValue):
        return value.value is not None
    if isinstance(value, SymbolicList):
        return False
    return True


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
            return bytes_type_error_result(self.name, state)
        exact, is_exact = _exact_partition_result(args[0], args[1], reverse=False)
        if is_exact:
            if exact is None:
                return _value_error_result("bytes_partition", "empty separator", state)
            return ModelResult(
                value=SymbolicList.from_const([symbolic_bytes_literal(part) for part in exact])
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
            return bytes_type_error_result(self.name, state)
        exact, is_exact = _exact_partition_result(args[0], args[1], reverse=True)
        if is_exact:
            if exact is None:
                return _value_error_result("bytes_rpartition", "empty separator", state)
            return ModelResult(
                value=SymbolicList.from_const([symbolic_bytes_literal(part) for part in exact])
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
            return bytes_type_error_result(self.name, state)
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
        [symbolic_bytes_literal(part) for part in source.splitlines(keepends)]
    )


def _concrete_truth(value: object) -> bool | None:
    if isinstance(value, SymbolicValue):
        value = value.value
    if value is None:
        return False
    if isinstance(value, (bool, int, str, bytes)):
        return bool(value)
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
            }
        },
    )
