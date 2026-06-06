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

"""Memoryview and complex method builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from ..base import FunctionModel, ModelResult
from ..core.helpers import value_error_side_effect
from .helpers import type_error_side_effect


def _memoryview_type_error_result(qualname: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{qualname.replace('.', '_')}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=type_error_side_effect(qualname, f"{qualname}() received invalid arguments"),
    )


def _memoryview_value_error_result(qualname: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{qualname.replace('.', '_')}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=value_error_side_effect(qualname, message),
    )


class MemoryviewTobytesModel(FunctionModel):
    name = "tobytes"
    qualname = "memoryview.tobytes"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2}
            or set(kwargs) - {"order"}
            or (len(args) > 1 and "order" in kwargs)
        ):
            return _memoryview_type_error_result(self.qualname, state)
        order = args[1] if len(args) > 1 else kwargs.get("order")
        if order is not None and not isinstance(order, (str, SymbolicString)):
            return _memoryview_type_error_result(self.qualname, state)
        if isinstance(order, str) and order not in {"C", "F", "A"}:
            return _memoryview_value_error_result(
                self.qualname, "order must be 'C', 'F' or 'A'", state
            )
        result, constraint = SymbolicValue.symbolic(f"tobytes_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class MemoryviewTolistModel(FunctionModel):
    name = "tolist"
    qualname = "memoryview.tolist"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _memoryview_type_error_result(self.qualname, state)
        result, constraint = SymbolicList.symbolic(f"tolist_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len == 0])


class MemoryviewHexModel(FunctionModel):
    name = "hex"
    qualname = "memoryview.hex"

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
            return _memoryview_type_error_result(self.qualname, state)
        has_sep = len(args) > 1 or "sep" in kwargs
        sep = args[1] if len(args) > 1 else kwargs.get("sep")
        if has_sep and not isinstance(sep, (str, bytes, SymbolicString)):
            return _memoryview_type_error_result(self.qualname, state)
        if isinstance(sep, (str, bytes)) and len(sep) != 1:
            return _memoryview_value_error_result(self.qualname, "sep must be length 1.", state)
        bytes_per_sep = args[2] if len(args) > 2 else kwargs.get("bytes_per_sep")
        if bytes_per_sep is not None and not isinstance(bytes_per_sep, int):
            return _memoryview_type_error_result(self.qualname, state)
        result, constraint = SymbolicString.symbolic(f"hex_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class MemoryviewReleaseModel(FunctionModel):
    name = "release"
    qualname = "memoryview.release"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _memoryview_type_error_result(self.qualname, state)
        return ModelResult(value=None, constraints=[])


class MemoryviewCastModel(FunctionModel):
    name = "cast"
    qualname = "memoryview.cast"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            not args
            or len(args) > 3
            or set(kwargs) - {"format", "shape"}
            or (len(args) == 1 and "format" not in kwargs)
            or (len(args) > 1 and "format" in kwargs)
            or (len(args) > 2 and "shape" in kwargs)
        ):
            return _memoryview_type_error_result(self.qualname, state)
        format_value = args[1] if len(args) > 1 else kwargs["format"]
        if format_value is None or isinstance(
            format_value, (int, float, bool, bytes, list, tuple, dict, set)
        ):
            return _memoryview_type_error_result(self.qualname, state)
        return ModelResult(value=args[0], constraints=[])
