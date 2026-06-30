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

from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.constructors.object import ModeledMemoryView
from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    concrete_bytes_literal,
    symbolic_bytes_literal,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult


def _exact_memoryview_bytes(receiver: StackValue) -> bytes | None:
    """Return exact bytes retained by a modeled memoryview receiver."""
    source: object = receiver
    if isinstance(receiver, SymbolicValue):
        payload = getattr(receiver, "_modeled_object", None)
        if isinstance(payload, ModeledMemoryView):
            source = payload.source
    if isinstance(source, bytearray):
        return bytes(source)
    return concrete_bytes_literal(source)


def _memoryview_value_error_result(qualname: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{qualname.replace('.', '_')}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=SideEffects.value_error(qualname, message),
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
            return ModelResult.method_type_error(self.qualname, state)
        order = args[1] if len(args) > 1 else kwargs.get("order")
        if order is not None and not isinstance(order, (str, SymbolicString)):
            return ModelResult.method_type_error(self.qualname, state)
        if isinstance(order, str) and order not in {"C", "F", "A"}:
            return _memoryview_value_error_result(
                self.qualname,
                "order must be 'C', 'F' or 'A'",
                state,
            )
        exact = _exact_memoryview_bytes(args[0])
        if exact is not None:
            return ModelResult(value=symbolic_bytes_literal(exact))
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
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_memoryview_bytes(args[0])
        if exact is not None:
            return ModelResult(value=SymbolicList.from_const(list(exact)))
        result, constraint = SymbolicList.symbolic(f"tolist_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


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
            return ModelResult.method_type_error(self.qualname, state)
        has_sep = len(args) > 1 or "sep" in kwargs
        sep = args[1] if len(args) > 1 else kwargs.get("sep")
        if has_sep and not isinstance(sep, (str, bytes, SymbolicString)):
            return ModelResult.method_type_error(self.qualname, state)
        if isinstance(sep, (str, bytes)) and len(sep) != 1:
            return _memoryview_value_error_result(self.qualname, "sep must be length 1.", state)
        bytes_per_sep = args[2] if len(args) > 2 else kwargs.get("bytes_per_sep")
        if bytes_per_sep is not None and not isinstance(bytes_per_sep, int):
            return ModelResult.method_type_error(self.qualname, state)
        exact = _exact_memoryview_bytes(args[0])
        if exact is not None:
            separator = sep if isinstance(sep, (str, bytes)) else None
            if separator is None:
                rendered = exact.hex()
            else:
                group_size = bytes_per_sep if isinstance(bytes_per_sep, int) else 1
                rendered = exact.hex(separator, group_size)
            return ModelResult(value=SymbolicString.from_const(rendered))
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
            return ModelResult.method_type_error(self.qualname, state)
        return ModelResult.none()


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
            return ModelResult.method_type_error(self.qualname, state)
        format_value = args[1] if len(args) > 1 else kwargs["format"]
        if format_value is None or isinstance(
            format_value,
            (int, float, bool, bytes, list, tuple, dict, set),
        ):
            return ModelResult.method_type_error(self.qualname, state)
        return ModelResult(value=args[0], constraints=[])
