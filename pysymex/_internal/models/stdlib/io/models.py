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

"""Symbolic models for the io module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class StringIOModel(FunctionModel):
    """Model for io.StringIO()."""

    name = "StringIO"
    qualname = "io.StringIO"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"stringio_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class BytesIOModel(FunctionModel):
    """Model for io.BytesIO()."""

    name = "BytesIO"
    qualname = "io.BytesIO"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"bytesio_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IOReadModel(FunctionModel):
    """Model for file.read() / StringIO.read()."""

    name = "read"
    qualname = "io.read"
    aliases = ("file.read", "TextIO.read", "BinaryIO.read", "io.StringIO.read")

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"io_read_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IOWriteModel(FunctionModel):
    """Model for file.write() / StringIO.write()."""

    name = "write"
    qualname = "io.write"
    aliases = ("file.write", "TextIO.write", "BinaryIO.write", "io.StringIO.write")

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args and isinstance(args[0], SymbolicString):
            return ModelResult(
                value=SymbolicValue(
                    _name=f"written_{state.pc}",
                    z3_int=args[0].z3_len,
                    is_int=Z3_TRUE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                ),
            )
        result, constraint = SymbolicValue.symbolic_int(f"io_write_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_int >= 0])


class IOGetvalueModel(FunctionModel):
    """Model for StringIO.getvalue()."""

    name = "getvalue"
    qualname = "io.StringIO.getvalue"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"io_getvalue_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


io_models = [
    StringIOModel(),
    BytesIOModel(),
    IOReadModel(),
    IOWriteModel(),
    IOGetvalueModel(),
]
