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

"""Models for the lzma standard-library module."""

from __future__ import annotations

import lzma
from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_bytes

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class LzmaCompressModel(FunctionModel):
    """Model for lzma.compress()."""

    name = "compress"
    qualname = "lzma.compress"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        data = const_bytes(args[0]) if args else None
        if data is not None:
            try:
                return ModelResult(value=SymbolicBytes.concrete(lzma.compress(data)))
            except (LZMAError, ValueError):
                pass
        return ModelResult(value=SymbolicBytes.symbolic(f"lzma_compress_{state.pc}"))


class LzmaDecompressModel(FunctionModel):
    """Model for lzma.decompress()."""

    name = "decompress"
    qualname = "lzma.decompress"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        data = const_bytes(args[0]) if args else None
        if data is not None:
            try:
                return ModelResult(value=SymbolicBytes.concrete(lzma.decompress(data)))
            except LZMAError:
                pass
        return ModelResult(value=SymbolicBytes.symbolic(f"lzma_decompress_{state.pc}"))


LZMAError = lzma.LZMAError
lzma_models: list[FunctionModel] = [LzmaCompressModel(), LzmaDecompressModel()]
