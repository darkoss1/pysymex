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

"""Models for the codecs standard-library module."""

from __future__ import annotations

import codecs
from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_bytes, const_string

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class CodecsEncodeModel(FunctionModel):
    """Model for codecs.encode()."""

    name = "encode"
    qualname = "codecs.encode"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        source = const_string(args[0]) if args else None
        encoding = const_string(args[1]) if len(args) > 1 else "utf-8"
        if source is not None and encoding is not None:
            try:
                encoded = codecs.encode(source, encoding)
            except (LookupError, TypeError, ValueError):
                pass
            else:
                return ModelResult(value=SymbolicBytes.concrete(encoded))
        return ModelResult(value=SymbolicBytes.symbolic(f"codecs_encode_{state.pc}"))


class CodecsDecodeModel(FunctionModel):
    """Model for codecs.decode()."""

    name = "decode"
    qualname = "codecs.decode"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        source = const_bytes(args[0]) if args else None
        encoding = const_string(args[1]) if len(args) > 1 else "utf-8"
        if source is not None and encoding is not None:
            try:
                decoded = codecs.decode(source, encoding)
            except (LookupError, TypeError, ValueError):
                pass
            else:
                return ModelResult(value=SymbolicString.from_const(decoded))
        value, constraint = SymbolicString.symbolic(f"codecs_decode_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


codecs_models: list[FunctionModel] = [CodecsEncodeModel(), CodecsDecodeModel()]
