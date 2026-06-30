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

"""Models for the textwrap standard-library module."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_string

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class TextwrapDedentModel(FunctionModel):
    """Model for textwrap.dedent()."""

    name = "dedent"
    qualname = "textwrap.dedent"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        source = const_string(args[0]) if args else None
        if source is not None:
            return ModelResult(value=SymbolicString.from_const(textwrap.dedent(source)))
        value, constraint = SymbolicString.symbolic(f"textwrap_dedent_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


class TextwrapShortenModel(FunctionModel):
    """Model for textwrap.shorten()."""

    name = "shorten"
    qualname = "textwrap.shorten"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        source = const_string(args[0]) if args else None
        width = kwargs.get("width")
        if source is not None and isinstance(width, int):
            return ModelResult(
                value=SymbolicString.from_const(textwrap.shorten(source, width=width)),
            )
        value, constraint = SymbolicString.symbolic(f"textwrap_shorten_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


textwrap_models: list[FunctionModel] = [TextwrapDedentModel(), TextwrapShortenModel()]
