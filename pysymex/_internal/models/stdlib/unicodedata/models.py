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

"""Models for the unicodedata standard-library module."""

from __future__ import annotations

import unicodedata
from typing import TYPE_CHECKING, Literal, cast

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_string

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

NormalizationForm = Literal["NFC", "NFD", "NFKC", "NFKD"]


class UnicodeNormalizeModel(FunctionModel):
    """Model for unicodedata.normalize()."""

    name = "normalize"
    qualname = "unicodedata.normalize"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        form = const_string(args[0]) if args else None
        source = const_string(args[1]) if len(args) > 1 else None
        if form is not None and source is not None:
            try:
                normalized = unicodedata.normalize(cast("NormalizationForm", form), source)
                return ModelResult(value=SymbolicString.from_const(normalized))
            except ValueError:
                pass
        value, constraint = SymbolicString.symbolic(f"unicodedata_normalize_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


unicodedata_models: list[FunctionModel] = [UnicodeNormalizeModel()]
