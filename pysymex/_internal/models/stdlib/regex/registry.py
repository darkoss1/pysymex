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

"""Regex compile/escape models and model registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.regex.matching import (
    ReFullmatchModel,
    ReMatchModel,
    ReSearchModel,
)
from pysymex._internal.models.stdlib.regex.sequences import ReFindallModel, ReSplitModel, ReSubModel

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class ReCompileModel(FunctionModel):
    """Model for re.compile() - compile pattern.
    Returns a compiled pattern object (modeled symbolically).
    """

    name = "compile"
    qualname = "re.compile"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = args[0] if args else None
        result, constraint = SymbolicValue.symbolic(f"compiled_{state.pc}")
        if isinstance(pattern, str):
            result.pattern = pattern
        return ModelResult(
            value=result,
            constraints=[constraint],
        )


class ReEscapeModel(FunctionModel):
    """Model for re.escape() - escape special chars.
    Result length >= original length (only adds chars).
    """

    name = "escape"
    qualname = "re.escape"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = SymbolicString.resolve(args[0]) if args else None
        result, constraint = SymbolicString.symbolic(f"escape_{state.pc}")
        constraints = [constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


REGEX_MODELS: dict[str, FunctionModel] = {
    "re.match": ReMatchModel(),
    "re.search": ReSearchModel(),
    "re.fullmatch": ReFullmatchModel(),
    "re.findall": ReFindallModel(),
    "re.sub": ReSubModel(),
    "re.split": ReSplitModel(),
    "re.compile": ReCompileModel(),
    "re.escape": ReEscapeModel(),
}
