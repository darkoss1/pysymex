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

"""Symbolic models for ``ast`` parsing helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue


class AstLiteralEvalModel(FunctionModel):
    """Model the list-valued branch of ``ast.literal_eval`` results."""

    name = "literal_eval"
    qualname = "ast.literal_eval"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"literal_eval_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


ast_models = [AstLiteralEvalModel()]

__all__ = ["AstLiteralEvalModel", "ast_models"]
