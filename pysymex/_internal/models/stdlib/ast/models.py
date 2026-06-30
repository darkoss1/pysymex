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

import ast
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult
from pysymex._internal.models.stdlib.literals import (
    UNRESOLVED,
    binding_error,
    concrete_value,
    raised_exception,
    stack_value,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class AstLiteralEvalModel(FunctionModel):
    """Model exact literal evaluation without assuming one result shape."""

    name = "literal_eval"
    qualname = "ast.literal_eval"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        invalid = binding_error(ast.literal_eval, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid
        source = concrete_value(args[0])
        if source is UNRESOLVED and isinstance(args[0], ast.AST):
            source = args[0]
        if source is not UNRESOLVED:
            try:
                literal_eval = cast("Callable[[object], object]", ast.literal_eval)
                return ModelResult(value=stack_value(literal_eval(source)))
            except (SyntaxError, TypeError, ValueError) as exc:
                return raised_exception(self.qualname, exc)
        result, constraint = SymbolicValue.symbolic(f"literal_eval_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            degradations=[
                ModelDegradation(
                    kind="precision_loss",
                    label=self.qualname,
                    owner=type(self).__name__,
                    reason="literal type and value depend on symbolic source text",
                ),
            ],
        )


ast_models = [AstLiteralEvalModel()]
