# pysymex: Python Symbolic Execution & Formal Verification
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

"""Exception type models for Python builtin exceptions.

Contains models for all Python builtin exception classes. These models
allow pysymex to handle isinstance(x, ValueError) and raise ValueError()
correctly without creating generic symbolic placeholders.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.exceptions.analyzer import BUILTIN_EXCEPTIONS
from pysymex.core.types.scalars import SymbolicValue
from pysymex.models.builtins.types import TypeModel, TypeModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


class ExceptionTypeModel(TypeModel):
    """Model for Python exception type classes."""

    def __init__(self, exc_type: type[BaseException]) -> None:
        self.name = exc_type.__name__
        self.qualname = f"builtins.{exc_type.__name__}"
        self.python_type = exc_type

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> TypeModelResult:
        """
        Apply the exception type model.

        When instantiated (e.g., ValueError("message")), returns a symbolic
        value representing the exception. When used in isinstance(),
        the type object itself is returned for type checking.
        """
        if args or kwargs:
            result, constraint = SymbolicValue.symbolic(f"{self.name}_instance_{state.pc}")
            return TypeModelResult(value=result, constraints=[constraint])

        return TypeModelResult(value=self.python_type)


def create_exception_models() -> list[ExceptionTypeModel]:
    """Create TypeModel instances for all builtin exceptions."""
    models: list[ExceptionTypeModel] = []
    for exc_type in BUILTIN_EXCEPTIONS:
        models.append(ExceptionTypeModel(exc_type))
    return models


NotImplementedErrorModel = ExceptionTypeModel(NotImplementedError)
ValueErrorModel = ExceptionTypeModel(ValueError)
TypeErrorModel = ExceptionTypeModel(TypeError)
AssertionErrorModel = ExceptionTypeModel(AssertionError)
StopIterationModel = ExceptionTypeModel(StopIteration)
GeneratorExitModel = ExceptionTypeModel(GeneratorExit)
ZeroDivisionErrorModel = ExceptionTypeModel(ZeroDivisionError)
IndexErrorModel = ExceptionTypeModel(IndexError)
KeyErrorModel = ExceptionTypeModel(KeyError)
AttributeErrorModel = ExceptionTypeModel(AttributeError)
RuntimeErrorModel = ExceptionTypeModel(RuntimeError)
