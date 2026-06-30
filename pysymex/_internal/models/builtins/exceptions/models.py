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

"""Exception type models for Python builtin exceptions.

Contains models for all Python builtin exception classes. These models
allow pysymex to handle isinstance(x, ValueError) and raise ValueError()
correctly without creating generic symbolic placeholders.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE
from pysymex._internal.core.exceptions.builtins import BUILTIN_EXCEPTIONS
from pysymex._internal.core.exceptions.policy import concrete_exception
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.models.contracts.types import TypeModel, TypeModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

_REQUIRED_POSITIONAL_COUNTS: dict[type[BaseException], int] = {
    BaseExceptionGroup: 2,
    ExceptionGroup: 2,
    UnicodeDecodeError: 5,
    UnicodeEncodeError: 5,
    UnicodeTranslateError: 4,
}

_UNKNOWN_CONCRETE = object()


def _exact_concrete_value(value: object, state: VMState | None = None) -> object:
    """Return retained literal payloads without solver-backed concretization."""
    if state is not None:
        value = SymbolicObject.resolve(value, state)
    if value is None or isinstance(value, (int, float, bool, str, bytes, list, dict, tuple)):
        return cast("object", value)
    if isinstance(value, SymbolicString):
        try:
            if z3.is_string_value(value.z3_str):
                return value.z3_str.as_string()
        except (AttributeError, z3.Z3Exception):
            return _UNKNOWN_CONCRETE
        return _UNKNOWN_CONCRETE
    if isinstance(value, SymbolicList):
        if value.concrete_items is None:
            return _UNKNOWN_CONCRETE
        return list(value.concrete_items)
    if isinstance(value, SymbolicValue):
        payload = value.value
        if payload is not None and isinstance(payload, (int, float, bool, str, bytes)):
            return payload
    return _UNKNOWN_CONCRETE


def _validate_unicode_constructor_args(
    exc_type: type[BaseException],
    args: list[StackValue],
    state: VMState,
) -> dict[str, object] | None:
    requirements: tuple[type[object] | tuple[type[object], ...], ...]
    if exc_type is UnicodeDecodeError:
        requirements = (str, bytes, int, int, str)
    elif exc_type is UnicodeEncodeError:
        requirements = (str, str, int, int, str)
    elif exc_type is UnicodeTranslateError:
        requirements = (str, int, int, str)
    else:
        return None

    for position, (value, expected) in enumerate(zip(args, requirements, strict=True), start=1):
        concrete_value = _exact_concrete_value(value, state)
        if concrete_value is not _UNKNOWN_CONCRETE and not isinstance(concrete_value, expected):
            return SideEffects.type_error(
                f"builtins.{exc_type.__name__}",
                f"{exc_type.__name__}() argument {position} has an invalid concrete type",
            )
    return None


def _validate_exception_group_args(
    exc_type: type[BaseException],
    args: list[StackValue],
    state: VMState,
) -> dict[str, object] | None:
    if exc_type not in {BaseExceptionGroup, ExceptionGroup}:
        return None
    message, members = args
    concrete_message = _exact_concrete_value(message, state)
    if concrete_message is not _UNKNOWN_CONCRETE and not isinstance(concrete_message, str):
        return SideEffects.type_error(
            f"builtins.{exc_type.__name__}",
            f"{exc_type.__name__}() message must be a string",
        )
    concrete_members = _exact_concrete_value(members, state)
    if isinstance(concrete_members, (list, tuple)):
        if not concrete_members:
            return SideEffects.value_error(
                f"builtins.{exc_type.__name__}",
                "second argument (exceptions) must be a non-empty sequence",
            )
        member_values = cast("list[object] | tuple[object, ...]", concrete_members)
        if any(
            _exact_concrete_value(member, state) is not _UNKNOWN_CONCRETE
            for member in member_values
        ):
            return SideEffects.value_error(
                f"builtins.{exc_type.__name__}",
                "second argument contains a definite non-exception value",
            )
    return None


class ExceptionTypeModel(TypeModel):
    """Model for Python exception type classes."""

    def __init__(self, exc_type: type[BaseException]) -> None:
        self.name = exc_type.__name__
        self.qualname = f"builtins.{exc_type.__name__}"
        self.python_type = exc_type
        self._exception_type = exc_type

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> TypeModelResult:
        """Apply the exception type model.

        Constructor calls return a symbolic exception instance. Type objects
        used as values (for example in isinstance()) are not invoked here.
        """
        required_count = _REQUIRED_POSITIONAL_COUNTS.get(self._exception_type)
        if kwargs or (required_count is not None and len(args) != required_count):
            result, constraint = SymbolicValue.symbolic(f"{self.name}_instance_{state.pc}")
            return TypeModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    f"builtins.{self.name}",
                    f"{self.name}() received invalid constructor arguments",
                ),
            )
        validation_effect = _validate_unicode_constructor_args(self._exception_type, args, state)
        if validation_effect is None:
            validation_effect = _validate_exception_group_args(self._exception_type, args, state)
        if validation_effect is not None:
            result, constraint = SymbolicValue.symbolic(f"{self.name}_instance_{state.pc}")
            return TypeModelResult(
                value=result,
                constraints=[constraint],
                side_effects=validation_effect,
            )
        result, constraint = SymbolicValue.symbolic(f"{self.name}_instance_{state.pc}")
        result.is_none = Z3_FALSE
        result.attach_modeled_object(concrete_exception(self._exception_type, *args, state=state))
        return TypeModelResult(value=result, constraints=[constraint])


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
