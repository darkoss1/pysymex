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

"""Result and side-effect types shared by all symbolic models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, TypedDict, TypeGuard, cast

import z3

from pysymex._internal.core.exceptions.policy import (
    ExceptionType,
    exception_type_name,
    issue_kind_for_exception,
)
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class RaisedExceptionEffect(TypedDict):
    """Structured metadata for modeled exceptions raised by builtins."""

    issue_kind: str
    exception_type: str
    message: str
    source: str


class SinkEventEffect(TypedDict):
    """Structured metadata for dynamic-code sink usage."""

    sink_type: Literal["eval", "exec", "compile"]
    severity: Literal["info", "critical"]
    source: str


class AttributeMutationEffect(TypedDict):
    """Structured metadata for attribute mutation side effects."""

    target_index: int
    attr_name: str
    status: Literal["applied", "unknown"]
    source: str


class PotentialException(TypedDict):
    """Structured metadata for potential modeled exceptions."""

    type: str
    message: str
    condition: z3.BoolRef


SideEffectValue = (
    object | RaisedExceptionEffect | SinkEventEffect | AttributeMutationEffect | PotentialException
)

ModelConstraint = z3.ExprRef | z3.BoolRef

ModelDegradationKind = Literal["precision_loss", "unknown", "unsupported"]


@dataclass(frozen=True, slots=True)
class ModelDegradation:
    """Typed precision or soundness limitation produced by a model invocation."""

    kind: ModelDegradationKind
    label: str
    owner: str
    reason: str


def _is_str_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    """Return whether *value* is a dict used for model side-effect payloads."""
    return isinstance(value, dict)


def _is_str_object_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    """Return whether *value* can be queried as a side-effect mapping."""
    return isinstance(value, Mapping)


def _issue_kind_name(exc_type: ExceptionType, explicit: str | IssueKind | None = None) -> str:
    """Return a canonical model side-effect issue-kind label."""
    if isinstance(explicit, IssueKind):
        return explicit.name
    if isinstance(explicit, str) and explicit:
        return explicit
    return issue_kind_for_exception(exc_type).name


class SideEffects:
    """Domain owner for symbolic-model side-effect payloads."""

    @staticmethod
    def empty() -> dict[str, SideEffectValue]:
        """Create an empty side-effects map."""
        return {}

    @staticmethod
    def is_raised_exception(value: object) -> TypeGuard[RaisedExceptionEffect]:
        """Return whether *value* has the raised-exception side-effect shape."""
        if not _is_str_object_dict(value):
            return False
        issue_kind = value.get("issue_kind")
        exception_type = value.get("exception_type")
        message = value.get("message")
        source = value.get("source")
        return (
            isinstance(issue_kind, str)
            and isinstance(exception_type, str)
            and isinstance(message, str)
            and isinstance(source, str)
        )

    @staticmethod
    def is_sink_event(value: object) -> TypeGuard[SinkEventEffect]:
        """Return whether *value* has the dynamic sink-event side-effect shape."""
        if not _is_str_object_dict(value):
            return False
        sink_type = value.get("sink_type")
        severity = value.get("severity")
        source = value.get("source")
        return (
            sink_type in {"eval", "exec", "compile"}
            and severity in {"info", "critical"}
            and isinstance(source, str)
        )

    @staticmethod
    def is_potential_exception(value: object) -> TypeGuard[PotentialException]:
        """Return whether *value* has the potential-exception side-effect shape."""
        if not _is_str_object_mapping(value):
            return False
        exc_type = value.get("type")
        message = value.get("message")
        condition = value.get("condition")
        return (
            isinstance(exc_type, str)
            and isinstance(message, str)
            and isinstance(condition, z3.BoolRef)
        )

    @staticmethod
    def is_potential_exception_sequence(
        value: object,
    ) -> TypeGuard[Sequence[PotentialException]]:
        """Return whether *value* is a sequence of potential-exception side effects."""
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            return False
        for item in cast("Sequence[object]", value):
            if not SideEffects.is_potential_exception(item):
                return False
        return True

    @staticmethod
    def raised_exception(
        source: str,
        exc_type: ExceptionType,
        message: str,
        *,
        issue_kind: str | IssueKind | None = None,
    ) -> RaisedExceptionEffect:
        """Build canonical metadata for a definitely raised modeled exception."""
        return {
            "issue_kind": _issue_kind_name(exc_type, issue_kind),
            "exception_type": exception_type_name(exc_type),
            "message": message,
            "source": source,
        }

    @staticmethod
    def potential_exception(
        exc_type: ExceptionType,
        message: str,
        condition: z3.BoolRef,
    ) -> PotentialException:
        """Build canonical metadata for a conditionally raised modeled exception."""
        return {
            "type": exception_type_name(exc_type),
            "message": message,
            "condition": condition,
        }

    @staticmethod
    def with_raised_exception(
        issue_kind: str,
        exception_type: str,
        source: str,
        message: str,
    ) -> dict[str, SideEffectValue]:
        """Build the canonical side-effect map for a definitely raised exception."""
        return {
            "raised_exception": SideEffects.raised_exception(
                source,
                exception_type,
                message,
                issue_kind=issue_kind,
            ),
        }

    @staticmethod
    def from_native_exception(source: str, exc: BaseException) -> dict[str, SideEffectValue]:
        """Build canonical side effects for an exact host exception."""
        return {"raised_exception": SideEffects.raised_exception(source, type(exc), str(exc))}

    @staticmethod
    def type_error(source: str, message: str) -> dict[str, SideEffectValue]:
        """Build a canonical ``TypeError`` raised-exception side effect."""
        return SideEffects.with_raised_exception(
            IssueKind.TYPE_ERROR.name,
            "TypeError",
            source,
            message,
        )

    @staticmethod
    def value_error(source: str, message: str) -> dict[str, SideEffectValue]:
        """Build a canonical ``ValueError`` raised-exception side effect."""
        return SideEffects.with_raised_exception(
            IssueKind.VALUE_ERROR.name,
            "ValueError",
            source,
            message,
        )

    @staticmethod
    def zero_division_error(source: str, message: str) -> dict[str, SideEffectValue]:
        """Build a canonical ``ZeroDivisionError`` raised-exception side effect."""
        return SideEffects.with_raised_exception(
            IssueKind.DIVISION_BY_ZERO.name,
            "ZeroDivisionError",
            source,
            message,
        )


@dataclass(frozen=True, slots=True)
class ModelResult:
    """Result of a model application, including explicit analysis limitations."""

    value: StackValue
    constraints: Sequence[z3.ExprRef | z3.BoolRef] = field(default_factory=tuple)
    side_effects: dict[str, SideEffectValue] = field(default_factory=SideEffects.empty)
    degradations: Sequence[ModelDegradation] = field(default_factory=tuple)

    @classmethod
    def none(cls, side_effects: dict[str, SideEffectValue] | None = None) -> ModelResult:
        """Return a model result for functions whose concrete return value is None."""
        from pysymex._internal.core.types.base import SymbolicNoneType

        return cls(value=SymbolicNoneType("none"), side_effects=side_effects or {})

    @classmethod
    def symbolic_int(cls, name: str) -> tuple[SymbolicValue, list[ModelConstraint]]:
        """Create a symbolic int value with its base model constraints."""
        value, constraint = SymbolicValue.symbolic_int(name)
        return value, [constraint]

    @classmethod
    def symbolic_bool(cls, name: str) -> tuple[SymbolicValue, list[ModelConstraint]]:
        """Create a symbolic bool value with its base model constraints."""
        value, constraint = SymbolicValue.symbolic_bool(name)
        return value, [constraint]

    @classmethod
    def int(
        cls,
        name: str,
        extra_constraints: Sequence[ModelConstraint] = (),
        side_effects: dict[str, SideEffectValue] | None = None,
    ) -> ModelResult:
        """Return a model result for operations guaranteed to return int."""
        value, constraints = cls.symbolic_int(name)
        constraints.extend(extra_constraints)
        return cls(value=value, constraints=constraints, side_effects=side_effects or {})

    @classmethod
    def bool(
        cls,
        name: str,
        extra_constraints: Sequence[ModelConstraint] = (),
        side_effects: dict[str, SideEffectValue] | None = None,
    ) -> ModelResult:
        """Return a model result for operations guaranteed to return bool."""
        value, constraints = cls.symbolic_bool(name)
        constraints.extend(extra_constraints)
        return cls(value=value, constraints=constraints, side_effects=side_effects or {})

    @classmethod
    def method_type_error(
        cls,
        qualname: str,
        state: VMState,
        *,
        message: str | None = None,
    ) -> ModelResult:
        """Return a deterministic TypeError result for an invalid method call."""
        result, constraint = SymbolicValue.symbolic(
            f"{qualname.replace('.', '_')}_invalid_{state.pc}",
        )
        return cls(
            value=result,
            constraints=[constraint],
            side_effects=SideEffects.type_error(
                qualname,
                message or f"{qualname}() received invalid arguments",
            ),
        )
