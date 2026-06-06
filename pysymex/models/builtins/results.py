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

"""Result and side-effect types for builtin and stdlib models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, TypeAlias, TypedDict, TypeGuard, cast

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue


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


class PotentialExceptionEffect(TypedDict):
    """Structured metadata for potential modeled exceptions."""

    type: str
    message: str
    condition: z3.BoolRef


SideEffectValue: TypeAlias = (
    object
    | RaisedExceptionEffect
    | SinkEventEffect
    | AttributeMutationEffect
    | PotentialExceptionEffect
)


def new_side_effects() -> dict[str, SideEffectValue]:
    """Create an empty side-effects map."""
    return {}


def _is_str_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    """Return whether *value* is a dict used for model side-effect payloads."""
    return isinstance(value, dict)


def _is_str_object_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    """Return whether *value* can be queried as a side-effect mapping."""
    return isinstance(value, Mapping)


@dataclass(frozen=True, slots=True)
class ModelResult:
    """Result of a model application."""

    value: StackValue
    constraints: Sequence[z3.ExprRef | z3.BoolRef] = field(default_factory=tuple)
    side_effects: dict[str, SideEffectValue] = field(default_factory=new_side_effects)


def none_model_result(side_effects: dict[str, SideEffectValue] | None = None) -> ModelResult:
    """Return a model result for functions whose concrete return value is None."""
    from pysymex.core.types.base import SymbolicNoneType as SymbolicNone

    return ModelResult(value=SymbolicNone("none"), side_effects=side_effects or {})


def is_raised_exception_effect(value: object) -> TypeGuard[RaisedExceptionEffect]:
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


def is_sink_event_effect(value: object) -> TypeGuard[SinkEventEffect]:
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


def is_potential_exception_effect(value: object) -> TypeGuard[PotentialExceptionEffect]:
    """Return whether *value* has the potential-exception side-effect shape."""
    if not _is_str_object_mapping(value):
        return False
    exc_type = value.get("type")
    message = value.get("message")
    condition = value.get("condition")
    return (
        isinstance(exc_type, str) and isinstance(message, str) and isinstance(condition, z3.BoolRef)
    )


def is_potential_exception_effect_sequence(
    value: object,
) -> TypeGuard[Sequence[PotentialExceptionEffect]]:
    """Return whether *value* is a sequence of potential-exception side effects."""
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        return False
    for item in cast("Sequence[object]", value):
        if not is_potential_exception_effect(item):
            return False
    return True


__all__ = [
    "AttributeMutationEffect",
    "ModelResult",
    "PotentialExceptionEffect",
    "RaisedExceptionEffect",
    "SideEffectValue",
    "SinkEventEffect",
    "is_potential_exception_effect",
    "is_potential_exception_effect_sequence",
    "is_raised_exception_effect",
    "is_sink_event_effect",
    "new_side_effects",
    "none_model_result",
]
