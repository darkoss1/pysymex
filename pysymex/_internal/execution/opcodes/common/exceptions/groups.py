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

"""Concrete ``ExceptionGroup`` matching helpers for ``except*`` opcode execution.

Evaluates whether a raised group matches ``except*`` type filters on concrete paths before
generic exception-handler lowering runs. Does not symbolically enumerate nested groups.
"""

from __future__ import annotations

import builtins
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.exceptions.policy import concrete_exception
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.exceptions.classes import raised_exception_class

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _symbolic_exception_payload(value: StackValue) -> SymbolicException | None:
    """Extract a :class:`SymbolicException` from a stack value or modeled wrapper."""
    payload = (
        value if isinstance(value, SymbolicException) else getattr(value, "_modeled_object", None)
    )
    return payload if isinstance(payload, SymbolicException) else None


def _concrete_exception_type(value: StackValue) -> type[BaseException] | None:
    """Resolve a concrete ``BaseException`` subclass from a type or symbolic name."""
    if isinstance(value, type) and issubclass(value, BaseException):
        return value
    if not isinstance(value, SymbolicValue):
        return None
    for name in (value.model_name, value.name):
        if not isinstance(name, str):
            continue
        candidate = getattr(builtins, name.rsplit(".", 1)[-1], None)
        if isinstance(candidate, type) and issubclass(candidate, BaseException):
            return candidate
    return None


def _members_from_payload(payload: SymbolicException, state: VMState) -> list[StackValue] | None:
    """Return concrete exception-group members from the payload's second argument."""
    if len(payload.args) != 2:
        return None
    members_obj = payload.args[1]
    if isinstance(members_obj, SymbolicObject) and members_obj.address != -1:
        resolved = state.memory.get(members_obj.address)
        if resolved is None:
            return None
        members_obj = resolved
    if isinstance(members_obj, SymbolicList):
        if members_obj.concrete_items is None:
            return None
        return cast("list[StackValue]", members_obj.concrete_items)
    if isinstance(members_obj, list):
        return cast("list[StackValue]", members_obj)
    if isinstance(members_obj, tuple):
        return list(cast("tuple[StackValue, ...]", members_obj))
    return None


def split_known_exception_group(
    group: StackValue,
    requested_type: StackValue,
    state: VMState,
) -> tuple[StackValue, StackValue] | None:
    """Return CPython stack outputs for a fully known uniform ``except*`` split."""
    payload = _symbolic_exception_payload(group)
    match_type = _concrete_exception_type(requested_type)
    if payload is None or match_type is None:
        return None
    if payload.exc_type not in {BaseExceptionGroup, ExceptionGroup}:
        return _split_direct_exception_for_except_star(group, payload, match_type)
    members = _members_from_payload(payload, state)
    if not members:
        return None

    match_results: list[bool] = []
    for member in members:
        member_payload = _symbolic_exception_payload(member)
        if member_payload is None or not isinstance(member_payload.exc_type, type):
            return None
        match_results.append(issubclass(member_payload.exc_type, match_type))

    if all(match_results):
        return SymbolicNoneType("eg_rest"), group
    if not any(match_results):
        return group, SymbolicNoneType("eg_match")
    matching_members = [
        member for member, matched in zip(members, match_results, strict=True) if matched
    ]
    rest_members = [
        member for member, matched in zip(members, match_results, strict=True) if not matched
    ]
    return (
        _exception_group_value(payload, rest_members, "eg_rest"),
        _exception_group_value(payload, matching_members, "eg_match"),
    )


def _split_direct_exception_for_except_star(
    group: StackValue,
    payload: SymbolicException,
    match_type: type[BaseException],
) -> tuple[StackValue, StackValue] | None:
    """Return CPython-shaped ``except*`` outputs for a direct modeled exception."""
    raised_type = raised_exception_class(group)
    if raised_type is None:
        return None
    wrapped_group = _single_member_exception_group_value(payload, group, "eg_direct", raised_type)
    if issubclass(raised_type, match_type):
        return SymbolicNoneType("eg_rest"), wrapped_group
    return group, SymbolicNoneType("eg_match")


def _exception_group_value(
    source: SymbolicException,
    members: list[StackValue],
    name: str,
) -> StackValue:
    """Build a retained symbolic exception group for one ``except*`` split side."""
    if not members:
        return SymbolicNoneType(name)
    message = source.args[0] if source.args else source.message or ""
    payload = concrete_exception(
        cast("type[BaseException]", source.exc_type),
        message,
        list(members),
        raised_at=source.raised_at,
    )
    value = SymbolicValue.from_const(payload)
    value.attach_modeled_object(payload)
    return value


def _single_member_exception_group_value(
    source: SymbolicException,
    member: StackValue,
    name: str,
    raised_type: type[BaseException],
) -> StackValue:
    """Wrap a direct modeled exception in the group shape bound by ``except*``."""
    group_type = ExceptionGroup if issubclass(raised_type, Exception) else BaseExceptionGroup
    message = source.message or source.type_name
    payload = concrete_exception(
        group_type,
        message,
        [member],
        raised_at=source.raised_at,
    )
    value = SymbolicValue.from_const(payload)
    value.attach_modeled_object(payload)
    return value
