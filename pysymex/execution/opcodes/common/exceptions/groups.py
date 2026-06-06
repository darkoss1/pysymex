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

from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue


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
    group: StackValue, requested_type: StackValue, state: VMState
) -> tuple[StackValue, StackValue] | None:
    """Return CPython stack outputs for a fully known uniform ``except*`` split."""
    payload = _symbolic_exception_payload(group)
    match_type = _concrete_exception_type(requested_type)
    if (
        payload is None
        or match_type is None
        or payload.exc_type not in {BaseExceptionGroup, ExceptionGroup}
    ):
        return None
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
        return SymbolicNone("eg_rest"), group
    if not any(match_results):
        return group, SymbolicNone("eg_match")
    return None
