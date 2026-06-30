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

"""Retained protocol method names for dynamic attribute continuations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.base import SymbolicNoneType

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True, slots=True)
class AttributeLoadContinuation:
    """Retained ``LOAD_ATTR`` stack-layout metadata for protocol returns."""

    push_null: bool


GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS = frozenset(
    (
        "__descriptor_get_getattr_default__",
        "__getattribute_getattr_default__",
    ),
)
GETATTR_CHAINED_PROTOCOL_METHODS = frozenset(
    (
        "__descriptor_get_getattr__",
        "__getattribute_getattr__",
    ),
)
GETATTR_DEFAULT_PROTOCOL_METHODS = (
    frozenset(
        (
            "__descriptor_get_default__",
            "__getattr_default__",
            "__getattribute_default__",
            "__descriptor_hasattr__",
        ),
    )
    | GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS
)
GETATTR_ATTRIBUTE_ERROR_CHAIN_PROTOCOL_METHODS = (
    GETATTR_CHAINED_PROTOCOL_METHODS | GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS
)
ATTRIBUTE_LOAD_PROTOCOL_METHODS = frozenset(
    (
        "__descriptor_get__",
        "__descriptor_get_getattr__",
        "__getattr__",
        "__getattribute__",
        "__getattribute_getattr__",
    ),
)


def attribute_load_retained_operand(push_null: bool) -> StackValue | None:
    """Return retained metadata only when ``LOAD_ATTR`` needs method-call stack shape."""
    if not push_null:
        return None
    return cast("StackValue", AttributeLoadContinuation(push_null=True))


def complete_attribute_load_protocol_return(
    state: object,
    retained_operand: object,
    return_value: StackValue,
) -> bool:
    """Push a protocol attribute result using the original ``LOAD_ATTR`` call layout."""
    if not isinstance(retained_operand, AttributeLoadContinuation):
        return False
    from pysymex._internal.core.state.record import VMState

    if not isinstance(state, VMState):
        return False
    if retained_operand.push_null:
        state.push(SymbolicNoneType())
    state.push(return_value)
    return True
