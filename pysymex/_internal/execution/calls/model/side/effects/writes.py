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

"""Write-ledger helpers for model side-effect application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.effects.events import WriteEvent, WriteKind
from pysymex._internal.core.effects.locations import attribute_write_location, item_write_location

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

PRECISE_WRITE_SIDE_EFFECT_KEYS: frozenset[str] = frozenset(
    (
        "attribute_mutation",
        "bytearray_mutation",
        "dict_mutation",
        "iterator_mutation",
        "list_mutation",
        "set_mutation",
    ),
)


def record_modeled_item_write(state: VMState, target: object, operation: object) -> VMState:
    """Record an effect-ledger write for a modeled mutating container method."""
    location = item_write_location(state, target)
    source = f"model.{operation}" if isinstance(operation, str) and operation else "model.mutation"
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, source),
    )


def record_modeled_attribute_write(
    state: VMState,
    args: list[StackValue],
    mutation: dict[str, object],
) -> VMState:
    """Record an effect-ledger write for a modeled attribute mutation."""
    raw_target_index = mutation.get("target_index", 0)
    target_index = raw_target_index if isinstance(raw_target_index, int) else 0
    if not 0 <= target_index < len(args):
        return state

    attr_name = mutation.get("attr_name")
    attr_name_str = attr_name if isinstance(attr_name, str) and attr_name else "<dynamic>"
    source = mutation.get("source")
    source_str = source if isinstance(source, str) and source else "model.attribute_mutation"

    location = attribute_write_location(state, args[target_index], attr_name_str)
    return state.record_write_event(
        WriteEvent(WriteKind.ATTRIBUTE, location.name, state.pc, location.precise, source_str),
    )


def has_precise_write_side_effect(side_effects: dict[str, object]) -> bool:
    """Return whether model side effects already carry a precise write payload."""
    return any(key in side_effects for key in PRECISE_WRITE_SIDE_EFFECT_KEYS)


def record_generic_mutates_arg_write(
    state: VMState,
    args: list[StackValue],
    raw_index: object,
) -> VMState:
    """Record a conservative write for models that only declare ``mutates_arg``."""
    if not isinstance(raw_index, int) or not 0 <= raw_index < len(args):
        return state
    location = item_write_location(state, args[raw_index])
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, "model.mutates_arg"),
    )
