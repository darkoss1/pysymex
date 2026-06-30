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

"""Container mutation side-effect application for model results."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.calls.model.side.effects.writes import record_modeled_item_write
from pysymex._internal.execution.calls.object.maps import as_mapping
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def apply_list_mutation_effect(
    state: VMState,
    args: list[StackValue],
    side_effects: dict[str, object],
) -> VMState:
    """Propagate a modeled list mutation to all aliases of the original list."""
    if "list_mutation" not in side_effects:
        return state
    mut = as_mapping(side_effects["list_mutation"])
    if mut is None:
        mut = {}
    orig_lst = mut.get("original_list")
    updated_lst = mut.get("updated_list")
    if orig_lst is None or updated_lst is None:
        return state

    write_target = args[0] if args else orig_lst
    state = record_modeled_item_write(state, write_target, mut.get("operation"))
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.aliases import (
        propagate_list_mutation_reference,
    )

    return propagate_list_mutation_reference(
        state,
        orig_lst,
        coerce_call_stack_value(updated_lst),
    )


def apply_dict_mutation_effect(
    state: VMState,
    args: list[StackValue],
    side_effects: dict[str, object],
) -> VMState:
    """Propagate a modeled dictionary mutation to all aliases of the original dict."""
    if "dict_mutation" not in side_effects:
        return state
    mut = as_mapping(side_effects["dict_mutation"])
    if mut is None:
        mut = {}
    orig_dict = mut.get("original_dict")
    updated_dict = mut.get("updated_dict")
    if orig_dict is None or updated_dict is None:
        return state

    write_target = args[0] if args else orig_dict
    state = record_modeled_item_write(state, write_target, mut.get("operation"))
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.aliases import (
        propagate_container_mutation_reference,
    )

    return propagate_container_mutation_reference(
        state,
        orig_dict,
        coerce_call_stack_value(updated_dict),
    )


def apply_simple_item_mutation_effects(
    state: VMState,
    args: list[StackValue],
    side_effects: dict[str, object],
) -> VMState:
    """Record item writes for modeled mutations without alias replacement payloads."""
    for mutation_key in ("set_mutation", "bytearray_mutation"):
        if mutation_key not in side_effects:
            continue
        mut = as_mapping(side_effects[mutation_key])
        if mut is None:
            mut = {}
        write_target = args[0] if args else None
        if write_target is not None:
            state = record_modeled_item_write(state, write_target, mut.get("operation"))
    return state
