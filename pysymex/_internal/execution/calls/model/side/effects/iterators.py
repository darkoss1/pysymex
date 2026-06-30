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

"""Iterator mutation side-effect application for model results."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.calls.model.side.effects.writes import record_modeled_item_write
from pysymex._internal.execution.calls.object.maps import as_mapping
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def apply_iterator_mutation_effect(
    state: VMState,
    args: list[StackValue],
    side_effects: dict[str, object],
) -> VMState:
    """Propagate a modeled iterator mutation to all aliases of the original iterator."""
    if "iterator_mutation" not in side_effects:
        return state
    mut = as_mapping(side_effects["iterator_mutation"])
    if mut is None:
        mut = {}
    original_iterator = mut.get("original_iterator")
    updated_iterator = mut.get("updated_iterator")
    if original_iterator is None or updated_iterator is None:
        return state

    write_target = args[0] if args else original_iterator
    state = record_modeled_item_write(state, write_target, mut.get("operation"))
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.aliases import (
        propagate_container_mutation_reference,
    )

    return propagate_container_mutation_reference(
        state,
        original_iterator,
        coerce_call_stack_value(updated_iterator),
    )


def apply_iterator_source_mutation_effects(
    state: VMState,
    side_effects: dict[str, object],
) -> VMState:
    """Propagate iterator source mutations recorded by exact iterator models."""
    source_mutations = side_effects.get("iterator_source_mutations")
    if not isinstance(source_mutations, list):
        return state
    for source_mutation in cast("list[object]", source_mutations):
        mut = as_mapping(source_mutation)
        if mut is None:
            continue
        original_iterator = mut.get("original_iterator")
        updated_iterator = mut.get("updated_iterator")
        if original_iterator is None or updated_iterator is None:
            continue
        from pysymex._internal.execution.opcodes.common.functions.classes.instances.aliases import (
            propagate_container_mutation_reference,
        )

        state = propagate_container_mutation_reference(
            state,
            original_iterator,
            coerce_call_stack_value(updated_iterator),
        )
    return state
