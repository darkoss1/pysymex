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

"""Concrete-backed ``FOR_ITER`` branch handling."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.iteration.exit import (
    push_for_iter_exit_sentinel,
)
from pysymex._internal.execution.opcodes.common.control.iteration.items import (
    stack_value_from_concrete_iter_item,
)
from pysymex._internal.execution.opcodes.common.control.iteration.state import (
    state_with_iterator_update,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def dispatch_concrete_for_iter(
    state: VMState,
    iterator: StackValue,
    iterable: object,
    *,
    target_index: int,
    push_exit_sentinel: bool = True,
    pop_exit_iterator: bool = False,
) -> OpcodeResult | None:
    """Return exact ``FOR_ITER`` branches for concrete-backed iterables, if available."""
    idx = iterator.index if isinstance(iterator, SymbolicIterator) else 0
    concrete_items: Sequence[object] | None = None
    known_len: int | None = None

    if isinstance(iterator, SymbolicIterator):
        concrete_from_iterator = IterationSources.iterator_items(iterator, state)
        if concrete_from_iterator is not None:
            concrete_items = cast("Sequence[object]", concrete_from_iterator)
            known_len = len(concrete_from_iterator)
    if concrete_items is None and isinstance(iterable, SymbolicList):
        concrete_from_list = iterable.concrete_items
        if concrete_from_list is not None:
            concrete_items = cast("Sequence[object]", concrete_from_list)
            known_len = len(concrete_from_list)
    elif concrete_items is None and isinstance(iterable, (str, bytes, list, tuple)):
        concrete_items = cast("Sequence[object]", iterable)
        known_len = len(concrete_items)

    if concrete_items is None or known_len is None:
        return None

    if idx < known_len:
        stack_item = stack_value_from_concrete_iter_item(concrete_items[idx])
        continue_state = state.fork()
        if isinstance(iterator, SymbolicIterator):
            updated_iterator = iterator.advance()
            continue_state = state_with_iterator_update(
                continue_state,
                iterator,
                updated_iterator,
            )
            continue_state.pop()
            continue_state = continue_state.push(updated_iterator)
        continue_state = continue_state.push(stack_item)
        continue_state = continue_state.advance_pc()
        return OpcodeResult.branch([continue_state])

    exit_state = state.fork()
    if isinstance(iterator, SymbolicIterator):
        exit_state = state_with_iterator_update(
            exit_state,
            iterator,
            iterator.exhaust(),
        )
    exit_state = push_for_iter_exit_sentinel(
        exit_state,
        push_sentinel=push_exit_sentinel,
        pop_iterator=pop_exit_iterator,
    )
    exit_state = exit_state.set_pc(target_index)
    return OpcodeResult.branch([exit_state])
