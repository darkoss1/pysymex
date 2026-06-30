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

"""Alias replacement for modeled coroutine state transitions."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.opcodes.common.coroutines.objects import ModeledCoroutine

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def replace_coroutine_aliases(
    state: VMState,
    old: ModeledCoroutine,
    new: ModeledCoroutine,
) -> None:
    """Replace *old* coroutine references in locals, globals, and the stack."""
    for name, value in tuple(state.local_vars.items()):
        state = state.set_local(str(name), cast("StackValue", _replace_value(value, old, new)))
    for name, value in tuple(state.global_vars.items()):
        state = state.set_global(str(name), cast("StackValue", _replace_value(value, old, new)))
    state.stack = [cast("StackValue", _replace_value(value, old, new)) for value in state.stack]
    state.invalidate_cached_hash()


def _replace_value(value: object, old: ModeledCoroutine, new: ModeledCoroutine) -> object:
    """Recursively substitute *new* for *old* inside nested container values."""
    if value is old:
        return new
    if isinstance(value, ModeledCoroutine) and value.identity == old.identity:
        return new
    if isinstance(value, list):
        items = cast("list[object]", value)
        return [_replace_value(item, old, new) for item in items]
    if isinstance(value, tuple):
        items = cast("tuple[object, ...]", value)
        return tuple(_replace_value(item, old, new) for item in items)
    if isinstance(value, dict):
        items = cast("dict[object, object]", value)
        return {key: _replace_value(item, old, new) for key, item in items.items()}
    return value
