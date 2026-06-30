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

"""Effect write visibility and assigns-location alias checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from types import CellType, CodeType
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.effects.events import WriteEvent, WriteKind
from pysymex._internal.core.types.containers.objects import SymbolicObject

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


def visible_effect_events(
    events: Sequence[WriteEvent],
    visible_roots: frozenset[str],
) -> tuple[WriteEvent, ...]:
    """Return writes visible outside the contract frame."""
    return tuple(event for event in events if _event_is_visible(event, visible_roots))


def event_allowed_by_assigns(
    state: VMState,
    func: Callable[..., object],
    event: WriteEvent,
    allowed_locations: frozenset[str],
) -> bool:
    """Return whether *event* is permitted by a frame-condition location."""
    if event.location in allowed_locations:
        return True
    return any(
        _locations_are_same_global_alias(func, event.location, allowed_location)
        or _locations_are_same_closure_alias(func, event.location, allowed_location)
        or _locations_are_same_default_alias(state, func, event.location, allowed_location)
        for allowed_location in allowed_locations
    )


def _event_is_visible(event: WriteEvent, visible_roots: frozenset[str]) -> bool:
    """Return whether a modeled write can affect frame-entry state."""
    if event.kind is WriteKind.CLOSURE:
        return event.location in visible_roots
    if event.kind not in {WriteKind.ATTRIBUTE, WriteKind.ITEM}:
        return True
    root = _write_location_root(event.location)
    if root is None:
        return True
    if root.startswith(("global.", "closure.")):
        return True
    return root in visible_roots


def _locations_are_same_global_alias(
    func: Callable[..., object],
    observed_location: str,
    allowed_location: str,
) -> bool:
    """Return whether two global-rooted write locations name the same entry object."""
    observed = _global_location_parts(observed_location)
    allowed = _global_location_parts(allowed_location)
    if observed is None or allowed is None:
        return False
    observed_root, observed_suffix = observed
    allowed_root, allowed_suffix = allowed
    if observed_suffix != allowed_suffix:
        return False
    return _global_roots_are_entry_aliases(func, observed_root, allowed_root)


def _global_location_parts(location: str) -> tuple[str, str] | None:
    """Return the global root and suffix for a write location."""
    if not location.startswith("global."):
        return None
    tail = location[len("global.") :]
    item_marker = tail.find("[")
    attr_marker = tail.find(".")
    markers = [marker for marker in (item_marker, attr_marker) if marker != -1]
    root_end = min(markers) if markers else len(tail)
    if root_end <= 0:
        return None
    root = f"global.{tail[:root_end]}"
    return root, tail[root_end:]


def _global_roots_are_entry_aliases(
    func: Callable[..., object],
    observed_root: str,
    allowed_root: str,
) -> bool:
    """Return whether two global roots are definite aliases at function entry."""
    if observed_root == allowed_root:
        return True
    observed_name = observed_root.removeprefix("global.")
    allowed_name = allowed_root.removeprefix("global.")
    globals_map = _function_globals(func)
    if not globals_map:
        return False
    sentinel = object()
    observed_value = globals_map.get(observed_name, sentinel)
    allowed_value = globals_map.get(allowed_name, sentinel)
    if observed_value is sentinel or allowed_value is sentinel:
        return False
    if observed_value is not allowed_value:
        return False
    return isinstance(observed_value, (list, dict, set))


def _locations_are_same_closure_alias(
    func: Callable[..., object],
    observed_location: str,
    allowed_location: str,
) -> bool:
    """Return whether two closure-rooted locations name the same entry object."""
    observed = _closure_location_parts(observed_location)
    allowed = _closure_location_parts(allowed_location)
    if observed is None or allowed is None:
        return False
    observed_root, observed_suffix = observed
    allowed_root, allowed_suffix = allowed
    if observed_suffix != allowed_suffix:
        return False
    return _closure_roots_are_entry_aliases(func, observed_root, allowed_root)


def _closure_location_parts(location: str) -> tuple[str, str] | None:
    """Return a local/closure root and suffix for a write location."""
    if location.startswith("global."):
        return None
    root = location.removeprefix("closure.")
    item_marker = root.find("[")
    attr_marker = root.find(".")
    markers = [marker for marker in (item_marker, attr_marker) if marker != -1]
    root_end = min(markers) if markers else len(root)
    if root_end <= 0:
        return None
    return root[:root_end], root[root_end:]


def _closure_roots_are_entry_aliases(
    func: Callable[..., object],
    observed_root: str,
    allowed_root: str,
) -> bool:
    """Return whether two closure roots are definite aliases at function entry."""
    if observed_root == allowed_root:
        return True
    closure_values = _function_closure_values(func)
    if not closure_values:
        return False
    sentinel = object()
    observed_value = closure_values.get(observed_root, sentinel)
    allowed_value = closure_values.get(allowed_root, sentinel)
    if observed_value is sentinel or allowed_value is sentinel:
        return False
    if observed_value is not allowed_value:
        return False
    return isinstance(observed_value, (list, dict, set))


def _locations_are_same_default_alias(
    state: VMState,
    func: Callable[..., object],
    observed_location: str,
    allowed_location: str,
) -> bool:
    """Return whether two local-rooted locations alias through omitted defaults."""
    observed = _closure_location_parts(observed_location)
    allowed = _closure_location_parts(allowed_location)
    if observed is None or allowed is None:
        return False
    observed_root, observed_suffix = observed
    allowed_root, allowed_suffix = allowed
    if observed_suffix != allowed_suffix:
        return False
    return _default_roots_are_entry_aliases(state, func, observed_root, allowed_root)


def _default_roots_are_entry_aliases(
    state: VMState,
    func: Callable[..., object],
    observed_root: str,
    allowed_root: str,
) -> bool:
    """Return whether two parameter roots share one mutable default at entry."""
    if observed_root == allowed_root:
        return True
    default_values = _function_default_values(func)
    if not default_values:
        return False
    sentinel = object()
    observed_value = default_values.get(observed_root, sentinel)
    allowed_value = default_values.get(allowed_root, sentinel)
    if observed_value is sentinel or allowed_value is sentinel:
        return False
    if observed_value is not allowed_value:
        return False
    if not isinstance(observed_value, (list, dict, set)):
        return False
    return _local_roots_are_current_aliases(state, observed_root, allowed_root)


def _local_roots_are_current_aliases(
    state: VMState,
    observed_root: str,
    allowed_root: str,
) -> bool:
    """Return whether two local roots still identify the same modeled object."""
    observed_value = _current_local_root_value(state, observed_root)
    allowed_value = _current_local_root_value(state, allowed_root)
    if observed_value is None or allowed_value is None:
        return False
    return _same_modeled_identity(observed_value, allowed_value)


def _current_local_root_value(state: VMState, root: str) -> object | None:
    """Return the current modeled value for a local root."""
    root_name = root.removeprefix("closure.")
    value = state.local_vars.get(root_name)
    if value is None:
        return None
    return _cell_contents_for_value(state, value)


def _cell_contents_for_value(state: VMState, value: object) -> object:
    """Return closure-cell contents when *value* is a modeled cell object."""
    if not (isinstance(value, SymbolicObject) and value.name.startswith("cell_")):
        return value
    if value.address == -1:
        return value
    cell_value = state.memory.get(value.address)
    return value if cell_value is None else cell_value


def _same_modeled_identity(left: object, right: object) -> bool:
    """Return whether two stack values are the same modeled mutation target."""
    if left is right:
        return True
    if isinstance(left, SymbolicObject) and isinstance(right, SymbolicObject):
        return left.address != -1 and left.address == right.address
    return False


def _function_default_values(func: Callable[..., object]) -> Mapping[str, object]:
    """Return positional and keyword-only default values keyed by parameter name."""
    code = getattr(func, "__code__", None)
    if not isinstance(code, CodeType):
        return {}
    values: dict[str, object] = {}
    raw_defaults = getattr(func, "__defaults__", None)
    if isinstance(raw_defaults, tuple) and raw_defaults:
        defaults = cast("tuple[object, ...]", raw_defaults)
        positional_names = code.co_varnames[: code.co_argcount]
        default_offset = len(positional_names) - len(defaults)
        if default_offset >= 0:
            for index, value in enumerate(defaults):
                values[str(positional_names[default_offset + index])] = value
    raw_kwdefaults = getattr(func, "__kwdefaults__", None)
    if isinstance(raw_kwdefaults, Mapping):
        kwdefaults = cast("Mapping[object, object]", raw_kwdefaults)
        for name, value in kwdefaults.items():
            if isinstance(name, str):
                values[name] = value
    return values


def _function_closure_values(func: Callable[..., object]) -> Mapping[str, object]:
    """Return closure cell contents keyed by free-variable name."""
    code = getattr(func, "__code__", None)
    if not isinstance(code, CodeType):
        return {}
    raw_closure = getattr(func, "__closure__", None)
    if not isinstance(raw_closure, tuple):
        return {}
    closure = cast("tuple[CellType, ...]", raw_closure)
    values: dict[str, object] = {}
    for name, cell in zip(code.co_freevars, closure, strict=False):
        try:
            values[name] = cell.cell_contents
        except ValueError:
            continue
    return values


def _function_globals(func: Callable[..., object]) -> Mapping[str, object]:
    """Return the function global namespace when available."""
    raw_globals = getattr(func, "__globals__", {})
    if isinstance(raw_globals, Mapping):
        return cast("Mapping[str, object]", raw_globals)
    return {}


def _write_location_root(location: str) -> str | None:
    """Return the root segment of a write-event location."""
    if not location or location.startswith("*"):
        return None
    if location.startswith("global."):
        parts = location.split(".", 2)
        return ".".join(parts[:2]) if len(parts) >= 2 else location
    item_marker = location.find("[")
    attr_marker = location.find(".")
    markers = [marker for marker in (item_marker, attr_marker) if marker != -1]
    if not markers:
        return location
    return location[: min(markers)]
