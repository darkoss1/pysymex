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

"""Pre-state scalar snapshots used by postcondition ``old()`` terms.

This module owns the contract binding boundary between VM frame-local values and
predicate compiler symbols. Snapshot collection is intentionally conservative:
only scalar values with a stable Z3 projection are exposed to ``old()``. Heap
objects, containers, and object identities are left unbound so postconditions are
reported as unsupported instead of treating mutable aliases as immutable values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

import z3

from pysymex._internal.core.effects.locations import modeled_write_root_name
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

_OLD_SYMBOL_PREFIX: Final = "__old_"
_OLD_SYMBOL_SUFFIX: Final = "__"


def _empty_old_symbols() -> Mapping[str, z3.ExprRef]:
    """Return an immutable empty old-symbol mapping."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class RuntimeContractFrame:
    """Runtime frame identifying the function and entry snapshots for returns."""

    function: Callable[..., object]
    old_symbols: Mapping[str, z3.ExprRef] = field(default_factory=_empty_old_symbols)
    effect_start_index: int = 0
    effect_visible_roots: frozenset[str] = frozenset()


def old_symbol_name(source_name: str) -> str:
    """Return the compiler-context key used for ``old(<source_name>)``."""
    return f"{_OLD_SYMBOL_PREFIX}{source_name}{_OLD_SYMBOL_SUFFIX}"


def is_old_symbol_name(name: str) -> bool:
    """Return whether ``name`` is an internal old-symbol compiler key."""
    return name.startswith(_OLD_SYMBOL_PREFIX) and name.endswith(_OLD_SYMBOL_SUFFIX)


def scalar_snapshot_expression(value: object) -> z3.ExprRef | None:
    """Return a stable scalar expression for ``old()`` or ``None`` if unsupported."""
    if isinstance(value, bool):
        return ConstraintValues.bool(value)
    if isinstance(value, int):
        return ConstraintValues.int(value)
    if isinstance(value, str):
        return ConstraintValues.string(value)
    if isinstance(value, z3.BoolRef):
        return value
    if isinstance(value, z3.ArithRef) and value.sort().kind() == z3.Z3_INT_SORT:
        return value
    if isinstance(value, z3.SeqRef):
        return value
    if isinstance(value, SymbolicString):
        return value.z3_str
    if isinstance(value, SymbolicValue):
        affinity = value.affinity_type
        if affinity == "int":
            return value.z3_int
        if affinity == "bool":
            return value.z3_bool
        if affinity == "str":
            return value.z3_str
    return None


def length_snapshot_expression(value: object, memory: object | None = None) -> z3.ArithRef | None:
    """Return a stable collection/string length expression when one is modeled."""
    resolved = _resolve_heap_value(value, memory)
    if isinstance(resolved, (str, bytes)):
        return ConstraintValues.int(len(resolved))
    if isinstance(resolved, tuple):
        return ConstraintValues.int(len(cast("tuple[object, ...]", resolved)))
    if isinstance(resolved, list):
        return ConstraintValues.int(len(cast("list[object]", resolved)))
    if isinstance(resolved, dict):
        return ConstraintValues.int(len(cast("dict[object, object]", resolved)))
    if isinstance(resolved, (set, frozenset)):
        return ConstraintValues.int(len(cast("set[object] | frozenset[object]", resolved)))
    if isinstance(resolved, SymbolicString):
        return resolved.z3_len
    if isinstance(resolved, SymbolicValue):
        retained_value: object = resolved.value
        if isinstance(retained_value, (set, frozenset)):
            retained_set = cast("set[object] | frozenset[object]", retained_value)
            return ConstraintValues.int(len(retained_set))
    if isinstance(resolved, (SymbolicList, SymbolicDict)):
        return resolved.z3_len
    return None


def collect_current_derived_symbols(
    local_vars: Mapping[str, object],
    memory: object | None = None,
) -> Mapping[str, z3.ExprRef]:
    """Collect current-frame length and shallow scalar-attribute symbols."""
    symbols: dict[str, z3.ExprRef] = {}
    for name in sorted(local_vars):
        value = local_vars[name]
        length_expr = length_snapshot_expression(value, memory)
        if length_expr is not None:
            symbols[f"len_{name}"] = length_expr
        for attr_name, attr_value in _shallow_attribute_values(value, memory):
            expr = scalar_snapshot_expression(attr_value)
            if expr is not None:
                symbols[f"{name}.{attr_name}"] = expr
    return MappingProxyType(symbols)


def collect_result_derived_symbols(
    return_value: object,
    memory: object | None = None,
) -> Mapping[str, z3.ExprRef]:
    """Collect length symbols for supported return-value aliases."""
    length_expr = length_snapshot_expression(return_value, memory)
    if length_expr is None:
        return _empty_old_symbols()
    return MappingProxyType(
        {
            "len_return": length_expr,
            "len___return__": length_expr,
            "len___result__": length_expr,
            "len_result": length_expr,
        },
    )


def collect_scalar_old_symbols(
    local_vars: Mapping[str, object],
    memory: object | None = None,
) -> Mapping[str, z3.ExprRef]:
    """Collect immutable old-symbol bindings for supported scalar locals."""
    symbols: dict[str, z3.ExprRef] = {}
    for name in sorted(local_vars):
        value = local_vars[name]
        expr = scalar_snapshot_expression(value)
        if expr is not None:
            symbols[old_symbol_name(name)] = expr
        length_expr = length_snapshot_expression(value, memory)
        if length_expr is not None:
            symbols[old_symbol_name(f"len({name})")] = length_expr
        for attr_name, attr_value in _shallow_attribute_values(value, memory):
            attr_expr = scalar_snapshot_expression(attr_value)
            if attr_expr is not None:
                symbols[old_symbol_name(f"{name}.{attr_name}")] = attr_expr
    return MappingProxyType(symbols)


def runtime_contract_frame(
    function: Callable[..., object],
    local_vars: Mapping[str, object],
    memory: object | None = None,
    *,
    effect_start_index: int = 0,
    closure_visible_names: frozenset[str] = frozenset(),
) -> RuntimeContractFrame:
    """Build a return-time contract frame from current entry locals."""
    return RuntimeContractFrame(
        function=function,
        old_symbols=collect_scalar_old_symbols(local_vars, memory),
        effect_start_index=effect_start_index,
        effect_visible_roots=_effect_visible_roots(local_vars, closure_visible_names),
    )


def runtime_frame_parts(
    frame: object,
) -> tuple[Callable[..., object], Mapping[str, z3.ExprRef], int, frozenset[str]] | None:
    """Return the function and old-symbols carried by a contract frame."""
    if isinstance(frame, RuntimeContractFrame):
        return (
            frame.function,
            frame.old_symbols,
            frame.effect_start_index,
            frame.effect_visible_roots,
        )
    if callable(frame):
        return frame, _empty_old_symbols(), 0, frozenset()
    return None


def _effect_visible_roots(
    local_vars: Mapping[str, object],
    closure_visible_names: frozenset[str],
) -> frozenset[str]:
    """Return local and modeled roots visible at effect-frame entry."""
    roots: set[str] = set()
    for name in closure_visible_names:
        roots.add(name)
        roots.add(f"closure.{name}")
    for name, value in local_vars.items():
        root_name = str(name)
        roots.add(root_name)
        modeled_root = modeled_write_root_name(value)
        if modeled_root is not None:
            roots.add(modeled_root)
        if isinstance(value, SymbolicObject) and value.name.startswith("cell_"):
            roots.add(f"closure.{root_name}")
    return frozenset(roots)


def _resolve_heap_value(value: object, memory: object | None) -> object:
    """Resolve fixed-address object handles through VM memory when available."""
    if not isinstance(value, SymbolicObject) or value.address == -1 or memory is None:
        return value
    getter = getattr(memory, "get", None)
    if not callable(getter):
        return value
    resolved = getter(value.address)
    return value if resolved is None else resolved


def _shallow_attribute_values(
    value: object,
    memory: object | None,
) -> tuple[tuple[str, object], ...]:
    """Return scalar-candidate attributes without invoking user code."""
    resolved = _resolve_heap_value(value, memory)
    items = _string_key_items(resolved)
    if items:
        return items
    modeled_object = getattr(resolved, "_modeled_object", None)
    attrs = getattr(modeled_object, "attrs", None)
    return _string_key_items(attrs)


def _string_key_items(value: object) -> tuple[tuple[str, object], ...]:
    """Return mapping-like items whose keys are strings."""
    items_method = getattr(value, "items", None)
    if not callable(items_method):
        return ()
    typed_items = cast("Callable[[], Iterable[tuple[object, object]]]", items_method)
    return tuple((key, item_value) for key, item_value in typed_items() if isinstance(key, str))
