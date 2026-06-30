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

"""Extract concrete sequences and mappings retained by symbolic carriers."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Protocol, TypeGuard, cast

from pysymex._internal.core.types.containers.dicts import SymbolicDict

_modeled_instance_mapping_extractor: (
    Callable[[object], SymbolicDict | dict[object, object] | None] | None
) = None


def register_modeled_mapping_extractor(
    extractor: Callable[[object], SymbolicDict | dict[object, object] | None],
) -> None:
    """Register a callback to extract mapping data from modeled instances."""
    global _modeled_instance_mapping_extractor
    _modeled_instance_mapping_extractor = extractor


from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.guards import RuntimeObjectGuards


class ConcreteKeysMapping(Protocol):
    """Concrete mapping protocol CPython uses for dict unpacking."""

    def keys(self) -> object:
        """Return an iterable of mapping keys."""
        ...

    def __getitem__(self, key: object, /) -> object:
        """Return the value for *key* or raise the concrete lookup exception."""
        ...


class ConcreteExtractionPolicy:
    """Return concrete backing data for stack and modeled containers."""

    @staticmethod
    def has_keys_mapping_protocol(value: object) -> TypeGuard[ConcreteKeysMapping]:
        """Return true when *value* supports CPython's ``keys``/``__getitem__`` mapping path."""
        return callable(getattr(value, "keys", None)) and callable(
            getattr(value, "__getitem__", None),
        )

    @staticmethod
    def sequence(value: object) -> list[object] | tuple[object, ...] | None:
        """Return a concrete sequence backing a stack or modeled container."""
        if isinstance(value, SymbolicTuple):
            return value.elements
        if RuntimeObjectGuards.list(value) or RuntimeObjectGuards.tuple(value):
            return value
        if isinstance(value, SymbolicValue):
            modeled_object = getattr(value, "_modeled_object", None)
            if RuntimeObjectGuards.list(modeled_object) or RuntimeObjectGuards.tuple(
                modeled_object,
            ):
                return modeled_object
            const_value = value.value
            if RuntimeObjectGuards.list(const_value) or RuntimeObjectGuards.tuple(const_value):
                return const_value
        concrete_items = getattr(value, "_concrete_items", None)
        if RuntimeObjectGuards.list(concrete_items) or RuntimeObjectGuards.tuple(concrete_items):
            return concrete_items
        return None

    @staticmethod
    def mapping(value: object) -> SymbolicDict | dict[object, object] | None:
        """Return a symbolic or concrete mapping used for dict updates."""
        if isinstance(value, SymbolicDict):
            return value
        if RuntimeObjectGuards.dict(value):
            return dict(value)
        if isinstance(value, Mapping):
            return dict(cast("Mapping[object, object]", value))
        if ConcreteExtractionPolicy.has_keys_mapping_protocol(value):
            return _extract_keys_mapping(value)
        if isinstance(value, SymbolicValue):
            const_value = value.value
            if RuntimeObjectGuards.dict(const_value):
                return dict(const_value)
            if isinstance(const_value, Mapping):
                return dict(cast("Mapping[object, object]", const_value))
            if const_value is not None and ConcreteExtractionPolicy.has_keys_mapping_protocol(
                const_value,
            ):
                return _extract_keys_mapping(const_value)
            if _modeled_instance_mapping_extractor is not None:
                modeled_mapping = _modeled_instance_mapping_extractor(value)
                if modeled_mapping is not None:
                    return modeled_mapping
        concrete_items = getattr(value, "_concrete_items", None)
        if RuntimeObjectGuards.dict(concrete_items):
            return dict(concrete_items)
        return None


def _extract_keys_mapping(value: ConcreteKeysMapping) -> dict[object, object]:
    """Extract a concrete dict through CPython's ``keys``/``__getitem__`` protocol."""
    keys_obj = value.keys()
    try:
        key_iter = iter(cast("Iterable[object]", keys_obj))
    except TypeError as exc:
        owner_type = type(value).__name__
        keys_type = type(keys_obj).__name__
        msg = f"{owner_type}.keys() returned a non-iterable (type {keys_type})"
        raise TypeError(msg) from exc
    return {key: value[key] for key in key_iter}
