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

"""Canonical names for modeled VM write locations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


@dataclass(frozen=True, slots=True)
class WriteLocation:
    """Resolved write location plus whether alias ownership is precise."""

    name: str
    precise: bool


def global_write_location(name: str) -> WriteLocation:
    """Return the canonical location for a module/global variable write."""
    return WriteLocation(f"global.{name}", True)


def closure_write_location(name: str) -> WriteLocation:
    """Return the canonical location for a closure-cell write."""
    return WriteLocation(f"closure.{name}", True)


def attribute_write_location(state: VMState, obj: object, attr_name: str) -> WriteLocation:
    """Resolve an attribute write to a stable root-relative location."""
    root = _root_name_for_value(state, obj)
    if root is None:
        return WriteLocation(f"*.{attr_name}", False)
    return WriteLocation(f"{root}.{attr_name}", True)


def item_write_location(state: VMState, container: object) -> WriteLocation:
    """Resolve a container item write to a stable root-relative location."""
    root = _root_name_for_value(state, container)
    if root is None:
        return WriteLocation("*[*]", False)
    return WriteLocation(f"{root}[*]", True)


def _root_name_for_value(state: VMState, value: object) -> str | None:
    """Return a local/global root name for *value* without invoking user code."""
    for name, candidate in state.global_vars.items():
        if _same_identity(candidate, value):
            return f"global.{name}"
    modeled_root = modeled_write_root_name(value)
    if modeled_root is not None:
        return modeled_root
    for name, candidate in state.local_vars.items():
        if _same_identity(candidate, value):
            return str(name)
        if _cell_contents_same_identity(state, candidate, value):
            return str(name)
    return None


def modeled_write_root_name(value: object) -> str | None:
    """Return the intrinsic modeled write root for a heap/container value."""
    if isinstance(value, (SymbolicDict, SymbolicList, SymbolicObject)) and value.name:
        return str(value.name)
    return None


def _same_identity(left: object, right: object) -> bool:
    """Return whether two VM values identify the same modeled object."""
    if left is right:
        return True
    if isinstance(left, SymbolicObject) and isinstance(right, SymbolicObject):
        return left.address != -1 and left.address == right.address
    return False


def _cell_contents_same_identity(state: VMState, cell: object, value: object) -> bool:
    """Return whether a closure cell currently contains *value*."""
    if not (isinstance(cell, SymbolicObject) and cell.name.startswith("cell_")):
        return False
    if cell.address == -1:
        return False
    cell_value = state.memory.get(cell.address)
    return cell_value is not None and _same_identity(cell_value, value)
