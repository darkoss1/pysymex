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

"""Bounded class-body stack helpers for retained function metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import dis
    from collections.abc import Sequence

UNKNOWN_METADATA = object()


@dataclass(frozen=True, slots=True)
class NameToken:
    """A bounded symbolic stack token for a loaded name."""

    name: str


@dataclass(frozen=True, slots=True)
class ConstToken:
    """A bounded symbolic stack token for a loaded constant."""

    value: object


@dataclass(frozen=True, slots=True)
class ContractFactoryToken:
    """A bounded symbolic stack token for a contract decorator factory result."""

    name: str
    args: tuple[object, ...]


def previous_class_body_store_index(
    instructions: Sequence[dis.Instruction],
    before_index: int,
) -> int:
    """Return the previous class-body store index before *before_index*."""
    for index in range(before_index - 1, -1, -1):
        if instructions[index].opname in {"STORE_NAME", "STORE_GLOBAL"}:
            return index
    return -1


def build_tuple(stack: list[object], count: int) -> None:
    """Apply a bounded BUILD_TUPLE stack effect."""
    if count <= 0:
        stack.append(())
        return
    if len(stack) < count:
        stack.append(UNKNOWN_METADATA)
        return
    items = stack[-count:]
    del stack[-count:]
    if any(item is UNKNOWN_METADATA for item in items):
        stack.append(UNKNOWN_METADATA)
        return
    stack.append(tuple(items))
