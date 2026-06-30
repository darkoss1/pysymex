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

"""Runtime generic-alias carriers for modeled classes.

This module owns the symbolic representation shared by PEP 695 ``SUBSCRIPT_GENERIC``
and runtime ``Class[T]`` subscripts. The carrier preserves constructor callability and
minimal CPython metadata without claiming full ``typing`` semantics.
"""

from __future__ import annotations

import copy
from typing import cast

from pysymex._internal.core.types.scalars.values import SymbolicValue


def modeled_runtime_generic_alias(
    origin: object,
    args: object,
    pc: int,
) -> SymbolicValue | None:
    """Return a callable generic-alias carrier for a modeled runtime class."""
    if not isinstance(origin, SymbolicValue):
        return None
    if getattr(origin, "affinity_type", None) != "type":
        return None

    alias = copy.copy(origin)
    alias.rename(f"{origin.name}[{_generic_alias_arg_name(args)}]_{pc}")
    alias.set_generic_alias_metadata(origin, generic_alias_args(args))
    return alias


def generic_alias_args(args: object) -> tuple[object, ...]:
    """Normalize generic alias arguments to CPython-like tuple metadata."""
    if isinstance(args, tuple):
        return cast("tuple[object, ...]", args)
    return (args,)


def _generic_alias_arg_name(args: object) -> str:
    """Return a stable short diagnostic label for generic alias arguments."""
    if isinstance(args, tuple):
        typed_args = cast("tuple[object, ...]", args)
        return ", ".join(_generic_alias_arg_name(item) for item in typed_args)
    name = getattr(args, "_name", None) or getattr(args, "name", None)
    if isinstance(name, str) and name:
        return name
    concrete_name = getattr(args, "__name__", None)
    if isinstance(concrete_name, str) and concrete_name:
        return concrete_name
    return type(args).__name__
