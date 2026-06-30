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

"""Module-global merge helpers for source scan execution passes."""

from __future__ import annotations

import types

from pysymex._internal.core.types.scalars.values import SymbolicValue


def merge_module_execution_globals(
    module_globals: dict[str, object],
    final_locals: dict[str, object],
) -> None:
    """Merge module execution locals without losing concrete top-level functions."""
    for name, value in final_locals.items():
        existing = module_globals.get(name)
        if isinstance(existing, types.FunctionType):
            modeled_object = getattr(value, "_modeled_object", None)
            if isinstance(modeled_object, types.CodeType):
                continue
        if isinstance(existing, SymbolicValue) and isinstance(value, SymbolicValue):
            init_hints = existing.init_type_hints
            if init_hints is not None:
                value.set_init_type_hints(init_hints)
            if existing.plain_class_definition:
                value.mark_plain_class_definition()
        module_globals[name] = value
