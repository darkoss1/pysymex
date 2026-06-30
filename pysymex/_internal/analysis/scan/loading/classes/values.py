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

"""Symbolic class values for compile-only scan loading."""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    import types


def bind_symbolic_class_values(
    class_names: set[str],
    plain_class_names: set[str],
    all_code_with_context: list[tuple[types.CodeType, str | None, str | None]],
    module_globals: dict[str, object],
) -> dict[str, SymbolicValue]:
    """Bind source class code objects as symbolic class values."""
    class_values: dict[str, SymbolicValue] = {}
    for code, _class_name, full_path in all_code_with_context:
        if not _is_top_level_class_code(code, class_names, full_path):
            continue
        class_val = SymbolicValue(
            _name=code.co_name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_obj=Z3_TRUE,
            is_none=Z3_FALSE,
            is_path=Z3_FALSE,
            affinity_type="type",
        )
        class_val.attach_modeled_object(code)
        if module_globals.get("functools") is functools:
            class_val.mark_trusted_cached_property()
        if code.co_name in plain_class_names:
            class_val.mark_plain_class_definition()
        module_globals.setdefault(code.co_name, class_val)
        class_values[code.co_name] = class_val
    return class_values


def _is_top_level_class_code(
    code: types.CodeType,
    class_names: set[str],
    full_path: str | None,
) -> bool:
    """Return whether *code* is the source body for a top-level class definition."""
    if code.co_name not in class_names or full_path is None:
        return False
    if full_path == code.co_name:
        return not code.co_freevars
    generic_path = f"<generic parameters of {code.co_name}>.{code.co_name}"
    return full_path == generic_path and code.co_freevars == (".type_params",)
