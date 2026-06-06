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

"""Runtime annotation normalization for scanner symbolic variables.

Normalizes runtime ``__annotations__`` or symbolic properties of targeted
functions, merging them into string-based type-hint dictionaries for subsequent
symbolic variable creation in :mod:`pysymex.scanner.symbolic_vars`.
"""

from __future__ import annotations

from pysymex.config import is_object_dict
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue


def merge_runtime_annotations(hints: dict[str, str], func_val: object) -> None:
    """Merge runtime annotation values into scanner type-hint strings.

    Extracts annotations from the provided object and resolves them to string
    representations. Supports standard typing annotations, types, symbolic strings,
    and fallback string representations.

    Args:
        hints: The target dictionary to update with resolved annotation strings in-place.
        func_val: The callable or object from which to extract ``__annotations__``.

    Side Effects:
        Mutates the ``hints`` dictionary in-place.
    """
    annotations = getattr(func_val, "__annotations__", None)
    if annotations is None and isinstance(func_val, SymbolicValue):
        annotations = getattr(func_val, "annotations", None)
    if not is_object_dict(annotations):
        return
    for key_obj, value in annotations.items():
        if not isinstance(key_obj, str):
            continue
        key = key_obj
        if isinstance(value, str):
            hints[key] = value
            continue
        if isinstance(value, SymbolicString):
            symbolic_name = value.name.strip()
            if symbolic_name:
                hints[key] = symbolic_name
            continue
        if isinstance(value, type):
            hints[key] = value.__name__
            continue
        hints[key] = str(value)
