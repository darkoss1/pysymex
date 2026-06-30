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

"""Default module globals for compile-only symbolic scans.

Provides builtins and modeled stdlib entries used when binding scan targets
without executing their module-level code.
"""

from __future__ import annotations

import zlib

from pysymex._internal.core.builtins import get_all_builtins
from pysymex._internal.core.solver.constraints.values import ConstraintValues


def _stable_module_address(module_name: str) -> int:
    """Return a reproducible concrete identity for a modeled stdlib module."""
    return zlib.crc32(module_name.encode("utf-8"))


def _default() -> dict[str, object]:
    """Provide a default global namespace for compile-only target loading.

    Initializes the namespace with default builtins from :func:`~pysymex._internal.core.builtins.get_all_builtins`,
    suppresses ``TYPE_CHECKING`` blocks (sets to ``False``), and populates common stdlib module names
    with symbolic placeholder objects to prevent attribute access crashes.

    Returns:
        A dictionary mapping global names to builtins and mock symbolic module objects.

    Limitations:
        These symbolic modules do not implement real module attributes or functions;
        they are basic fallback
        :class:`~pysymex._internal.core.types.containers.objects.SymbolicObject` instances.

    """
    from pysymex._internal.core.types.containers.objects import SymbolicObject

    defaults: dict[str, object] = {
        "TYPE_CHECKING": False,
    }
    defaults.update(get_all_builtins())

    common_modules = [
        "sys",
        "os",
        "functools",
        "re",
        "json",
        "math",
        "time",
        "random",
        "datetime",
        "io",
        "itertools",
        "collections",
        "pathlib",
        "abc",
        "typing",
    ]

    for mod_name in common_modules:
        addr = _stable_module_address(mod_name)
        obj = SymbolicObject(mod_name, addr, ConstraintValues.int(addr), {addr})
        defaults[mod_name] = obj

    return defaults


class ModuleGlobals:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    default = staticmethod(_default)
