# pysymex: Python Symbolic Execution & Formal Verification
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

"""Python builtin utilities for symbolic execution.

Provides functions to get and manage Python builtin objects
for pre-populating VMState.global_vars.
"""

from __future__ import annotations

import builtins
from typing import Any

from pysymex.core.exceptions.analyzer import BUILTIN_EXCEPTIONS


def get_all_builtins() -> dict[str, Any]:
    """Get all Python builtin objects.

    Returns a dict mapping builtin names to their actual Python objects.
    This includes functions, types, exception classes, and constants.
    """
    builtin_dict: dict[str, Any] = {}

    for name in dir(builtins):
        if name.startswith("_"):
            continue
        builtin_dict[name] = getattr(builtins, name)

    for exc_type in BUILTIN_EXCEPTIONS:
        builtin_dict[exc_type.__name__] = exc_type

    builtin_dict["__build_class__"] = __build_class__
    builtin_dict["__import__"] = __import__

    builtin_dict["True"] = True
    builtin_dict["False"] = False
    builtin_dict["None"] = None
    builtin_dict["Ellipsis"] = Ellipsis
    builtin_dict["__debug__"] = __debug__

    return builtin_dict


def get_safe_builtins_for_symbolic_exec() -> dict[str, Any]:
    """Get safe builtins for symbolic execution.

    Similar to sandbox.get_safe_builtins() but for symbolic execution.
    Returns all builtins since symbolic execution doesn't execute
    dangerous functions - it models them symbolically.
    """
    return get_all_builtins()
