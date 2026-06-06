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

"""Python 3.13 opcode handler package root.

Re-exports version-specific handler modules registered with
:mod:`pysymex.execution.dispatch.dispatcher` for CPython 3.13 bytecode (``TO_BOOL``,
``SET_FUNCTION_ATTRIBUTE``, ``ENTER_EXECUTOR``, and unified ``JUMP``). Shared
semantics live under :mod:`pysymex.execution.opcodes.common`; async generator
opcodes load lazily from :mod:`pysymex.execution.opcodes.py311.async_generators`.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

from pysymex.execution.opcodes.py313 import (
    arithmetic,
    collections,
    compare,
    control,
    exceptions,
    formatting,
    functions,
    locals,
    stack,
)

async_ops: ModuleType


def __getattr__(name: str) -> object:
    """Lazily load the Python 3.11 async generator opcode module as ``async_ops``."""
    if name == "async_ops":
        return import_module("pysymex.execution.opcodes.py311.async_generators")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "arithmetic",
    "async_ops",
    "collections",
    "compare",
    "control",
    "exceptions",
    "formatting",
    "functions",
    "locals",
    "stack",
]
