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

"""Python 3.12 opcode handler package root.

Re-exports version-specific handler modules registered with
:mod:`pysymex.execution.dispatch.dispatcher` for CPython 3.12 bytecode (shorter jump
names, ``RETURN_CONST``, ``LOAD_SUPER_*``, and PEP 669 instrumented opcodes).
Shared semantics live under :mod:`pysymex.execution.opcodes.common`; async
generator opcodes reuse :mod:`pysymex.execution.opcodes.py311.async_generators`.
"""

from __future__ import annotations

from pysymex.execution.opcodes.py311 import async_generators as async_ops
from pysymex.execution.opcodes.py312 import (
    arithmetic,
    collections,
    compare,
    control,
    exceptions,
    functions,
    formatting,
    locals,
    stack,
)

__all__ = [
    "arithmetic",
    "async_ops",
    "collections",
    "compare",
    "control",
    "exceptions",
    "functions",
    "formatting",
    "locals",
    "stack",
]
