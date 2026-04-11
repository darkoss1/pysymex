# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Opcode handlers module.
This module imports all opcode handlers to ensure they are registered
with the global dispatcher when the module is loaded.
"""

import sys

from pysymex.execution.opcodes.base import (
    arithmetic,
    async_ops,
    collections,
    compare,
    control,
    exceptions,
    functions,
    locals,
    stack,
)

if sys.version_info >= (3, 13):
    from pysymex.execution.opcodes import py313 as py_version
elif sys.version_info >= (3, 12):
    from pysymex.execution.opcodes import py312 as py_version
else:
    from pysymex.execution.opcodes import py311 as py_version

__all__ = [
    "arithmetic",
    "async_ops",
    "collections",
    "compare",
    "control",
    "exceptions",
    "functions",
    "locals",
    "py_version",
    "stack",
]
