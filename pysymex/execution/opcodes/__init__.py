"""Opcode handlers module.
This module imports all opcode handlers to ensure they are registered
with the global dispatcher when the module is loaded.
"""

from pysymex.execution.opcodes import (
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

__all__ = [
    "arithmetic",
    "async_ops",
    "collections",
    "compare",
    "control",
    "exceptions",
    "functions",
    "locals",
    "stack",
]
