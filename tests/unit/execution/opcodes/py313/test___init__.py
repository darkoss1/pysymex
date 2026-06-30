from __future__ import annotations

from types import ModuleType

import pysymex._internal.execution.opcodes.py311.async_generators as async_ops
import pysymex._internal.execution.opcodes.py313.arithmetic as arithmetic
import pysymex._internal.execution.opcodes.py313.collections as collections
import pysymex._internal.execution.opcodes.py313.compare as compare
import pysymex._internal.execution.opcodes.py313.control as control
import pysymex._internal.execution.opcodes.py313.exceptions as exceptions
import pysymex._internal.execution.opcodes.py313.formatting as formatting
import pysymex._internal.execution.opcodes.py313.functions as functions
import pysymex._internal.execution.opcodes.py313.locals as locals
import pysymex._internal.execution.opcodes.py313.stack as stack


def test_py313_opcode_modules_import_directly() -> None:
    modules = (
        arithmetic,
        async_ops,
        collections,
        compare,
        control,
        exceptions,
        functions,
        formatting,
        locals,
        stack,
    )
    assert all(isinstance(module, ModuleType) for module in modules)
