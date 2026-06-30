from __future__ import annotations

from types import ModuleType

import pysymex._internal.execution.opcodes.py311.async_generators as async_ops
import pysymex._internal.execution.opcodes.py312.arithmetic as arithmetic
import pysymex._internal.execution.opcodes.py312.collections as collections
import pysymex._internal.execution.opcodes.py312.compare as compare
import pysymex._internal.execution.opcodes.py312.control as control
import pysymex._internal.execution.opcodes.py312.exceptions as exceptions
import pysymex._internal.execution.opcodes.py312.formatting as formatting
import pysymex._internal.execution.opcodes.py312.functions as functions
import pysymex._internal.execution.opcodes.py312.locals as locals
import pysymex._internal.execution.opcodes.py312.stack as stack


def test_py312_opcode_modules_import_directly() -> None:
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
