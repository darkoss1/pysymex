from __future__ import annotations

from pysymex.execution.opcodes import py313
from pysymex.execution.opcodes.py311 import async_ops
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


def test_py313_exports_all_base_opcode_groups() -> None:
    exported = set(py313.__all__)

    assert exported == {
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
    }


def test_py313_routes_to_base_modules() -> None:
    assert py313.arithmetic is arithmetic
    assert py313.async_ops is async_ops
    assert py313.collections is collections
    assert py313.compare is compare
    assert py313.control is control
    assert py313.exceptions is exceptions
    assert py313.formatting is formatting
    assert py313.functions is functions
    assert py313.locals is locals
    assert py313.stack is stack
