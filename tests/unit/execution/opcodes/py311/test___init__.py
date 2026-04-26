from __future__ import annotations

from pysymex.execution.opcodes import py311
from pysymex.execution.opcodes.py311 import (
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


def test_py311_exports_all_base_opcode_groups() -> None:
    exported = set(py311.__all__)

    assert exported == {
        "arithmetic",
        "async_ops",
        "collections",
        "compare",
        "control",
        "exceptions",
        "functions",
        "locals",
        "stack",
    }


def test_py311_routes_to_base_modules() -> None:
    assert py311.arithmetic is arithmetic
    assert py311.async_ops is async_ops
    assert py311.collections is collections
    assert py311.compare is compare
    assert py311.control is control
    assert py311.exceptions is exceptions
    assert py311.functions is functions
    assert py311.locals is locals
    assert py311.stack is stack
