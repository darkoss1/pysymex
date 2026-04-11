from __future__ import annotations

from pysymex.execution.opcodes import py312
from pysymex.execution.opcodes.base import arithmetic, async_ops, collections, compare, control, exceptions, functions, locals, stack


def test_py312_exports_all_base_opcode_groups() -> None:
    exported = set(py312.__all__)

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


def test_py312_routes_to_base_modules() -> None:
    assert py312.arithmetic is arithmetic
    assert py312.async_ops is async_ops
    assert py312.collections is collections
    assert py312.compare is compare
    assert py312.control is control
    assert py312.exceptions is exceptions
    assert py312.functions is functions
    assert py312.locals is locals
    assert py312.stack is stack
