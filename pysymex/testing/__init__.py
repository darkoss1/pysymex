"""Testing infrastructure for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Provides property-based testing (fuzzing) with Hypothesis,
conformance test generation, and stateful testing machines.
"""

from __future__ import annotations

from importlib import import_module

_EXPORTS: dict[str, tuple[str, str]] = {
    "ConformanceGenerator": ("pysymex.testing.fuzzing", "ConformanceGenerator"),
    "ConformanceTest": ("pysymex.testing.fuzzing", "ConformanceTest"),
    "MockInstruction": ("pysymex.testing.fuzzing", "MockInstruction"),
    "PropertyTests": ("pysymex.testing.fuzzing", "PropertyTests"),
    "SymbolicStateMachine": ("pysymex.testing.fuzzing", "SymbolicStateMachine"),
    "TestSymbolicState": ("pysymex.testing.fuzzing", "TestSymbolicState"),
    "arithmetic_ops": ("pysymex.testing.fuzzing", "arithmetic_ops"),
    "comparison_ops": ("pysymex.testing.fuzzing", "comparison_ops"),
    "invariants": ("pysymex.testing.fuzzing", "invariants"),
    "mock_instructions": ("pysymex.testing.fuzzing", "mock_instructions"),
    "postconditions": ("pysymex.testing.fuzzing", "postconditions"),
    "preconditions": ("pysymex.testing.fuzzing", "preconditions"),
    "symbolic_booleans": ("pysymex.testing.fuzzing", "symbolic_booleans"),
    "symbolic_dicts": ("pysymex.testing.fuzzing", "symbolic_dicts"),
    "symbolic_floats": ("pysymex.testing.fuzzing", "symbolic_floats"),
    "symbolic_integers": ("pysymex.testing.fuzzing", "symbolic_integers"),
    "symbolic_lists": ("pysymex.testing.fuzzing", "symbolic_lists"),
    "symbolic_none": ("pysymex.testing.fuzzing", "symbolic_none"),
    "symbolic_sets": ("pysymex.testing.fuzzing", "symbolic_sets"),
    "symbolic_strings": ("pysymex.testing.fuzzing", "symbolic_strings"),
    "symbolic_tuples": ("pysymex.testing.fuzzing", "symbolic_tuples"),
    "symbolic_values": ("pysymex.testing.fuzzing", "symbolic_values"),
    "z3_arithmetic_exprs": ("pysymex.testing.fuzzing", "z3_arithmetic_exprs"),
    "z3_bool_exprs": ("pysymex.testing.fuzzing", "z3_bool_exprs"),
    "z3_bool_vars": ("pysymex.testing.fuzzing", "z3_bool_vars"),
    "z3_int_constants": ("pysymex.testing.fuzzing", "z3_int_constants"),
    "z3_int_vars": ("pysymex.testing.fuzzing", "z3_int_vars"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.testing' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return list(_EXPORTS.keys())


__all__: list[str] = [
    "ConformanceGenerator",
    "ConformanceTest",
    "MockInstruction",
    "PropertyTests",
    "SymbolicStateMachine",
    "TestSymbolicState",
    "arithmetic_ops",
    "comparison_ops",
    "invariants",
    "mock_instructions",
    "postconditions",
    "preconditions",
    "symbolic_booleans",
    "symbolic_dicts",
    "symbolic_floats",
    "symbolic_integers",
    "symbolic_lists",
    "symbolic_none",
    "symbolic_sets",
    "symbolic_strings",
    "symbolic_tuples",
    "symbolic_values",
    "z3_arithmetic_exprs",
    "z3_bool_exprs",
    "z3_bool_vars",
    "z3_int_constants",
    "z3_int_vars",
]
