"""Arithmetic validation cases for exception-producing operations."""

from __future__ import annotations

from tests.repro.arithmetic_validation_types import OpcodeValidationCase, case


ARITHMETIC_ERROR_CASES: tuple[OpcodeValidationCase, ...] = (
    case(
        "x = a / b",
        "Division by Zero Concrete",
        initial_values={"a": 10, "b": 0},
    ),
    case(
        "x = a / b",
        "Division by Zero Symbolic",
        symbolic_vars={"b": "int"},
        initial_values={"a": 10, "b": 0},
    ),
    case(
        "x = a % b",
        "Modulo by Zero Concrete",
        initial_values={"a": 10, "b": 0},
    ),
    case(
        "x = a % b",
        "Modulo by Zero Symbolic",
        symbolic_vars={"b": "int"},
        initial_values={"a": 10, "b": 0},
    ),
)
