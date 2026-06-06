"""Shared arithmetic validation case types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class OpcodeValidationCase:
    source: str
    description: str
    initial_values: dict[str, Any] | None = None
    expected_locals: dict[str, Any] | None = None
    symbolic_vars: dict[str, str] | None = None


def case(
    source: str,
    description: str,
    *,
    initial_values: dict[str, Any] | None = None,
    expected_locals: dict[str, Any] | None = None,
    symbolic_vars: dict[str, str] | None = None,
) -> OpcodeValidationCase:
    return OpcodeValidationCase(
        source=source,
        description=description,
        initial_values=initial_values,
        expected_locals=expected_locals,
        symbolic_vars=symbolic_vars,
    )
