# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""Literal classifiers for conversion-backed ValueError detection."""

from __future__ import annotations

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.affinity import AffinityKind
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


def extract_string_literal(value: object) -> str | None:
    """Extract a concrete string literal from concrete or symbolic string values."""
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString):
        if z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        return None
    if isinstance(value, SymbolicValue):
        if isinstance(value.value, str):
            return value.value
        if (
            value.affinity_type == AffinityKind.STR or z3.is_true(simplify_expr(value.is_str))
        ) and z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        return None
    return None


def is_invalid_int_literal(value: object) -> bool:
    """Return True when ``int(value)`` would raise ValueError for common cases."""
    literal = extract_string_literal(value)
    if literal is None:
        return False
    stripped = literal.strip()
    if not stripped:
        return True
    try:
        int(stripped, 10)
    except ValueError:
        return True
    return False


def extract_int_base(base_value: object) -> int | None:
    """Extract a concrete integer base when possible."""
    if isinstance(base_value, int):
        return base_value
    if isinstance(base_value, SymbolicValue) and isinstance(base_value.value, int):
        return base_value.value
    return None


def is_invalid_int_literal_with_base(value: object, base_value: object) -> bool:
    """Return True when ``int(value, base)`` would raise ValueError for concrete inputs."""
    literal = extract_string_literal(value)
    base = extract_int_base(base_value)
    if literal is None or base is None:
        return False
    stripped = literal.strip()
    if not stripped:
        return True
    try:
        int(stripped, base)
    except ValueError:
        return True
    return False


def is_invalid_float_literal(value: object) -> bool:
    """Return True when ``float(value)`` would raise ValueError for common cases."""
    literal = extract_string_literal(value)
    if literal is None:
        return False
    stripped = literal.strip()
    if not stripped:
        return True
    try:
        float(stripped)
    except ValueError:
        return True
    return False


def is_invalid_hex_literal(value: object) -> bool:
    """Return True when ``bytes.fromhex(value)`` would raise ValueError."""
    literal = extract_string_literal(value)
    if literal is None:
        return False
    try:
        bytes.fromhex(literal)
    except ValueError:
        return True
    return False
