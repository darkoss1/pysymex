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

"""Literal conversion ValueError evidence for CALL-family detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.runtime.value.issues import value_error_issue
from pysymex._internal.analysis.detectors.runtime.value.literals import (
    extract_string_literal,
    is_invalid_float_literal,
    is_invalid_hex_literal,
    is_invalid_int_literal,
    is_invalid_int_literal_with_base,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
    from pysymex._internal.core.state.record import VMState


def conversion_value_error_issue(
    state: VMState,
    solver_check: IsSatFn,
    lowered_target: str,
    argc: int,
    args: Sequence[object],
) -> Issue | None:
    """Return an issue for literal conversion ValueError cases."""
    if lowered_target in {"fromhex", "bytes.fromhex"} and argc == 1:
        return _invalid_fromhex_issue(state, solver_check, args[0])
    if lowered_target in {"int", "builtins.int"} and argc == 1:
        return _invalid_int_issue(state, solver_check, args[0])
    if lowered_target in {"int", "builtins.int"} and argc == 2:
        return _invalid_int_base_issue(state, solver_check, args[0], args[1])
    if lowered_target in {"float", "builtins.float"} and argc == 1:
        return _invalid_float_issue(state, solver_check, args[0])
    return None


def _string_literal_repr(value: object) -> str:
    """Get a string representation, extracting literal strings when possible."""
    literal = extract_string_literal(value)
    if literal is not None:
        return repr(literal)
    return repr(value)


def _invalid_fromhex_issue(state: VMState, solver_check: IsSatFn, value: object) -> Issue | None:
    """Return an issue for invalid ``bytes.fromhex`` literal values."""
    if not is_invalid_hex_literal(value):
        return None
    return value_error_issue(
        state,
        solver_check,
        f"Potential ValueError: bytes.fromhex() invalid literal {_string_literal_repr(value)}",
    )


def _invalid_int_issue(state: VMState, solver_check: IsSatFn, value: object) -> Issue | None:
    """Return an issue for invalid one-argument ``int`` literal values."""
    if not is_invalid_int_literal(value):
        return None
    return value_error_issue(
        state,
        solver_check,
        f"Potential ValueError: int() invalid literal {_string_literal_repr(value)}",
    )


def _invalid_int_base_issue(
    state: VMState,
    solver_check: IsSatFn,
    value: object,
    base: object,
) -> Issue | None:
    """Return an issue for invalid explicit-base ``int`` conversions."""
    if not is_invalid_int_literal_with_base(value, base):
        return None
    literal_repr = _string_literal_repr(value)
    return value_error_issue(
        state,
        solver_check,
        f"Potential ValueError: int() invalid literal/base combination {literal_repr}, {base!r}",
    )


def _invalid_float_issue(state: VMState, solver_check: IsSatFn, value: object) -> Issue | None:
    """Return an issue for invalid ``float`` literal values."""
    if not is_invalid_float_literal(value):
        return None
    return value_error_issue(
        state,
        solver_check,
        f"Potential ValueError: float() invalid literal {_string_literal_repr(value)}",
    )
