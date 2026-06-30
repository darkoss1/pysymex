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

"""Shared validation helpers for user-facing CLI arguments."""

from __future__ import annotations

import argparse
import keyword
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


def positive_int(value: str) -> int:
    """Parse an integer greater than zero for argparse ``type=`` hooks."""
    return _parse_int(value, minimum=1, expected="an integer greater than 0")


def non_negative_int(value: str) -> int:
    """Parse an integer greater than or equal to zero for argparse ``type=`` hooks."""
    return _parse_int(value, minimum=0, expected="an integer 0 or greater")


def non_negative_float(value: str) -> float:
    """Parse a float greater than or equal to zero for argparse ``type=`` hooks."""
    return _parse_float(value, minimum=0.0, expected="a number 0 or greater")


def symbolic_arg_spec(value: str) -> str:
    """Validate and normalize one symbolic argument spec for argparse ``type=`` hooks."""
    try:
        return _canonicalize_symbolic_arg_spec(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def symbolic_args_from_specs(specs: Sequence[str] | None) -> dict[str, str]:
    """Build symbolic-argument mapping from normalized or raw ``NAME:TYPE`` specs.

    Args:
        specs: Optional list of symbolic argument specs supplied by the CLI.

    Returns:
        Mapping from argument name to symbolic type hint.

    Raises:
        ValueError: If any spec is malformed or a name is duplicated.

    """
    symbolic_args: dict[str, str] = {}
    for spec in specs or ():
        normalized = _canonicalize_symbolic_arg_spec(spec)
        name, _, type_hint = normalized.partition(":")
        if name in symbolic_args:
            msg = f"duplicate symbolic argument {name!r}"
            raise ValueError(msg)
        symbolic_args[name] = type_hint
    return symbolic_args


def _parse_int(value: str, *, minimum: int, expected: str) -> int:
    """Parse an integer and enforce a lower bound."""
    try:
        parsed = int(value)
    except ValueError as exc:
        msg = f"expected {expected}, got {value!r}"
        raise argparse.ArgumentTypeError(msg) from exc
    if parsed < minimum:
        msg = f"expected {expected}, got {parsed}"
        raise argparse.ArgumentTypeError(msg)
    return parsed


def _parse_float(value: str, *, minimum: float, expected: str) -> float:
    """Parse a float and enforce a lower bound."""
    try:
        parsed = float(value)
    except ValueError as exc:
        msg = f"expected {expected}, got {value!r}"
        raise argparse.ArgumentTypeError(msg) from exc
    if parsed < minimum:
        msg = f"expected {expected}, got {parsed:g}"
        raise argparse.ArgumentTypeError(msg)
    return parsed


def _canonicalize_symbolic_arg_spec(value: str) -> str:
    """Normalize one symbolic ``NAME:TYPE`` argument spec."""
    text = value.strip()
    name, separator, type_hint = text.partition(":")
    if not separator:
        msg = "symbolic arguments must use NAME:TYPE, for example x:int"
        raise ValueError(msg)

    name = name.strip()
    type_hint = type_hint.strip()
    if not name:
        msg = "symbolic argument name cannot be empty"
        raise ValueError(msg)
    if not name.isidentifier() or keyword.iskeyword(name):
        msg = f"symbolic argument name must be a Python identifier, got {name!r}"
        raise ValueError(msg)
    if not type_hint:
        msg = f"symbolic argument {name!r} must include a non-empty type"
        raise ValueError(msg)

    return f"{name}:{type_hint}"
