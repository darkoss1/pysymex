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

"""Integer candidate generation for detector witness probes."""

from __future__ import annotations

import itertools
from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from collections.abc import Iterator

_SMALL_INTEGER_WITNESS_CANDIDATES: tuple[int, ...] = (
    0,
    -1,
    1,
    -2,
    2,
    -3,
    3,
    -4,
    4,
    -5,
    5,
    -6,
    6,
    -7,
    7,
    -8,
    8,
)
_COMMON_INTEGER_BOUNDARIES: tuple[int, ...] = (
    -256,
    -255,
    -128,
    -127,
    127,
    128,
    255,
    256,
    -(2**31),
    -(2**31) + 1,
    2**31 - 1,
    2**31,
)
_INTEGER_WITNESS_CANDIDATES: tuple[int, ...] = tuple(
    dict.fromkeys((*_SMALL_INTEGER_WITNESS_CANDIDATES, *_COMMON_INTEGER_BOUNDARIES)),
)
_INTEGER_WITNESS_PATTERN_BASE_VALUES: tuple[int, ...] = (0, 1, -1)
_MAX_INTEGER_WITNESS_PRODUCT_VARS = 3
_MAX_INTEGER_WITNESS_PRODUCT_ASSIGNMENTS = 512
_MAX_INTEGER_WITNESS_MIXED_RADIX_ASSIGNMENTS = 1024
_MAX_INTEGER_LITERAL_CANDIDATES = 32
_MAX_INTEGER_LITERAL_ABS_VALUE = 4096


def _assignments(
    variable_count: int,
    formula: z3.BoolRef,
) -> list[tuple[int, ...]]:
    """Return deterministic bounded assignments for integer witness probes."""
    candidates = _integer_witness_candidates(formula)
    assignments = list(_integer_pattern_assignments(variable_count))
    if variable_count <= _MAX_INTEGER_WITNESS_PRODUCT_VARS:
        product_assignments = sorted(
            itertools.product(candidates, repeat=variable_count),
            key=_integer_assignment_priority,
        )
        assignments.extend(product_assignments[:_MAX_INTEGER_WITNESS_PRODUCT_ASSIGNMENTS])
    else:
        assignments.extend(_mixed_radix_integer_assignments(variable_count, candidates))
    return list(dict.fromkeys(assignments))


def _string_context_candidates(
    name: str,
    *,
    source_text: str,
    bin_text: str | None,
) -> tuple[int, ...]:
    """Return deterministic integer candidates for string-derived helper names."""
    if name.startswith("len_") and name.endswith("_int"):
        return (len(source_text),)
    if "count" in name and name.endswith("_int") and bin_text is not None:
        return (bin_text.count("1"),)
    return _INTEGER_WITNESS_CANDIDATES


def _integer_literal_candidates(formula: z3.ExprRef) -> tuple[int, ...]:
    """Collect bounded integer literals from a detector formula as witness candidates."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    values: list[int] = []
    while pending and len(values) < _MAX_INTEGER_LITERAL_CANDIDATES:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if z3.is_int_value(expression):
            value = expression.as_long()
            if abs(value) > _MAX_INTEGER_LITERAL_ABS_VALUE:
                continue
            values.extend((value, -value, value - 1, value + 1))
            continue
        pending.extend(expression.children())
    return tuple(dict.fromkeys(values))


def _integer_witness_candidates(formula: z3.BoolRef) -> tuple[int, ...]:
    """Return deterministic bounded candidates for concrete integer witness probes."""
    return tuple(
        dict.fromkeys(
            (
                *_SMALL_INTEGER_WITNESS_CANDIDATES,
                *_integer_literal_candidates(formula),
                *_COMMON_INTEGER_BOUNDARIES,
            ),
        ),
    )


def _integer_pattern_assignments(variable_count: int) -> Iterator[tuple[int, ...]]:
    """Yield shape-generic low-cost assignments before bounded enumeration."""
    for value in _INTEGER_WITNESS_PATTERN_BASE_VALUES:
        yield (value,) * variable_count

    for index in range(variable_count):
        for value in _INTEGER_WITNESS_PATTERN_BASE_VALUES[1:]:
            values = [0] * variable_count
            values[index] = value
            yield tuple(values)

    if variable_count < 2:
        return

    yield tuple(0 if index % 2 == 0 else 1 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else -1 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else 2 for index in range(variable_count))
    yield tuple(2 if index % 2 == 0 else 0 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else -2 for index in range(variable_count))
    yield tuple(-2 if index % 2 == 0 else 0 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else 3 for index in range(variable_count))
    yield tuple(3 if index % 2 == 0 else 0 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else -3 for index in range(variable_count))
    yield tuple(-3 if index % 2 == 0 else 0 for index in range(variable_count))

    if variable_count >= 4:
        for first_odd in (2, -2, 3, -3):
            for later_odd in (2, -2, 3, -3):
                values = [0] * variable_count
                for index in range(1, variable_count, 2):
                    values[index] = later_odd
                values[1] = first_odd
                yield tuple(values)

    yield tuple(range(variable_count))
    yield tuple(-index for index in range(variable_count))

    center = variable_count // 2
    yield tuple(index - center for index in range(variable_count))
    yield tuple(center - index for index in range(variable_count))


def _mixed_radix_integer_assignments(
    variable_count: int,
    candidates: tuple[int, ...],
) -> Iterator[tuple[int, ...]]:
    """Yield a deterministic prefix of the bounded candidate product."""
    if not candidates:
        return
    for seed in range(_MAX_INTEGER_WITNESS_MIXED_RADIX_ASSIGNMENTS):
        remainder = seed
        values: list[int] = []
        for _ in range(variable_count):
            values.append(candidates[remainder % len(candidates)])
            remainder //= len(candidates)
        yield tuple(values)


def _integer_assignment_priority(values: tuple[int, ...]) -> tuple[int, int, tuple[int, ...]]:
    """Prefer compact signed witnesses before wide integer combinations."""
    magnitudes = tuple(abs(value) for value in values)
    return (max(magnitudes, default=0), sum(magnitudes), values)


class IntegerWitnesses:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    assignments = staticmethod(_assignments)
    string_context_candidates = staticmethod(_string_context_candidates)
