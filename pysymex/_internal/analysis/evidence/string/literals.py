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

"""String literal and candidate extraction for detector witness probes."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.analysis.evidence.errors import EVIDENCE_SOLVER_FAILURES
from pysymex._internal.analysis.evidence.formulas import iter_conjuncts
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = get_logger(__name__)
_MAX_STRING_LITERAL_CANDIDATES = 32
_MAX_STRING_WITNESS_LENGTH = 32
_BASE_STRING_WITNESS_CANDIDATES: tuple[str, ...] = (
    "0",
    "1",
    "",
    "a",
    "b",
    "ab",
    "abc",
    "z",
)


def _constants(
    formula: z3.ExprRef,
    *,
    limit: int | None = None,
) -> list[z3.SeqRef]:
    """Collect uninterpreted string constants from *formula* in stable order."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    constants_by_name: dict[str, z3.SeqRef] = {}
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if (
            isinstance(expression, z3.SeqRef)
            and expression.sort().kind() == z3.Z3_SEQ_SORT
            and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED
        ):
            constants_by_name[expression.decl().name()] = expression
            if limit is not None and len(constants_by_name) >= limit:
                return [constants_by_name[name] for name in sorted(constants_by_name)]
            continue
        pending.extend(expression.children())
    return [constants_by_name[name] for name in sorted(constants_by_name)]


def _candidates(formula: z3.ExprRef) -> tuple[str, ...]:
    """Return bounded string candidates derived from the detector formula."""
    candidates = [
        *_BASE_STRING_WITNESS_CANDIDATES,
        *_string_literal_candidates(formula),
        *_substring_literal_candidates(formula),
    ]
    candidates.extend(_length_shaped_string_candidates(formula, candidates))
    return tuple(
        dict.fromkeys(
            candidate for candidate in candidates if len(candidate) <= _MAX_STRING_WITNESS_LENGTH
        ),
    )


def _bin_candidates(formula: z3.ExprRef) -> tuple[str, ...]:
    """Return formula-derived ``bin(...)`` text candidates for count bridges."""
    return tuple(
        candidate
        for candidate in StringWitnesses.candidates(formula)
        if candidate.startswith("0b")
        and len(candidate) > 2
        and all(character in {"0", "1"} for character in candidate[2:])
    )


def _string_literal_candidates(formula: z3.ExprRef) -> tuple[str, ...]:
    """Collect concrete string literals that already appear in a formula."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    values: list[str] = []
    while pending and len(values) < _MAX_STRING_LITERAL_CANDIDATES:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        try:
            value = _z3_string_literal_value(expression)
            if value is not None:
                values.append(value)
                continue
            pending.extend(expression.children())
        except EVIDENCE_SOLVER_FAILURES:
            logger.debug("String literal witness collection failed; skipping expression")
    return tuple(dict.fromkeys(values))


def _substring_literal_candidates(formula: z3.ExprRef) -> tuple[str, ...]:
    """Reconstruct concrete strings from contiguous ``SubString`` equalities."""
    characters_by_source: dict[str, dict[int, str]] = {}
    for constraint in iter_conjuncts(cast("z3.BoolRef", simplify_expr(formula))):
        if not z3.is_eq(constraint):
            continue
        left, right = constraint.children()
        for source_name, offset, value in _substring_literal_assignments(left, right):
            characters = characters_by_source.setdefault(source_name, {})
            for index, character in enumerate(value, start=offset):
                characters[index] = character
        for source_name, offset, value in _substring_literal_assignments(right, left):
            characters = characters_by_source.setdefault(source_name, {})
            for index, character in enumerate(value, start=offset):
                characters[index] = character

    candidates: list[str] = []
    for characters in characters_by_source.values():
        if not characters:
            continue
        width = max(characters) + 1
        if width > _MAX_STRING_WITNESS_LENGTH:
            continue
        if set(characters) != set(range(width)):
            continue
        candidates.append("".join(characters[index] for index in range(width)))
    return tuple(dict.fromkeys(candidates))


def _substring_literal_assignments(
    left: z3.ExprRef,
    right: z3.ExprRef,
) -> Iterator[tuple[str, int, str]]:
    """Yield ``(source_name, offset, literal)`` for ``SubString(source, i, n) == text``."""
    try:
        literal = _z3_string_literal_value(right)
        if literal is None:
            return
        if left.decl().name() == "str.substr":
            source, offset_expr, length_expr = left.children()
            if not z3.is_int_value(length_expr):
                return
            length = length_expr.as_long()
        elif left.decl().name() == "str.at":
            source, offset_expr = left.children()
            length = 1
        else:
            return
        if source.decl().kind() != z3.Z3_OP_UNINTERPRETED:
            return
        if not z3.is_int_value(offset_expr):
            return
        offset = offset_expr.as_long()
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Substring literal witness extraction failed; skipping expression")
        return
    if offset < 0 or length < 0 or len(literal) != length:
        return
    yield (source.decl().name(), offset, literal)


def _z3_string_literal_value(expression: z3.ExprRef) -> str | None:
    try:
        if not z3.is_string_value(expression):
            return None
        return _decode_z3_string_escapes(expression.as_string())
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Z3 string literal decoding failed; skipping expression")
    return None


def _decode_z3_string_escapes(value: str) -> str:
    r"""Decode Z3 ``\\u{...}`` escapes from ``SeqRef.as_string()`` output."""
    parts: list[str] = []
    index = 0
    while index < len(value):
        if value.startswith("\\u{", index):
            end = value.find("}", index + 3)
            if end != -1:
                try:
                    parts.append(chr(int(value[index + 3 : end], 16)))
                except ValueError:
                    parts.append(value[index])
                    index += 1
                    continue
                index = end + 1
                continue
        parts.append(value[index])
        index += 1
    return "".join(parts)


def _length_shaped_string_candidates(
    formula: z3.ExprRef,
    known_candidates: list[str],
) -> tuple[str, ...]:
    """Generate small length-compatible candidates from visible length constraints."""
    lengths = _string_length_literals(formula)
    if not lengths:
        return ()
    atoms = ["a", "b", "0", "1"]
    atoms.extend(candidate[:1] for candidate in known_candidates if candidate)
    shaped: list[str] = []
    for length in lengths:
        if length < 0 or length > _MAX_STRING_WITNESS_LENGTH:
            continue
        if length == 0:
            shaped.append("")
            continue
        shaped.extend(atom * length for atom in atoms if atom)
    return tuple(dict.fromkeys(shaped))


def _string_length_literals(formula: z3.ExprRef) -> tuple[int, ...]:
    """Collect small integer literals from ``Length(text) == n`` constraints."""
    lengths: list[int] = []
    for constraint in iter_conjuncts(cast("z3.BoolRef", simplify_expr(formula))):
        if not z3.is_eq(constraint):
            continue
        left, right = constraint.children()
        length = _string_length_literal(left, right)
        if length is not None:
            lengths.append(length)
        length = _string_length_literal(right, left)
        if length is not None:
            lengths.append(length)
    return tuple(dict.fromkeys(lengths))


def _string_length_literal(left: z3.ExprRef, right: z3.ExprRef) -> int | None:
    try:
        if left.decl().name() == "str.len" and z3.is_int_value(right):
            return right.as_long()
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("String length witness extraction failed; skipping expression")
    return None


class StringWitnesses:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    constants = staticmethod(_constants)
    candidates = staticmethod(_candidates)
    bin_candidates = staticmethod(_bin_candidates)
