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

"""Policy-driven lowering for quantified contract predicates.

This module owns quantifier strategy. It scans source predicates into
``QuantifierPredicateIR`` occurrences, finite-expands supported bounded integer
domains, and only emits native Z3 quantifiers when the caller explicitly opts in.
It does not run solver checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.contracts.ir.predicates import QuantifierPredicateIR
from pysymex._internal.contracts.quantifiers.lower.finite import lower_quantifier
from pysymex._internal.contracts.quantifiers.lower.policy import (
    DEFAULT_QUANTIFIER_LOWERING_POLICY,
    QuantifierLoweringPolicy,
)
from pysymex._internal.contracts.quantifiers.parser import (
    QuantifierParser,
    parse_quantifier_syntax,
)
from pysymex._internal.contracts.quantifiers.translator import parse_condition_to_z3

if TYPE_CHECKING:
    from collections.abc import Mapping

    import z3

    from pysymex._internal.contracts.quantifiers.types import Quantifier


@dataclass(frozen=True, slots=True)
class QuantifierOccurrence:
    """One quantified predicate occurrence found in source text."""

    predicate_ir: QuantifierPredicateIR
    quantifier: Quantifier
    start: int
    end: int


_KEYWORDS = ("exists!", "forall", "exists")


def find_matching_paren(text: str, start: int) -> int:
    """Find the index of the closing parenthesis matching ``text[start]``."""
    if start >= len(text) or text[start] != "(":
        return -1
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def find_quantifier_occurrences(
    condition: str,
    context: Mapping[str, z3.ExprRef] | None = None,
) -> list[QuantifierOccurrence]:
    """Return source-ordered quantified predicates in ``condition``."""
    parser = QuantifierParser(dict(context or {}))
    occurrences: list[QuantifierOccurrence] = []
    index = 0
    while index < len(condition):
        keyword = _match_keyword(condition, index)
        if keyword is None:
            index += 1
            continue
        open_index = _skip_whitespace(condition, index + len(keyword))
        if open_index >= len(condition) or condition[open_index] != "(":
            index += 1
            continue
        close_index = find_matching_paren(condition, open_index)
        if close_index == -1:
            index += 1
            continue
        source = condition[index : close_index + 1]
        quantifier = parser.parse(source)
        syntax = parse_quantifier_syntax(source)
        if quantifier is not None and syntax is not None:
            predicate_ir = QuantifierPredicateIR(
                source=source,
                variable=syntax.variable,
                bound_source=syntax.bound_source,
                body_source=syntax.body_source,
            )
            occurrences.append(
                QuantifierOccurrence(
                    predicate_ir=predicate_ir,
                    quantifier=quantifier,
                    start=index,
                    end=close_index + 1,
                ),
            )
            index = close_index + 1
            continue
        index += 1
    return occurrences


def lower_condition_quantifiers(
    condition: str,
    context: Mapping[str, z3.ExprRef],
    *,
    policy: QuantifierLoweringPolicy = DEFAULT_QUANTIFIER_LOWERING_POLICY,
) -> z3.BoolRef:
    """Lower all top-level quantifier calls in a string predicate."""
    occurrences = find_quantifier_occurrences(condition, context)
    if not occurrences:
        return parse_condition_to_z3(condition, context)

    lowered_context: dict[str, z3.ExprRef] = dict(context)
    pieces: list[str] = []
    cursor = 0
    for occurrence_index, occurrence in enumerate(occurrences):
        marker = f"__pysymex_quantifier_{occurrence_index}"
        pieces.append(condition[cursor : occurrence.start])
        pieces.append(marker)
        lowered_context[marker] = lower_quantifier(occurrence.quantifier, policy=policy)
        cursor = occurrence.end
    pieces.append(condition[cursor:])
    return parse_condition_to_z3("".join(pieces), lowered_context)


def _match_keyword(text: str, index: int) -> str | None:
    """Return a quantifier keyword starting at ``index`` with identifier boundaries."""
    if index > 0 and _is_identifier_char(text[index - 1]):
        return None
    for keyword in _KEYWORDS:
        if not text.startswith(keyword, index):
            continue
        end = index + len(keyword)
        if keyword == "exists" and end < len(text) and text[end] == "!":
            continue
        if end < len(text) and _is_identifier_char(text[end]):
            continue
        return keyword
    return None


def _skip_whitespace(text: str, index: int) -> int:
    """Return the next non-whitespace index."""
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _is_identifier_char(char: str) -> bool:
    """Return whether ``char`` can continue a Python-like identifier."""
    return char.isalnum() or char == "_"
