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

"""Compatibility wrappers for quantified predicate discovery and lowering.

The strategy owner is :mod:`pysymex.contracts.quantifiers.lowering`. This module
keeps the previous public function names available while delegating to the new
policy-driven lowering path. Does not query the solver.
"""

from __future__ import annotations

import z3

from pysymex.contracts.quantifiers.lowering import (
    find_matching_paren,
    find_quantifier_occurrences,
    lower_condition_quantifiers,
)
from pysymex.contracts.quantifiers.types import Quantifier


def extract_quantifiers(
    contract_string: str, context: dict[str, z3.ExprRef] | None = None
) -> list[Quantifier]:
    """Extract quantified expressions from a contract string.

    Parses universal, existential, and unique existential sub-clauses
    from a condition string (e.g. ``forall(...)``) into structured quantifier objects.

    Args:
        contract_string: The contract string expression to search.
        context: Optional mapping of symbol names to Z3 expressions.

    Returns:
        A list of parsed ``Quantifier`` objects.
    """
    return [
        occurrence.quantifier
        for occurrence in find_quantifier_occurrences(contract_string, context)
    ]


def replace_quantifiers_with_z3(
    contract_string: str,
    context: dict[str, z3.ExprRef],
) -> z3.BoolRef:
    """Lower quantified clauses while preserving surrounding Boolean operators.

    Replaces quantified sub-expressions in the contract string with unique marker
    variables, compiles the quantified expressions through the default finite
    lowering policy, and parses the outer structure with the markers bound to
    the lowered formulas.

    Args:
        contract_string: The Python-style contract string containing quantifiers.
        context: Mapping of variable names to their active Z3 symbolic terms.

    Returns:
        A ``z3.BoolRef`` representing the fully lowered and compiled formula.
    """
    return lower_condition_quantifiers(contract_string, context)


__all__ = ["find_matching_paren", "extract_quantifiers", "replace_quantifiers_with_z3"]
