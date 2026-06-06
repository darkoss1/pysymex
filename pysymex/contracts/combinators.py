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

"""Z3 logical connectives for callable contract predicates.

``And_``, ``Or_``, ``Not_``, and ``Implies_`` build ``z3.BoolRef`` values during symbolic
tracing so lambdas avoid Python short-circuit semantics. String predicates use the AST
translator instead.
"""

from __future__ import annotations

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_bool_val


def And_(*args: z3.BoolRef | bool) -> z3.BoolRef:
    """Perform a logical AND reduction over the given constraints.

    Wraps ``z3.And`` to evaluate multiple boolean sub-conditions. Essential
    for grouping preconditions or postconditions inside lambda declarations.

    Args:
        args: Boolean expressions or literal values to conjunct.

    Returns:
        A conjunct Z3 boolean expression. Returns ``True`` if no arguments are
        provided.
    """
    z3_args: list[z3.BoolRef] = []
    for a in args:
        if isinstance(a, bool):
            z3_args.append(get_bool_val(a))
        else:
            z3_args.append(a)
    if len(z3_args) == 0:
        return Z3_TRUE
    if len(z3_args) == 1:
        return z3_args[0]
    return z3.And(*z3_args)


def Or_(*args: z3.BoolRef | bool) -> z3.BoolRef:
    """Perform a logical OR reduction over the given constraints.

    Wraps ``z3.Or`` to check if at least one sub-condition holds.

    Args:
        args: Boolean expressions or literal values to disjunct.

    Returns:
        A disjunct Z3 boolean expression. Returns ``False`` if no arguments
        are provided.
    """
    z3_args: list[z3.BoolRef] = []
    for a in args:
        if isinstance(a, bool):
            z3_args.append(get_bool_val(a))
        else:
            z3_args.append(a)
    if len(z3_args) == 0:
        return Z3_FALSE
    if len(z3_args) == 1:
        return z3_args[0]
    return z3.Or(*z3_args)


def Not_(arg: z3.BoolRef | bool) -> z3.BoolRef:
    """Negate a boolean expression.

    Wraps ``z3.Not`` to compute the logical negation of the provided condition.

    Args:
        arg: A boolean expression or literal value.

    Returns:
        A negated Z3 boolean expression.
    """
    if isinstance(arg, bool):
        return get_bool_val(not arg)
    return z3.Not(arg)


def Implies_(antecedent: z3.BoolRef | bool, consequent: z3.BoolRef | bool) -> z3.BoolRef:
    """Evaluate logical implication between two conditions.

    Wraps ``z3.Implies``. Evaluates to ``True`` if the antecedent is ``False``
    or if both the antecedent and consequent are ``True``.

    Args:
        antecedent: The condition that implies.
        consequent: The implied condition.

    Returns:
        An implication Z3 boolean expression.
    """
    a = get_bool_val(antecedent) if isinstance(antecedent, bool) else antecedent
    c = get_bool_val(consequent) if isinstance(consequent, bool) else consequent
    return z3.Implies(a, c)
