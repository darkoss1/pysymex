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

"""Map VM stack values to Z3 terms for contract compilation.

``expression_for_contract_value`` recognizes concrete scalars, raw ``z3.ExprRef``
values, and symbolic wrappers exposing ``z3_int`` / ``z3_bool`` / similar attributes.
Returns ``None`` when no sound projection exists.
"""

from __future__ import annotations

import z3

from pysymex._internal.core.solver.constraints.values import ConstraintValues


def expression_for_contract_value(value: object) -> z3.ExprRef | None:
    """Project a Python scalar or symbolic wrapper onto a Z3 expression.

    Supports native Python types (``bool``, ``int``, ``float``, ``str``) as
    well as objects exposing custom Z3 variable bindings via affinity type
    lookups (such as ``z3_int``, ``z3_bool``, ``z3_str``, or ``z3_addr``).

    Args:
        value: The Python object or Z3 expression reference to convert.

    Returns:
        A resolved ``z3.ExprRef`` if the value can be projected, or ``None``
        if unsupported.

    """
    if isinstance(value, z3.ExprRef):
        return value
    if isinstance(value, bool):
        return ConstraintValues.bool(value)
    if isinstance(value, int):
        return ConstraintValues.int(value)
    if isinstance(value, float):
        return ConstraintValues.real(value)
    if isinstance(value, str):
        return ConstraintValues.string(value)

    affinity_attrs = {
        "bool": "z3_bool",
        "str": "z3_str",
        "float": "z3_float",
        "int": "z3_int",
    }
    affinity = getattr(value, "affinity_type", None)
    attr = affinity_attrs.get(affinity) if isinstance(affinity, str) else None
    if attr is not None:
        expr = getattr(value, attr, None)
        if isinstance(expr, z3.ExprRef):
            return expr
    for candidate in ("z3_int", "z3_bool", "z3_str", "z3_addr"):
        expr = getattr(value, candidate, None)
        if isinstance(expr, z3.ExprRef):
            return expr
    return None
