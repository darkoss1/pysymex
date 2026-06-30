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

"""Hard-theory path-feasibility skip and witness policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.feasibility import hard_theory_witness_model
from pysymex._internal.core.solver.query.planner import formula_meta, symbolic_query

if TYPE_CHECKING:
    from collections.abc import Sequence

    import z3


def skip_hard_theory_pending_query(
    constraints: Sequence[z3.BoolRef],
    *,
    constraints_have_bitvector_smt_theory: bool | None = None,
) -> bool:
    """Return whether hard-theory preprocessing should run before Z3.

    Pure sequence/string formulas are intentionally not pre-empted here: Z3 often
    decides the small string queries emitted by builtin models faster than the
    bounded concrete-witness search.  The witness path remains available for
    bit-vector, float, array, and arithmetic-hard queries, and direct detector
    callers can still ask for string witnesses explicitly.
    """
    if constraints_have_bitvector_smt_theory is not None:
        if constraints_have_bitvector_smt_theory:
            return True
    query = symbolic_query(constraints)
    has_non_sequence_complex_theory = False
    for constraint in query.constraints:
        meta = formula_meta(constraint)
        if meta.contains_bitvector or meta.contains_float or meta.contains_array:
            return True
        if meta.contains_modulo or meta.contains_division or meta.contains_nonlinear_mul:
            has_non_sequence_complex_theory = True
    return has_non_sequence_complex_theory


def query_has_hard_theory_witness(constraints: list[z3.BoolRef]) -> bool:
    """Return whether bounded substitution proves a hard-theory query SAT."""
    return hard_theory_witness_model(constraints) is not None


def should_probe_hard_theory_witness(constraints: Sequence[z3.BoolRef]) -> bool:
    """Return whether a hard-theory witness probe has any constraints to inspect."""
    return bool(constraints)
