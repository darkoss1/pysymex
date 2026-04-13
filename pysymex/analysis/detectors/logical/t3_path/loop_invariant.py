from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    expr_contains_variable,
    extract_bounds,
    extract_var_const_equalities,
)

class LoopInvariantViolationRule(LogicRule):
    name = "Loop Invariant Violation"
    tier = 3

    def matches(self, ctx: ContradictionContext) -> bool:
        # Impossible self-referential equalities often arise from broken loop invariants.
        for expr in ctx.core:
            if not z3.is_app(expr) or expr.decl().kind() != z3.Z3_OP_EQ or expr.num_args() != 2:
                continue
            lhs, rhs = expr.arg(0), expr.arg(1)
            if not z3.is_const(lhs) or lhs.decl().kind() != z3.Z3_OP_UNINTERPRETED:
                continue
            name = str(lhs.decl().name())
            if expr_contains_variable(rhs, name) and str(rhs) != str(lhs):
                return True

        # Loop-tagged variable ranges collapsing to empty intervals indicate invariant drift.
        bounds = extract_bounds(ctx.core)
        equalities = extract_var_const_equalities(ctx.core)
        for var, b in bounds.items():
            lower_name = var.lower()
            if "loop" not in lower_name and "iter" not in lower_name and "induction" not in lower_name:
                continue
            if bounds_are_inconsistent(b):
                return True
            if var in equalities and len(equalities[var]) > 1:
                return True

        return False
