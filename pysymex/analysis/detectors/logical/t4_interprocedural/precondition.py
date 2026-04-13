from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    extract_bounds,
    extract_var_const_equalities,
)

class PreconditionImpossibilityRule(LogicRule):
    name = "Precondition Impossibility"
    tier = 4

    def matches(self, ctx: ContradictionContext) -> bool:
        bounds = extract_bounds(ctx.core)
        equalities = extract_var_const_equalities(ctx.core)

        for var, b in bounds.items():
            lname = var.lower()
            if "arg" not in lname and "param" not in lname and "input" not in lname and "pre" not in lname:
                continue
            if bounds_are_inconsistent(b):
                return True
            if var in equalities and len(equalities[var]) > 1:
                return True
        return False
