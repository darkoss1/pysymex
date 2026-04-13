from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    extract_bounds,
    extract_var_const_disequalities,
    extract_var_const_equalities,
)

class PostAssignmentContradictionRule(LogicRule):
    name = "Post-assignment Contradiction"
    tier = 3

    def matches(self, ctx: ContradictionContext) -> bool:
        if len(ctx.core) < 2:
            return False

        equalities = extract_var_const_equalities(ctx.core)
        disequalities = extract_var_const_disequalities(ctx.core)
        bounds = extract_bounds(ctx.core)

        for var, values in equalities.items():
            if len(values) != 1:
                continue

            assigned = next(iter(values))
            if assigned in disequalities.get(var, set()):
                return True

            vbounds = bounds.get(var)
            if vbounds is None:
                continue
            if bounds_are_inconsistent(vbounds):
                return True

            min_val = vbounds.get("min")
            max_val = vbounds.get("max")
            min_strict = vbounds.get("min_strict")
            max_strict = vbounds.get("max_strict")

            if min_val is not None and assigned < int(min_val):
                return True
            if max_val is not None and assigned > int(max_val):
                return True
            if min_strict is not None and assigned <= int(min_strict):
                return True
            if max_strict is not None and assigned >= int(max_strict):
                return True

        return False
