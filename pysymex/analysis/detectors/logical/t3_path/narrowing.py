from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    extract_bounds,
    extract_var_const_equalities,
)

class NarrowingContradictionRule(LogicRule):
    name = "Narrowing Contradiction"
    tier = 3

    def matches(self, ctx: ContradictionContext) -> bool:
        if len(ctx.core) < 3:
            return False

        bounds = extract_bounds(ctx.core)
        for b in bounds.values():
            if bounds_are_inconsistent(b):
                return True

        # A narrowed interval can also collapse to a constant inconsistent with equality requirements.
        equalities = extract_var_const_equalities(ctx.core)
        for var, vals in equalities.items():
            if len(vals) > 1:
                return True
            b = bounds.get(var)
            if not b or not vals:
                continue
            value = next(iter(vals))
            min_val = b.get("min")
            max_val = b.get("max")
            min_strict = b.get("min_strict")
            max_strict = b.get("max_strict")
            if min_val is not None and value < int(min_val):
                return True
            if max_val is not None and value > int(max_val):
                return True
            if min_strict is not None and value <= int(min_strict):
                return True
            if max_strict is not None and value >= int(max_strict):
                return True

        return False
