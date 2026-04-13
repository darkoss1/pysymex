from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    extract_bounds,
    extract_bool_assignments,
    extract_var_const_equalities,
)

class PostconditionContradictionRule(LogicRule):
    name = "Postcondition Contradiction"
    tier = 4

    def matches(self, ctx: ContradictionContext) -> bool:
        bounds = extract_bounds(ctx.core)
        equalities = extract_var_const_equalities(ctx.core)
        bool_values = extract_bool_assignments(ctx.core)

        for var, b in bounds.items():
            lname = var.lower()
            if "_is_" in lname:
                continue
            if "result" not in lname and "post" not in lname and "out" not in lname:
                continue
            if bounds_are_inconsistent(b):
                return True
            eq_values = equalities.get(var)
            if eq_values and len(eq_values) > 1:
                return True
            if eq_values:
                value = next(iter(eq_values))
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

        for name, values in bool_values.items():
            lname = name.lower()
            if "_is_" in lname:
                continue
            if ("result" in lname or "post" in lname or "out" in lname) and len(values) > 1:
                return True

        return False
