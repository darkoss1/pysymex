from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    extract_bool_assignments,
    extract_bounds,
    get_variable_names_all,
)

class TaintConstraintContradictionRule(LogicRule):
    name = "Taint + Constraint Contradiction"
    tier = 4

    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        taint_names = [n for n in names if "taint" in n.lower() or "untrusted" in n.lower()]
        if not taint_names:
            return False

        bool_values = extract_bool_assignments(ctx.core)
        for name in taint_names:
            vals = bool_values.get(name)
            if vals and len(vals) > 1:
                return True

        # Contradiction between tainted and sanitized states for same symbol lineage.
        lower = {n.lower() for n in names}
        for marker in lower:
            if "sanitized" in marker or "clean" in marker:
                base = marker.replace("sanitized", "").replace("clean", "").strip("_")
                if any(base and base in t.lower() for t in taint_names):
                    return True

        # Tainted values collapsing to impossible range implies broken sanitization constraints.
        bounds = extract_bounds(ctx.core)
        for var, b in bounds.items():
            lname = var.lower()
            if "taint" in lname or "untrusted" in lname or "input" in lname:
                if bounds_are_inconsistent(b):
                    return True

        return False
