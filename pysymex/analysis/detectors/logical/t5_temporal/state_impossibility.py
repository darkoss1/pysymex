from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    extract_bool_assignments,
    extract_var_const_equalities,
    get_variable_names_all,
)

class StateImpossibilityRule(LogicRule):
    name = "State Impossibility"
    tier = 5

    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        state_names = [n for n in names if any(tag in n.lower() for tag in ("state", "status", "mode", "phase"))]
        if not state_names:
            return False

        equalities = extract_var_const_equalities(ctx.core)
        for name in state_names:
            values = equalities.get(name)
            if values and len(values) > 1:
                return True

        bool_values = extract_bool_assignments(ctx.core)
        for name in state_names:
            values = bool_values.get(name)
            if values and len(values) > 1:
                return True

        return False
