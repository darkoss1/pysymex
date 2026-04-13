from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    count_variables,
    extract_bounds,
    extract_var_const_equalities,
    extract_var_var_comparisons,
    get_variable_names_all,
)

class NumericRangePropagationRule(LogicRule):
    name = "Numeric Range Propagation Contradiction"
    tier = 4

    def matches(self, ctx: ContradictionContext) -> bool:
        if len(ctx.core) < 2 or count_variables(ctx.core) < 2:
            return False

        names = {n.lower() for n in get_variable_names_all(ctx.core)}
        has_interproc_signal = any(
            token in name
            for name in names
            for token in ("arg", "param", "input", "ret", "result", "caller", "callee", "api", "contract")
        )
        if not has_interproc_signal:
            return False

        bounds = extract_bounds(ctx.core)
        equalities = extract_var_const_equalities(ctx.core)
        for var, b in bounds.items():
            if bounds_are_inconsistent(b):
                return True
            if var in equalities and len(equalities[var]) > 1:
                return True

        relations = extract_var_var_comparisons(ctx.core)
        rel = {(a, op, b) for a, op, b in relations}

        # Immediate cycles: x < y and y <= x (and symmetric variants)
        for a, op, b in relations:
            if op == "<" and ((b, "<", a) in rel or (b, "<=", a) in rel):
                return True
            if op == "<=" and (b, "<", a) in rel:
                return True
            if op == ">" and ((b, ">", a) in rel or (b, ">=", a) in rel):
                return True
            if op == ">=" and (b, ">", a) in rel:
                return True
            if op == "==" and ((a, "!=", b) in rel or (b, "!=", a) in rel):
                return True

        return False
