from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, extract_var_var_comparisons

class AntisymmetryRule(LogicRule):
    name = "Antisymmetry Violation"
    tier = 2

    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 2:
            return False

        relations = extract_var_var_comparisons(ctx.core)
        if not relations:
            return False

        rel = {(a, op, b) for a, op, b in relations}
        for a, op, b in relations:
            if op == ">" and ((b, ">", a) in rel or (b, ">=", a) in rel):
                return True
            if op == ">=" and (b, ">", a) in rel:
                return True
            if op == "<" and ((b, "<", a) in rel or (b, "<=", a) in rel):
                return True
            if op == "<=" and (b, "<", a) in rel:
                return True
            if op == "==" and ((a, "!=", b) in rel or (b, "!=", a) in rel):
                return True

        return False