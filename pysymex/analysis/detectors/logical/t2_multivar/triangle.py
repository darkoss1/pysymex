from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator
import z3

class TriangleImpossibilityRule(LogicRule):
    name = "Triangle Impossibility"
    tier = 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 3 or len(ctx.core) < 3: return False
        
        has_gt = core_has_operator(ctx.core, {z3.Z3_OP_GT, z3.Z3_OP_GE})
        has_lt = core_has_operator(ctx.core, {z3.Z3_OP_LT, z3.Z3_OP_LE})
        has_not = core_has_operator(ctx.core, {z3.Z3_OP_NOT})
        
        return has_gt or has_lt or has_not