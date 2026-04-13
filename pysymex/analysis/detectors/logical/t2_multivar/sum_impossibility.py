from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator
import z3

class SumImpossibilityRule(LogicRule):
    name = "Sum Impossibility"
    tier = 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 2: return False
        
        has_sum = core_has_operator(ctx.core, {z3.Z3_OP_ADD})
        has_eq = core_has_operator(ctx.core, {z3.Z3_OP_EQ})
        has_ineq = core_has_operator(ctx.core, {z3.Z3_OP_GT, z3.Z3_OP_GE, z3.Z3_OP_LT, z3.Z3_OP_LE, z3.Z3_OP_NOT})
        
        return has_sum and has_eq and has_ineq