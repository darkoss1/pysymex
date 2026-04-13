from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator
import z3

class ProductSignContradictionRule(LogicRule):
    name = "Product Sign Contradiction"
    tier = 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 2: return False
        
        has_mul = core_has_operator(ctx.core, {z3.Z3_OP_MUL})
        has_ineq = core_has_operator(ctx.core, {z3.Z3_OP_GT, z3.Z3_OP_GE, z3.Z3_OP_LT, z3.Z3_OP_LE, z3.Z3_OP_NOT})
        
        return has_mul and has_ineq