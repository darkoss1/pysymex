from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import count_variables, core_count_operator, core_has_operator

class EqualityContradictionRule(LogicRule):
    name = "Equality Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        if core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM, z3.Z3_OP_ADD, z3.Z3_OP_MUL, z3.Z3_OP_SUB, z3.Z3_OP_DIV, z3.Z3_OP_IDIV}):
            return False
        return core_count_operator(ctx.core, {z3.Z3_OP_EQ}) >= 2