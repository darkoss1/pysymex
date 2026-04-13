from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator, core_count_operator

class ArithmeticImpossibilityRule(LogicRule):
    name = "Arithmetic Impossibility"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        has_arith = core_has_operator(ctx.core, {z3.Z3_OP_ADD, z3.Z3_OP_MUL, z3.Z3_OP_SUB, z3.Z3_OP_DIV, z3.Z3_OP_IDIV})
        has_eq = core_has_operator(ctx.core, {z3.Z3_OP_EQ})
        has_mod = core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM})
        return has_arith and has_eq and not has_mod