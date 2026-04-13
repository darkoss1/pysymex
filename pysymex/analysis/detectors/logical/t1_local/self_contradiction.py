from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator
import z3

class SelfContradictionRule(LogicRule):
    name = "Self-Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1 or len(ctx.core) != 1:
            return False
        has_not = core_has_operator(ctx.core, {z3.Z3_OP_NOT})
        has_eq = core_has_operator(ctx.core, {z3.Z3_OP_EQ})
        has_mod = core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM})
        return has_not and has_eq and not has_mod