from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator
import z3

class GcdImpossibilityRule(LogicRule):
    name = "GCD Impossibility"
    tier = 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 2: return False
        return core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM})