from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator

class ModularContradictionRule(LogicRule):
    name = "Modular Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        if core_has_operator(ctx.core, {z3.Z3_OP_MUL, z3.Z3_OP_ADD}): return False
        return core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM})