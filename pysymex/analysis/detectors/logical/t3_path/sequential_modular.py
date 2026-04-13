from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import core_has_operator
import z3

class SequentialModularRule(LogicRule):
    name = "Sequential Modular Contradiction"
    tier = 3
    def matches(self, ctx: ContradictionContext) -> bool:
        has_mod = core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM})
        has_mul = core_has_operator(ctx.core, {z3.Z3_OP_MUL})
        # Sequential modular contradictions stem from arithmetic substitutions under modulo.
        return has_mod and has_mul