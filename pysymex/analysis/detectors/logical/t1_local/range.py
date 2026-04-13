from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator

class RangeContradictionRule(LogicRule):
    name = "Range Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        has_gt = core_has_operator(ctx.core, {z3.Z3_OP_GT, z3.Z3_OP_GE})
        has_lt = core_has_operator(ctx.core, {z3.Z3_OP_LT, z3.Z3_OP_LE})
        return has_gt and has_lt