from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator

class ParityContradictionRule(LogicRule):
    name = "Parity Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        if not core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM}): return False
        
        # Check if there is a modulo by 2
        for c in ctx.core:
            worklist = [c]
            seen = {c.get_id()}
            while worklist:
                node = worklist.pop()
                if z3.is_app(node) and node.decl().kind() in (z3.Z3_OP_MOD, z3.Z3_OP_REM):
                    if node.num_args() == 2:
                        arg1 = node.arg(1)
                        if z3.is_const(arg1) and arg1.decl().kind() == z3.Z3_OP_ANUM:
                            try:
                                if arg1.as_long() == 2:
                                    return True
                            except Exception:
                                pass
                for child in node.children():
                    if child.get_id() not in seen:
                        seen.add(child.get_id())
                        worklist.append(child)
        return False