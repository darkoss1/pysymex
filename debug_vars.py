import z3
from pysymex.analysis.detectors.logic.utils import get_variables_for_core

# Let's mock a simple core with the variables from the output
x_int = z3.Int("x_int")
cmp_mixed_3 = z3.Bool("cmp_mixed_3")
core = [z3.If(z3.And(False, False), z3.BoolVal(False), cmp_mixed_3), x_int > 10]
vars = get_variables_for_core(core)
print([v.decl().name() for v in vars])
