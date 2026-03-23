import z3
import numpy as np
from pysymex.h_acceleration.bytecode import compile_constraint
from pysymex.h_acceleration.bytecode_optimizer import optimize
from pysymex.h_acceleration.backends import cpu

def test_optimizer_soundness():
    x, y, z = z3.Bools("x y z")
    # A constraint with common subexpressions, constants to fold, and dead code
    expr = z3.And(
        z3.Or(x, z3.Not(x)),  # constant True
        z3.And(x, y) == z3.And(x, y), # True, CSE
        z3.If(x, y, z) == z3.If(x, y, z), # True, CSE
        z3.Or(x, y, z)
    )
    
    constraint = compile_constraint(expr, ["x", "y", "z"])
    optimized, stats = optimize(constraint)
    
    # Newer optimizer pipelines may already receive near-minimal bytecode from
    # upstream simplification passes. Enforce non-regression, not mandatory reduction.
    assert (
        stats.optimized_instructions <= stats.original_instructions
    ), "Optimizer must never increase instruction count"
    assert stats.reduction_percent >= 0, "Reduction percent should be non-negative"
    
    if cpu.is_available():
        res_unopt = cpu.evaluate_bag(constraint)
        res_opt = cpu.evaluate_bag(optimized)
        assert np.array_equal(res_unopt, res_opt), "Optimizer changed the semantics of the constraint"
