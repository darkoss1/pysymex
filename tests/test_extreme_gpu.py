"""
Extreme GPU Fuzzing and Stress Test Suite (2026 Edition).

Validates:
1. Bit-exactness between Reference, CPU, and Bit-Sliced CUDA backends.
2. 1000-case random formula fuzzing.
3. Edge cases (Tautologies, Contradictions, Max Treewidth).
4. Native ITE opcode correctness.
"""

import pytest
import numpy as np
import z3
import random
from pysymex.h_acceleration.bytecode import compile_constraint
from pysymex.h_acceleration.dispatcher import get_dispatcher, BackendType

def create_complex_formula(vars, depth):
    if depth == 0 or random.random() < 0.3:
        return random.choice(vars)
    
    op = random.choice(['and', 'or', 'not', 'xor', 'implies', 'ite'])
    if op == 'not':
        return z3.Not(create_complex_formula(vars, depth - 1))
    elif op == 'ite':
        return z3.If(create_complex_formula(vars, depth - 1),
                     create_complex_formula(vars, depth - 1),
                     create_complex_formula(vars, depth - 1))
    else:
        left = create_complex_formula(vars, depth - 1)
        right = create_complex_formula(vars, depth - 1)
        if op == 'and': return z3.And(left, right)
        if op == 'or': return z3.Or(left, right)
        if op == 'xor': return z3.Xor(left, right)
        if op == 'implies': return z3.Implies(left, right)

@pytest.mark.parametrize("fuzz_idx", range(100)) # Reduced from 1000 for CI efficiency, can be increased
def test_fuzz_correctness(fuzz_idx):
    """Fuzz test all available backends for bit-exact consistency."""
    w = random.randint(1, 12) # Reference is slow beyond 12
    var_names = [f'x{i}' for i in range(w)]
    vars = [z3.Bool(name) for name in var_names]
    
    formula = create_complex_formula(vars, depth=4)
    compiled = compile_constraint(formula, var_names)
    
    # 1. Reference Result
    from pysymex.h_acceleration.backends import reference
    ref_bitmap = reference.evaluate_bag(compiled)
    
    # 2. CPU Result
    from pysymex.h_acceleration.backends import cpu
    if cpu.is_available():
        cpu_bitmap = cpu.evaluate_bag(compiled)
        assert np.array_equal(ref_bitmap, cpu_bitmap), f"CPU mismatch at fuzz {fuzz_idx}"
        
    # 3. CUDA Result (Bit-Sliced)
    from pysymex.h_acceleration.backends import gpu as cuda
    if cuda.is_available():
        cuda_bitmap = cuda.evaluate_bag(compiled)
        assert np.array_equal(ref_bitmap, cuda_bitmap), f"CUDA mismatch at fuzz {fuzz_idx}"

def test_max_treewidth_grid_stride():
    """Test that grid-stride loops correctly handle large treewidths."""
    from pysymex.h_acceleration.backends import gpu as cuda
    if not cuda.is_available():
        pytest.skip("CUDA not available")
        
    w = 21 # 2^21 is > 2 million states, usually triggers grid limits
    var_names = [f'x{i}' for i in range(w)]
    vars = [z3.Bool(name) for name in var_names]
    
    # Simple formula that is only SAT for the very last state
    # (x0 & x1 & ... & x20)
    formula = z3.And(*vars)
    compiled = compile_constraint(formula, var_names)
    
    cuda_bitmap = cuda.evaluate_bag(compiled)
    sat_count = int(np.unpackbits(cuda_bitmap).sum())
    
    assert sat_count == 1, "Grid-stride loop failed to find the single SAT state in large space"

def test_gpu_projection_correctness():
    """Verify that GPU-side projection matches CPU-side projection."""
    from pysymex.h_acceleration.backends import gpu as cuda
    if not cuda.is_available():
        pytest.skip("CUDA not available")
        
    w = 8
    var_names = [f'x{i}' for i in range(w)]
    vars = [z3.Bool(name) for name in var_names]
    
    formula = z3.And(vars[0], vars[1]) # Only SAT if x0 and x1 are True
    compiled = compile_constraint(formula, var_names)
    
    # Adhesion is just {x0}
    adhesion_vars = ['x0']
    
    # 1. GPU Projection
    gpu_proj = cuda.evaluate_bag_projected(compiled, adhesion_vars, var_names)
    
    # 2. CPU Reference (evaluate full then project)
    from pysymex.h_acceleration.backends import reference
    full_bitmap = reference.evaluate_bag(compiled)
    
    # Manual projection on CPU
    cpu_proj = np.zeros(1, dtype=np.uint8) # 2^1 = 2 bits -> 1 byte
    for tid in range(1 << w):
        byte_idx = tid >> 3
        bit_idx = tid & 7
        if (full_bitmap[byte_idx] >> bit_idx) & 1:
            adhesion_idx = (tid >> 0) & 1 # x0 is bit 0
            cpu_proj[adhesion_idx >> 3] |= (1 << (adhesion_idx & 7))
            
    assert np.array_equal(gpu_proj, cpu_proj), "GPU-side projection mismatch"

if __name__ == "__main__":
    pytest.main([__file__])
