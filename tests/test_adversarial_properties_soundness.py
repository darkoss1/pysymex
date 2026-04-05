import pytest
import z3

from pysymex.analysis.properties.core import PropertyProver, ArithmeticVerifier
from pysymex.analysis.properties.types import ProofStatus

def test_stage2_bitvec_truncation_unsoundness():
    """
    Adversarial test demonstrating that ArithmeticVerifier silently truncates
    integer boundaries when evaluating BitVecs, resulting in completely hallucinated
    overflow/underflow detections (Soundness Violation).
    """
    verifier = ArithmeticVerifier(int_bits=64)
    x = z3.BitVec('x', 32)
    constraints = [x == -5]
    
    proof = verifier.check_overflow(x, {'x': x}, constraints=constraints)
    
    assert proof.status == ProofStatus.PROVEN, "Vulnerability fixed: Proper bounds check without truncation."

def test_stage3_array_bounds_sort_mismatch():
    """
    Adversarial test demonstrating that check_array_bounds crashes the symbolic engine
    with a Sort Mismatch when mixing Int and BitVec representations for indices/lengths.
    """
    verifier = ArithmeticVerifier()
    index = z3.BitVec('index', 32)
    length = z3.Int('length')
    
    # 🔴 VULNERABILITY FIXED: No sort mismatch! It should just prove/disprove.
    proof = verifier.check_array_bounds(index, length, {'index': index, 'length': length})
    assert proof.status in (ProofStatus.PROVEN, ProofStatus.DISPROVEN, ProofStatus.UNKNOWN)

def test_stage4_model_extraction_overflow():
    """
    Adversarial test demonstrating that the prover crashes on valid SMT models
    with large rationals due to native Python float conversion limits.
    """
    prover = PropertyProver()
    x = z3.Real('x')
    large_val = 10**400
    
    constraints = [x * 3 == large_val]
    
    # We test prove_bounded so the violation condition (x > 10) is SAT, triggering model extraction.
    proof = prover.prove_bounded(x, z3.IntVal(-10), z3.IntVal(10), {'x': x}, constraints=constraints)
    
    assert proof.status == ProofStatus.DISPROVEN
    assert "x" in proof.counterexample
    assert isinstance(proof.counterexample["x"], str) # Should fallback to string instead of crashing!

def test_stage4_type_crash_on_unary_minus():
    """
    Adversarial test demonstrating that mathematical functions crash the engine
    with TypeError because they blindly apply operators not valid on all sorts.
    """
    prover = PropertyProver()
    x = z3.String('x')
    
    with pytest.raises(TypeError, match="bad operand type for unary -: 'SeqRef'"):
        prover.prove_even_function(lambda a: a, x)

if __name__ == "__main__":
    pytest.main(["-v", __file__])
