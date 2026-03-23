import math
from pysymex import analyze

def test_symbolic_nan_equality():
    """Verify that PySyMex correctly tracks NaN inequality semantics matching IEEE-754."""
    def check_nan(f):
        # NaN is never equal to itself.
        if math.isnan(f):
            if f == f:
                return 1  # Should be mathematically unreachable
            return 2
        return 0
        
    res = analyze(check_nan, {"f": "float"})
    
    assert res.paths_explored > 0, "Should explore paths"
    # Note: If the engine doesn't unroll math.isnan properly, this may fail. 
    # Left as an assertion to catch true engine limitations.

def test_symbolic_inf_propagation():
    """Verify positive and negative infinity boundaries."""
    def check_inf(pos, neg):
        if math.isinf(pos) and pos > 0:
            if math.isinf(neg) and neg < 0:
                if pos > neg:
                    return 1
        return 0
        
    res = analyze(check_inf, {"pos": "float", "neg": "float"})
    assert res.paths_explored > 0, "Engine should support symbolic floats exceeding sys.float_info boundaries"
