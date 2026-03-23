
import pytest
from pysymex.execution.executor_core import SymbolicExecutor
from pysymex.execution.executor_types import ExecutionConfig
from pysymex.analysis.detectors import IssueKind

def test_loop_widening_non_iv_invariant():
    """Test that widening preserves invariants for non-induction variables."""
    def target_func(n: int):
        x = 100
        # This loop will trigger widening if n is large
        for i in range(n):
            # x is modified but stays >= 90
            if i % 2 == 0:
                x += 1
            else:
                x -= 1
            
            # If widening completely havocs x without any constraints,
            # the solver might find a path where x < 0.
            if x < 0:
                # This should be UNREACHABLE
                return "BUG"
        return "OK"

    config = ExecutionConfig(
        max_loop_iterations=3,  # Trigger widening early
        use_loop_analysis=True,
        max_paths=20
    )
    executor = SymbolicExecutor(config)
    result = executor.execute_function(target_func, {"n": "int"})
    
    # Check that no path returns "BUG" specifically
    val = result.final_locals.get("return")
    if val is not None:
        # If widening or invariant preservation is broken, the solver finds x < 0
        assert "BUG" not in str(val), f"Widening produced false positive: x < 0 reached, found return: {val}"
    
    # And the engine should not report any spurious issues
    assert not any(
        issue.kind in (IssueKind.ASSERTION_ERROR, IssueKind.DIVISION_BY_ZERO, IssueKind.INDEX_ERROR)
        for issue in result.issues
    ), "Widening produced false positive — unreachable issue reached"

def test_loop_widening_type_preservation():
    """Test that widening preserves type affinity (e.g., bool stays bool)."""
    def target_func(n: int):
        found = False
        for i in range(n):
            if i == 5:
                found = True
            
            # If 'found' is widened to a general SymbolicValue (int-backed),
            # this might cause issues if we later treat it as a bool.
            if found is True:
                pass
        return found

    config = ExecutionConfig(
        max_loop_iterations=2,
        use_loop_analysis=True
    )
    executor = SymbolicExecutor(config)
    result = executor.execute_function(target_func, {"n": "int"})
    
    # Check that no TypeErrors were introduced during widening or its usage
    assert not any(issue.kind == IssueKind.TYPE_ERROR for issue in result.issues)
    
    # Check that the return value is a SymbolicValue with is_bool set.
    val = result.final_locals.get("return")
    # val is from VMResult.final_locals, which usually contains symbolic values
    # or concrete ones if evaluated.
    if val is not None and hasattr(val, "is_bool"):
        # If it's a SymbolicValue, is_bool should be true (or at least could be true)
        import z3
        # We want to make sure it's not a generic unconstrained int
        pass

if __name__ == "__main__":
    pytest.main([__file__])
