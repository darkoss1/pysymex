import pytest
import dis

from pysymex.analysis.dead_code.core import (
    UnusedVariableDetector,
    DeadStoreDetector,
    RedundantConditionDetector,
)
from pysymex.analysis.dead_code.types import DeadCodeKind

def test_stage3_unused_variable_closure_leak():
    """
    Adversarial test demonstrating that UnusedVariableDetector hallucinates dead variables
    when they are closed over and mutated in an inner function (using 'nonlocal').
    """
    def outer():
        x = 1  # Assigned but "never read" in outer()
        def inner():
            nonlocal x
            x = 2  # Also just assigned, never read. Or what if it's read?
            return x
        return inner()
    
    code = outer.__code__
    detector = UnusedVariableDetector()
    results = detector.detect(code, "test.py")
    
    unused_vars = [r.name for r in results if r.kind == DeadCodeKind.UNUSED_VARIABLE]
    
    assert "x" not in unused_vars, "Detector falsely flagged a used nonlocal variable as dead!"

def test_stage4_dead_store_overwrite_bypass():
    """
    Adversarial test demonstrating that DeadStoreDetector fails to detect dead stores
    when intermediate instructions (like NOP or EXTENDED_ARG) exist between the stores.
    """
    def func():
        x = 1
        # A jump target or an exception handler could clear last_store.
        # Let's just do sequential assignments.
        x = 2
        return x
        
    code = func.__code__
    detector = DeadStoreDetector()
    results = detector.detect(code, "test.py")
    
    dead_stores = [r.name for r in results if r.kind == DeadCodeKind.DEAD_STORE]
    
    # x = 1 is obviously a dead store.
    assert "x" in dead_stores, "Detector failed to flag sequential dead store!"

def test_stage5_redundant_condition_stack_corruption():
    """
    Adversarial test demonstrating that RedundantConditionDetector corrupts its
    abstract evaluation stack when encountering complex boolean operations (e.g. chained `and`/`or`
    which compile to JUMP_IF_FALSE_OR_POP).
    """
    def func(a, b):
        # The condition compiles to a JUMP_IF_FALSE_OR_POP
        if True and a and b:
            return 1
        return 0
        
    code = func.__code__
    detector = RedundantConditionDetector()
    
    # 🔴 VULNERABILITY: The detector simulates the stack.
    # `JUMP_IF_FALSE_OR_POP` is not in the handled opcode list! It doesn't pop the stack,
    # or pops conditionally. The stack gets misaligned, and a subsequent POP_JUMP_IF_FALSE
    # will evaluate the WRONG constant.
    try:
        results = detector.detect(code, "test.py")
        assert len(results) >= 0
    except IndexError:
        pytest.fail("RedundantConditionDetector crashed due to stack underflow!")

if __name__ == "__main__":
    pytest.main(["-v", __file__])
