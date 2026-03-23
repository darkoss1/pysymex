import z3
from pysymex import analyze
from pysymex.analysis.detectors import IssueKind

def test_symbolic_float_floordiv_type_break():
    """
    INVARIANT: The result of floor division on SymbolicFloat must have a valid type discriminator.
    VIOLATION: Missing float division logic causes executor to drop constraints or return untyped SymbolicValue.
    """
    def float_floor_div(x: float):
        # Without fix, this returns a SymbolicValue with both is_int=False and is_float=False
        # or causes an execution error that is silently swallowed.
        res = x // 2.0
        if isinstance(res, float) or isinstance(res, int):
            return 1
        return 2

    res = analyze(float_floor_div, {"x": "float"})
    # It should complete 1 path, returning 1
    assert res.paths_completed >= 1
    # We want to ensure it doesn't just prune the path. 
    # Also verify there are no engine crashes.
    assert len([p for p in res.degraded_passes if "exception" in str(p).lower()]) == 0

def test_nested_reraise_soundness():
    """
    INVARIANT: RERAISE must propagate the exception to the next outer handler.
    VIOLATION: Current implementation uses OpcodeResult.terminate(), which silences the exception.
    """
    def nested_reraise(x: int):
        try:
            try:
                if x > 10:
                    raise ValueError("inner")
            except ValueError:
                raise # RERAISE
        except ValueError:
            return 42
        return 0

    res = analyze(nested_reraise, {"x": "int"})
    # If RERAISE is fixed, it will propagate the exception to the outer block
    # (if exception tables are fully supported) OR it will bubble it up as an
    # EXCEPTION issue (if fallback fails). Before, it silently terminated without an issue.
    # The key soundness requirement is that the path doesn't just disappear.
    assert res.paths_completed > 0
    
    # We verify that either we successfully returned 42, OR we correctly reported an escaped exception.
    # Both prove that the silent prune is fixed.
    escaped_issues = [i for i in res.issues if i.kind == IssueKind.EXCEPTION and "re-raised" in i.message]
    
    import dis
    instrs = list(dis.get_instructions(nested_reraise))
    returns_42_indices = [i for i, inst in enumerate(instrs) if inst.argval == 42]
    returned_42 = any(idx in res.coverage for idx in returns_42_indices) if getattr(res, "coverage", None) else False
    
    assert len(escaped_issues) > 0 or returned_42, "Path must not silently disappear"

def test_dict_update_length_havoc():
    """
    INVARIANT: dict.update must maintain an accurate and non-negative length.
    VIOLATION: update() havocs length without constraints.
    """
    def dict_havoc():
        d = {"a": 1}
        d.update({"b": 2})
        # If length is havoced and disconnected from len(), this might be SAT
        # A real dict of size 2 cannot have len() == 100.
        if len(d) == 100:
            raise AssertionError("Length was havoced!")
        return len(d)

    res = analyze(dict_havoc)
    issues = [i for i in res.issues if i.kind.name == "ASSERTION_ERROR"]
    assert len(issues) == 0, "Length havoc allowed len(d) == 100 to be SAT"

def test_dict_update_negative_length_internal():
    """
    INVARIANT: dict.update must not allow negative length.
    """
    def dict_update_bug(d1: dict, d2: dict):
        d1.update(d2)
        # If length is completely unconstrained, it can be negative!
        if len(d1) < 0:
            raise AssertionError("Negative length dict!")
        return len(d1)

    res = analyze(dict_update_bug, {"d1": "dict", "d2": "dict"})
    issues = [i for i in res.issues if i.kind.name == "ASSERTION_ERROR"]
    assert len(issues) == 0, "Expected no assertion errors if length is properly constrained"

def test_string_modulo_unconstrained_length():
    """
    INVARIANT: String modulo results must have length >= 0.
    VIOLATION: Arithmetic modulo opcode creates a fresh SymbolicString without length constraints.
    """
    def str_mod_bug(s: str, arg: int):
        formatted = s % arg
        if len(formatted) < 0:
            raise AssertionError("Negative length formatted string!")
        return formatted

    res = analyze(str_mod_bug, {"s": "str", "arg": "int"})
    issues = [i for i in res.issues if i.kind.name == "ASSERTION_ERROR"]
    assert len(issues) == 0, "Expected no assertion errors if string length is >= 0"

def test_complex_exception_routing():
    """
    INVARIANT: Exceptions must route through multiple nested handlers correctly.
    """
    def nested_routing(x: int):
        try:
            try:
                if x > 10:
                    raise ValueError("A")
                if x < 0:
                    raise TypeError("B")
                return 1
            except ValueError:
                if x > 20:
                    raise # RERAISE A
                return 2
        except (ValueError, TypeError):
            return 3

    # x = 5 -> return 1
    # x = 15 -> inner catch -> return 2
    # x = 25 -> inner catch -> reraise A -> outer catch -> return 3
    # x = -5 -> outer catch -> return 3
    
    res = analyze(nested_routing, {"x": "int"})
    # It should find paths returning 1, 2, and 3.
    # We check if 3 unique paths completed and returned different values if possible.
    assert res.paths_completed >= 3
    # Ensure no unexpected engine terminal issues
    assert len([i for i in res.issues if i.kind == IssueKind.EXCEPTION and "re-raised" in i.message]) == 0

if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
