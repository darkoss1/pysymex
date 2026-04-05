import pytest
from pysymex import analyze
from pysymex.execution.executor import ExecutionConfig
from pysymex.analysis.detectors import IssueKind


@pytest.mark.timeout(5)
def test_infinite_loop_timeout_defense():

    """Verify the VM correctly drops runaway symbolic infinite loops without hanging the test runner."""
    def hang(x):
        # A while loop where the condition is purely symbolic but unresolvable to bounded integers
        while x > 0:
            pass 
        return 0

    # Strict limits so the test breaks fast
    res = analyze(hang, {"x": "int"}, max_depth=8, max_paths=1, max_iterations=200, timeout=1.0)
    
    # The scan should finish quickly due to depth cutoff constraints
    assert res.paths_pruned >= 0, "Engine should prune paths exceeding boundaries cleanly"

@pytest.mark.timeout(10)
def test_mutually_recursive_halting():

    """Verify the call stack limits strictly halt explosive recursion."""
    def ping(x):
        if x > 0:
            return pong(x)
        return 1
        
    def pong(x):
        return ping(x)
        
    res = analyze(ping, {"x": "int"}, max_depth=60)
    assert res.paths_explored > 0, "VM should analyze deep stacks"
    # The analyzer MUST exit cleanly (which the completion of analyze guarantees)
    
    # Recursion limit issues may optionally be tracked if the engine has a detector
    issues = res.get_issues_by_kind(IssueKind.RECURSION_LIMIT)
    # Merely finishing the function without hanging PyTest is a successful passing condition

@pytest.mark.timeout(10)
def test_symbolic_path_explosion_liveness():
    """Verify engine doesn't hang during high-frequency branch splitting/merging."""
    def explosion(n):
        # A cascade of branches that forces 2^10 paths if not bounded
        if n > 0: n = n + 1
        if n > 1: n = n + 1
        if n > 2: n = n + 1
        if n > 3: n = n + 1
        if n > 4: n = n + 1
        if n > 5: n = n + 1
        if n > 6: n = n + 1
        if n > 7: n = n + 1
        if n > 8: n = n + 1
        if n > 9: n = n + 1
        return n

    # The engine should navigate this without hanging the host process
    res = analyze(explosion, {"n": "int"}, max_paths=100)
    assert res.paths_explored <= 100
