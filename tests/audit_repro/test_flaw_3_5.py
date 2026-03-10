import pytest
from pysymex.core.types_containers import SymbolicDict, SymbolicString
from pysymex.core.types import SymbolicValue
from pysymex.execution.executor import analyze
from pysymex.analysis.detectors import IssueKind


def test_missing_key_oversight():
    """Verify that a symbolic dictionary lookup correctly forks on KeyError."""

    def target_func(k):
        d = {"a": 1, "b": 2}
        # If 'k' is "c", this SHOULD raise KeyError
        res = d[k]
        return res

    # The analyze function should now explore the KeyError path
    results = analyze(target_func, symbolic_args={"k": "str"})

    # Check for KeyError in issues
    key_errors = [p for p in results.issues if p.kind == IssueKind.KEY_ERROR]

    print(f"Paths explored: {results.paths_explored}")
    print(f"KeyErrors found: {len(key_errors)}")

    # We expect at least one KeyError if 'k' can be anything other than "a" or "b"
    assert len(key_errors) > 0, "Should have found at least one KeyError path"
    assert results.paths_explored >= 2, f"Expected at least 2 paths, got {results.paths_explored}"


if __name__ == "__main__":
    test_missing_key_oversight()
