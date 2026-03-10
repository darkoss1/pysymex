import pytest
from pysymex.execution.executor import analyze, ExecutionConfig
from pysymex.analysis.detectors import IssueKind


def test_dict_mutation_persistence():
    """Verify that dict mutation persists across aliased references (Flaw 3.4)."""

    def code_to_test(k_str: str, v: int):
        d = {}
        x = d
        d[k_str] = v
        # If Flaw 3.4 is present, x[k_str] == v will fail because d and x
        # point to the same dict, but the mutation was lost or not aliased.
        assert x[k_str] == v

    # Analyze the function with symbolic arguments
    # Note: we use k_str to ensure it's treated as SymbolicString
    results = analyze(code_to_test, symbolic_args={"k_str": "str", "v": "int"})

    # We expect an assertion failure if the mutation is lost
    assertion_failures = [i for i in results.issues if i.kind == IssueKind.ASSERTION_ERROR]

    # Debug print issues
    for issue in results.issues:
        print(f"Issue found: {issue.kind} - {issue.message}")

    # If the bug is present, there should be an issue
    # If the fix works, there should be NO assertion failures
    assert (
        len(assertion_failures) == 0
    ), f"Mutation was lost! Found assertion failures: {[i.message for i in assertion_failures]}"
