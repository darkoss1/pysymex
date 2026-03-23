from pysymex import analyze
from pysymex.analysis.detectors import IssueKind

def test_symbolic_array_oob():
    def array_access(idx):
        arr = [1, 2, 3, 4, 5]
        return arr[idx]
        
    res = analyze(array_access, {"idx": "int"})
    issues = res.get_issues_by_kind(IssueKind.INDEX_ERROR)
    
    assert len(issues) > 0, "Should detect out of bounds array access"
    ce = issues[0].get_counterexample()
    assert "idx" in ce, "Counterexample should specify exact offending index"
    
    val = ce["idx"]
    assert val >= 5 or val < -5, f"Counterexample {val} should be strictly Out of Bounds for length 5"

def test_symbolic_array_safe_bounds():
    def safe_access(idx):
        arr = [1, 2, 3, 4, 5]
        if 0 <= idx < 5:
            return arr[idx]
        return 0
        
    res = analyze(safe_access, {"idx": "int"})
    issues = res.get_issues_by_kind(IssueKind.INDEX_ERROR)
    assert len(issues) == 0, "Guard should prevent OOB detection cleanly"
