from pysymex import analyze

def test_analysis_isolation():
    def simple_div(x):
        return 10 / x

    # Run once
    res1 = analyze(simple_div, {"x": "int"})
    
    # Run twice
    res2 = analyze(simple_div, {"x": "int"})
    
    assert res1.paths_explored == res2.paths_explored, "Path exploration count changed between identical runs"
    assert len(res1.issues) == len(res2.issues), "Issue count changed between identical runs"
    
    # Verify counterexamples are independent dictionaries to prevent state leakage
    ce1 = res1.issues[0].get_counterexample()
    ce2 = res2.issues[0].get_counterexample()
    ce1["mutated"] = True
    assert "mutated" not in ce2, "Global state leakage: Modifying one counterexample modified the other"
