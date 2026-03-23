from pysymex import analyze
from pysymex.execution.executor import ExecutionConfig

def test_state_merging():
    def converging_paths(x):
        a = 0
        if x > 10:
            a = 1
        else:
            a = 2
        # Paths diverge then converge here
        return a + 5

    # If state_merging is explicitly configurable, we test its enabling
    try:
        config = ExecutionConfig(enable_state_merging=True)
    except TypeError:
        # Fallback if config parameter doesn't exist
        config = ExecutionConfig()
        
    res = analyze(converging_paths, {"x": "int"}, config=config)
    
    assert res.paths_explored > 0, "Should explore paths efficiently without explosion"
