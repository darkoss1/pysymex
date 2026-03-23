from pysymex import analyze
from pysymex.analysis.path_manager import ExplorationStrategy
from pysymex.execution.executor import ExecutionConfig

def test_thompson_sampling():
    # A function with multiple branches to test path selection
    def branchy(x, y):
        res = 0
        if x > 0:
            res += 1
            if y > 0:
                res += 2
            else:
                res -= 1
        else:
            if y < 0:
                res -= 2
            else:
                res += 1
        return res

    # Using standard search
    config_default = ExecutionConfig(max_paths=10)
    res_default = analyze(branchy, {"x": "int", "y": "int"}, config=config_default)
    
    # Using Thompson Sampling
    config_thompson = ExecutionConfig(
        max_paths=10,
        strategy=ExplorationStrategy.ADAPTIVE,
    )
    res_thompson = analyze(branchy, {"x": "int", "y": "int"}, config=config_thompson)

    assert res_thompson.paths_explored > 0, "Thompson sampling should explore paths"
    assert res_thompson.paths_completed > 0, "Thompson sampling should complete paths"
