from pysymex.accel.thompson import HierarchicalThompsonScheduler, RewardMetrics


def test_thompson_scheduler_initialization():
    scheduler = HierarchicalThompsonScheduler()
    assert "min-fill" in scheduler.decomposition.arms
    assert "DFS" in scheduler.path.arms


def test_compute_chtd_yield():
    scheduler = HierarchicalThompsonScheduler()
    metrics1 = RewardMetrics(
        pruned_frontier=10,
        centrality=1.5,
        core_size=2,
        subtree_reach=3.0,
        separator_size=1,
        core_reuse=5,
        subtree_width=2,
        solve_time_ms=10.0,
        minimize_time_ms=2.0,
    )
    reward1 = scheduler.compute_chtd_yield(metrics1)
    assert 0.0 <= reward1 <= 1.0

    # A better core (more prunes, less time) should have a higher yield
    metrics2 = RewardMetrics(
        pruned_frontier=100,
        centrality=1.5,
        core_size=2,
        subtree_reach=3.0,
        separator_size=1,
        core_reuse=5,
        subtree_width=2,
        solve_time_ms=1.0,
        minimize_time_ms=0.5,
    )
    reward2 = scheduler.compute_chtd_yield(metrics2)
    assert reward2 > reward1


def test_bandit_layer_update():
    scheduler = HierarchicalThompsonScheduler()
    initial_alpha = scheduler.path.arms["DFS"]["alpha"]

    # Positive reward should increase alpha
    scheduler.path.update_arm("DFS", reward=0.8, eta=1.0)
    assert scheduler.path.arms["DFS"]["alpha"] > initial_alpha
