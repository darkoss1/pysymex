"""Topological Thompson Sampling for Acceleration Work Selection.

Uses a normalized continuous reward to prevent hyperparameter fragility.
"""

import random
from dataclasses import dataclass


class BanditLayer:
    """A single layer in the hierarchical Thompson Sampling bandit."""

    def __init__(self, arm_names: list[str], rng: random.Random | None = None):
        self.arms = {name: {"alpha": 1.0, "beta": 1.0} for name in arm_names}
        self._rng = rng or random.Random()

    def sample(self) -> str:
        """Sample from the Beta distribution for each arm and return the max."""
        best_arm = None
        max_sample = -1.0
        for name, params in self.arms.items():
            # betavariate requires alpha, beta > 0
            alpha = max(0.001, params["alpha"])
            beta = max(0.001, params["beta"])
            sample = self._rng.betavariate(alpha, beta)
            if sample > max_sample:
                max_sample = sample
                best_arm = name

        if best_arm is None:
            raise ValueError("No arms configured in BanditLayer.")

        return best_arm

    def update_arm(self, arm: str, reward: float, eta: float = 1.0) -> None:
        """Apply a fractional Thompson-style update using a reward in [0, 1]."""
        if arm not in self.arms:
            raise ValueError(f"Unknown arm: {arm}")

        # Continuous fraction update
        self.arms[arm]["alpha"] = max(0.001, self.arms[arm]["alpha"] + eta * reward)
        self.arms[arm]["beta"] = max(0.001, self.arms[arm]["beta"] + eta * (1.0 - reward))


@dataclass
class RewardMetrics:
    pruned_frontier: int
    centrality: float
    core_size: int
    subtree_reach: float
    separator_size: int
    core_reuse: int
    subtree_width: int
    solve_time_ms: float
    minimize_time_ms: float


class HierarchicalThompsonScheduler:
    """Manages TS arms using a fractional continuous reward in [0, 1] across hierarchical policies."""

    def __init__(self, rng: random.Random | None = None):
        self._rng = rng or random.Random()
        self.decomposition = BanditLayer(
            [
                "min-fill",
                "weighted min-fill",
                "theory-aware min-fill",
                "core-aware min-fill",
                "incremental repair",
            ],
            self._rng,
        )

        self.target = BanditLayer(
            [
                "smallest active bag",
                "highest centrality bag",
                "highest frontier-reuse bag",
                "separator-heavy bag",
                "recent-core-neighborhood bag",
            ],
            self._rng,
        )

        self.path = BanditLayer(
            [
                "DFS",
                "BFS",
                "coverage-guided",
                "low-width-first",
                "high-reuse-potential-first",
                "solver-cheap-first",
                "rare-branch-first",
            ],
            self._rng,
        )

        self.budget = BanditLayer(
            [
                "no minimization",
                "small minimization budget",
                "reuse-weighted minimization",
                "full-path fallback",
            ],
            self._rng,
        )

        self.window_size = 100
        self._solver_ms_history: list[float] = []

    def compute_chtd_yield(self, metrics: RewardMetrics) -> float:
        """
        Computes the CHTD-aware yield for reward calculation.
        R = clamp(...)
        """
        import math

        # Hyperparameters representing W1..W6 in the CHTD yield formula
        w1, w2, w3, w4, w5, w6 = 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
        tau = 1.0

        part1 = w1 * math.log(1.0 + metrics.pruned_frontier)
        part2 = w2 * (metrics.centrality / max(1.0, metrics.core_size**tau))
        part3 = w3 * (metrics.subtree_reach / (1.0 + metrics.separator_size))
        part4 = w4 * (metrics.core_reuse / (1.0 + metrics.subtree_width))

        # Update solver history for normalization
        self._solver_ms_history.append(metrics.solve_time_ms + metrics.minimize_time_ms)
        if len(self._solver_ms_history) > self.window_size:
            self._solver_ms_history.pop(0)

        # Compute running average for normalization
        avg_cost = sum(self._solver_ms_history) / len(self._solver_ms_history)
        norm_cost = (
            (metrics.solve_time_ms * w5 + metrics.minimize_time_ms * w6) / avg_cost
            if avg_cost > 0
            else (metrics.solve_time_ms * w5 + metrics.minimize_time_ms * w6)
        )

        raw_reward = part1 + part2 + part3 + part4 - norm_cost

        # Sigmoid squash to [0, 1]
        reward = 1.0 / (1.0 + math.exp(-raw_reward))
        return reward
