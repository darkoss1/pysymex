# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Path exploration strategies for symbolic execution."""

from __future__ import annotations

import heapq
import itertools
import math
import random
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import TYPE_CHECKING, Dict, Generic, List, Optional, TypeVar

from pysymex.core.graph.cig import ConstraintInteractionGraph

if TYPE_CHECKING:
    from pysymex.core.state import VMState

DEFAULT_RHO = 0.1
DEFAULT_LAM = 1.0
DEFAULT_TAU = 1.5
DEFAULT_GAMMA = 0.95
RANDOM_SEED = 42
TOPOLOGICAL_MULTIPLIER = 10.0
UNIFORM_PRIOR_ALPHA = 1.0
UNIFORM_PRIOR_BETA = 1.0
INFORMED_PRIOR_ALPHA = 2.0
INFORMED_PRIOR_BETA = 1.0


class ExplorationStrategy(Enum):
    """Available path-exploration strategy identifiers."""

    CHTD_NATIVE = auto()
    RANDOM = auto()
    COVERAGE = auto()
    DIRECTED = auto()
    ADAPTIVE = auto()


T = TypeVar("T")


class PathManager(ABC, Generic[T]):
    """Abstract base class for path-exploration managers."""

    @abstractmethod
    def add_state(self, state: T, priority: float = 0.0) -> None:
        """Add a state to explore."""

    @abstractmethod
    def get_next_state(self) -> T | None:
        """Get the next state to explore."""

    @abstractmethod
    def is_empty(self) -> bool:
        """Check if there are states to explore."""

    @abstractmethod
    def size(self) -> int:
        """Get number of pending states."""


class PrioritizedState(Generic[T]):
    __slots__ = ("priority", "counter", "state")

    def __init__(self, priority: float, counter: int, state: T):
        self.priority = priority
        self.counter = counter
        self.state = state

    def __lt__(self, other: "PrioritizedState[T]") -> bool:
        if self.priority == other.priority:
            return self.counter < other.counter
        return self.priority > other.priority


class TopologicalThompsonSampling:
    """
    Beta-Bernoulli multi-armed bandit with Topological Information Yield.
    Adaptive exploration strategy based on the Constraint Interaction Graph (CIG).
    """

    __slots__ = ("rho", "lam", "tau", "gamma", "arms", "last_arm", "_rng", "_total_rewards")

    def __init__(
        self,
        rho: float = DEFAULT_RHO,
        lam: float = DEFAULT_LAM,
        tau: float = DEFAULT_TAU,
        gamma: float = DEFAULT_GAMMA,
    ):
        self.rho = rho
        self.lam = lam
        self.tau = tau
        self.gamma = gamma
        self._total_rewards = 0.0

        self.arms = {
            "topological": [INFORMED_PRIOR_ALPHA, INFORMED_PRIOR_BETA],
            "coverage": [INFORMED_PRIOR_ALPHA, INFORMED_PRIOR_BETA],
            "random": [UNIFORM_PRIOR_ALPHA, UNIFORM_PRIOR_BETA],
        }
        self.last_arm: Optional[str] = None
        self._rng = random.Random(RANDOM_SEED)

    def calculate_y_topo(self, core_pcs: List[int], cig: ConstraintInteractionGraph) -> float:
        if not core_pcs:
            return 0.0

        sum_deg = sum(cig.get_degree(v) for v in core_pcs)
        core_size = len(core_pcs)

        x = self.lam * (sum_deg / (core_size**self.tau)) - self.rho
        try:
            return 1.0 / (1.0 + math.exp(-x))
        except OverflowError:
            return 0.0 if x < 0 else 1.0

    def select_arm(self) -> str:
        best_score = -1.0
        best_arm = "random"

        for arm, (alpha, beta) in self.arms.items():
            sample = self._rng.betavariate(alpha, beta)
            if sample > best_score:
                best_score = sample
                best_arm = arm

        self.last_arm = best_arm
        return best_arm

    def update_reward(self, arm: str, reward: float) -> None:
        self._total_rewards += reward
        normalized_reward = max(0.0, min(1.0, reward))
        alpha, beta = self.arms[arm]

        self.arms[arm][0] = (
            UNIFORM_PRIOR_ALPHA + self.gamma * (alpha - UNIFORM_PRIOR_ALPHA) + normalized_reward
        )
        self.arms[arm][1] = (
            UNIFORM_PRIOR_BETA
            + self.gamma * (beta - UNIFORM_PRIOR_BETA)
            + (1.0 - normalized_reward)
        )

    def reseed(self, seed: int) -> None:
        """Reseed the internal RNG for deterministic test runs."""
        self._rng.seed(seed)

    def randint(self, low: int, high: int) -> int:
        """Draw a random integer in ``[low, high]`` from the internal RNG."""
        return self._rng.randint(low, high)

    @property
    def total_rewards(self) -> float:
        """Cumulative reward mass observed across all arms."""
        return self._total_rewards


class AdaptivePathManager(PathManager["VMState"]):
    """
    Adaptive Path Manager utilizing Topological Thompson Sampling (TTS).
    """

    ARM_STRUCTURAL = "topological"
    ARM_COVERAGE = "coverage"
    ARM_RANDOM = "random"

    def __init__(
        self, cig: ConstraintInteractionGraph, deterministic: bool = False, random_seed: int = 42
    ):
        self.cig = cig
        self.tts = TopologicalThompsonSampling()
        if deterministic:
            self.tts.reseed(random_seed)
        self._states: Dict[int, "VMState"] = {}
        self._counter = itertools.count()
        self._heap_topological: List[PrioritizedState[int]] = []
        self._heap_coverage: List[PrioritizedState[int]] = []
        self._random_pool: List[int] = []
        self._covered_pcs: set[int] = set()

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        _ = priority
        count = next(self._counter)
        state_id = count
        pc = state.pc
        depth = state.depth
        self._states[state_id] = state

        topo_score = self.cig.get_degree(pc) * TOPOLOGICAL_MULTIPLIER - depth
        heapq.heappush(self._heap_topological, PrioritizedState(topo_score, count, state_id))

        cov_score = float(depth)
        heapq.heappush(self._heap_coverage, PrioritizedState(cov_score, count, state_id))

        self._random_pool.append(state_id)

    def _pop_topological(self) -> Optional["VMState"]:
        while self._heap_topological:
            state_id = heapq.heappop(self._heap_topological).state
            if state_id in self._states:
                state = self._states.pop(state_id)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def _pop_coverage(self) -> Optional["VMState"]:
        while self._heap_coverage:
            state_id = heapq.heappop(self._heap_coverage).state
            if state_id in self._states:
                state = self._states.pop(state_id)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def _pop_random(self) -> Optional["VMState"]:
        while self._random_pool:
            idx = self.tts.randint(0, len(self._random_pool) - 1)
            self._random_pool[idx], self._random_pool[-1] = (
                self._random_pool[-1],
                self._random_pool[idx],
            )
            state_id = self._random_pool.pop()

            if state_id in self._states:
                state = self._states.pop(state_id)
                self._covered_pcs.update(state.visited_pcs)
                return state
        return None

    def get_next_state(self) -> Optional["VMState"]:
        if not self._states:
            return None

        arm = self.tts.select_arm()

        dispatch = {
            "topological": self._pop_topological,
            "coverage": self._pop_coverage,
            "random": self._pop_random,
        }

        state = dispatch[arm]()
        if state is not None:
            return state

        for fallback_arm, pop_func in dispatch.items():
            if fallback_arm != arm:
                state = pop_func()
                if state is not None:
                    self.tts.last_arm = fallback_arm
                    return state

        return None

    def is_empty(self) -> bool:
        return len(self._states) == 0

    def size(self) -> int:
        return len(self._states)

    def feedback_mus(self, core_pcs: List[int]) -> None:
        if self.tts.last_arm == "topological":
            y_topo = self.tts.calculate_y_topo(core_pcs, self.cig)
            self.tts.update_reward("topological", y_topo)
        elif self.tts.last_arm == "coverage":
            self.tts.update_reward("coverage", 1.0)
        elif self.tts.last_arm == "random":
            self.tts.update_reward("random", 1.0)

    def record_reward(self, reward: float) -> None:
        if self.tts.last_arm:
            self.tts.update_reward(self.tts.last_arm, reward)

    def reheat_arm(self, arm_name: str, strength: float = 0.5) -> None:
        if arm_name in self.tts.arms:
            strength = max(0.0, min(1.0, strength))
            alpha, beta = self.tts.arms[arm_name]
            self.tts.arms[arm_name][0] = ((1.0 - strength) * alpha) + (
                strength * UNIFORM_PRIOR_ALPHA
            )
            self.tts.arms[arm_name][1] = ((1.0 - strength) * beta) + (strength * UNIFORM_PRIOR_BETA)

    def get_stats(self) -> dict[str, object]:
        return {
            "arms": {k: {"alpha": v[0], "beta": v[1]} for k, v in self.tts.arms.items()},
            "total_rewards": self.tts.total_rewards,
            "covered_pcs": len(self._covered_pcs),
        }


def create_path_manager(
    strategy: ExplorationStrategy,
    cig: Optional[ConstraintInteractionGraph] = None,
    **kwargs: object,
) -> PathManager[VMState]:
    _ = strategy
    if cig is None:
        cig = ConstraintInteractionGraph()
    deterministic_raw = kwargs.get("deterministic", False)
    random_seed_raw = kwargs.get("random_seed", RANDOM_SEED)
    deterministic = bool(deterministic_raw)
    random_seed = random_seed_raw if isinstance(random_seed_raw, int) else RANDOM_SEED
    return AdaptivePathManager(cig, deterministic=deterministic, random_seed=random_seed)
