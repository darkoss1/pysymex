import heapq
import itertools
import random
from typing import Dict, Generic, List, Optional, TypeVar

from pysymex.core.graph.cig import ConstraintInteractionGraph
from pysymex.execution.strategies.manager import PathManager

T = TypeVar("T")

class PrioritizedState(Generic[T]):
    __slots__ = ("priority", "counter", "state")
    
    def __init__(self, priority: float, counter: int, state: T):
        self.priority = priority
        self.counter = counter
        self.state = state
        
    def __lt__(self, other: 'PrioritizedState[T]') -> bool:
        if self.priority == other.priority:
            return self.counter < other.counter
        return self.priority > other.priority  # Higher priority comes first

class TopologicalThompsonSampling:
    """
    Beta-Bernoulli multi-armed bandit with Topological Information Yield.
    Adaptive exploration strategy based on the Constraint Interaction Graph (CIG).
    """
    __slots__ = ("rho", "lam", "tau", "gamma", "arms", "last_arm", "_rng")

    def __init__(self, rho: float = 0.1, lam: float = 1.0, tau: float = 1.5, gamma: float = 0.95):
        self.rho = rho
        self.lam = lam
        self.tau = tau
        self.gamma = gamma
        
        # Beta priors for arms: [alpha, beta]
        self.arms = {
            "topological": [2.0, 1.0],
            "coverage": [2.0, 1.0],
            "random": [1.0, 1.0],
        }
        self.last_arm: Optional[str] = None
        self._rng = random.Random(42)

    def calculate_y_topo(self, core_pcs: List[int], cig: ConstraintInteractionGraph) -> float:
        """
        Calculates Topological Information Yield.
        Y_topo(C_MUS, G) = -rho + lambda * (sum(deg_G(v) for v in C_MUS) / |C_MUS|^tau)
        Returns the scalar yield score.
        """
        if not core_pcs:
            return 0.0
            
        sum_deg = sum(cig.get_degree(v) for v in core_pcs)
        core_size = len(core_pcs)
        
        y_topo = -self.rho + self.lam * (sum_deg / (core_size ** self.tau))
        return y_topo

    def select_arm(self) -> str:
        """Samples from Beta distribution to select the best strategy arm."""
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
        """
        Applies reward to the specific arm using Beta-Bernoulli conjugate updating
        with a discount factor (gamma) for non-stationary environments.
        Limits reward to [0, 1] range to preserve Beta conjugacy mathematically.
        """
        normalized_reward = max(0.0, min(1.0, reward))
        alpha, beta = self.arms[arm]
        
        # Discount old values (decay towards uniform prior 1.0, 1.0)
        self.arms[arm][0] = 1.0 + self.gamma * (alpha - 1.0) + normalized_reward
        self.arms[arm][1] = 1.0 + self.gamma * (beta - 1.0) + (1.0 - normalized_reward)

class AdaptivePathManagerV2(PathManager[T]):
    """
    v2 Adaptive Path Manager utilizing Topological Thompson Sampling (TTS).
    """
    def __init__(self, cig: ConstraintInteractionGraph):
        self.cig = cig
        self.tts = TopologicalThompsonSampling()
        self._states: Dict[int, T] = {}
        self._counter = itertools.count()
        self._heap_topological: List[PrioritizedState[int]] = []
        self._heap_coverage: List[PrioritizedState[int]] = []
        self._random_pool: List[int] = []

    def add_state(self, state: T, state_id: Optional[int] = None, pc: int = 0, depth: int = 0) -> None:
        """Adds a state to the manager with its required metadata."""
        count = next(self._counter)
        if state_id is None:
            state_id = count
        self._states[state_id] = state
        
        # Heuristics for topological priority: high degree PCs get higher priority
        topo_score = self.cig.get_degree(pc) * 10.0 - depth
        heapq.heappush(self._heap_topological, PrioritizedState(topo_score, count, state_id))
        
        # Coverage heuristic (simplified: depth-first search like)
        cov_score = float(depth)
        heapq.heappush(self._heap_coverage, PrioritizedState(cov_score, count, state_id))
        
        self._random_pool.append(state_id)

    def get_next_state(self) -> Optional[T]:
        """Pulls the next state according to TTS strategy arm."""
        if not self._states:
            return None
            
        while True:
            arm = self.tts.select_arm()
            state_id = None
            
            if arm == "topological" and self._heap_topological:
                state_id = heapq.heappop(self._heap_topological).state
            elif arm == "coverage" and self._heap_coverage:
                state_id = heapq.heappop(self._heap_coverage).state
            elif arm == "random" and self._random_pool:
                idx = random.randint(0, len(self._random_pool) - 1)
                state_id = self._random_pool.pop(idx)
                
            if state_id is not None and state_id in self._states:
                state = self._states.pop(state_id)
                return state
                
            if not self._heap_topological and not self._heap_coverage and not self._random_pool:
                return None

    def is_empty(self) -> bool:
        return len(self._states) == 0

    def size(self) -> int:
        return len(self._states)
        
    def feedback_mus(self, core_pcs: List[int]) -> None:
        """
        Feedback loop for when an UNSAT core is found.
        Rewards the Topological arm based on Y_topo.
        """
        if self.tts.last_arm == "topological":
            y_topo = self.tts.calculate_y_topo(core_pcs, self.cig)
            # Normalize y_topo into a reward [0, 1] mapping (heuristically)
            reward = max(0.0, min(1.0, y_topo / 10.0))
            self.tts.update_reward("topological", reward)
