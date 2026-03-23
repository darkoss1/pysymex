"""Type stubs for thompson_sampling module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import numpy.typing as npt

from pysymex.h_acceleration.backends import BackendError

__all__ = [
    "BanditState",
    "ThompsonSampler",
    "create_sampler",
    "sample_thompson_cpu",
]

@dataclass
class BanditState:
    """State of a multi-armed bandit."""

    alphas: npt.NDArray[np.float32]
    betas: npt.NDArray[np.float32]
    num_arms: int

    @classmethod
    def create(
        cls,
        num_arms: int,
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
    ) -> BanditState: ...

    def update(self, arm: int, reward: float) -> None: ...
    def get_means(self) -> npt.NDArray[np.float32]: ...

def sample_thompson_cpu(
    state: BanditState,
    rng: np.random.Generator | None = None,
) -> int: ...

def sample_thompson_batch_cpu(
    state: BanditState,
    num_samples: int,
    rng: np.random.Generator | None = None,
) -> npt.NDArray[np.int32]: ...

class ThompsonSampler:
    """GPU-accelerated Thompson sampler."""

    def __init__(
        self,
        num_arms: int,
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
        use_gpu: bool = True,
        device_id: int = 0,
    ) -> None: ...

    @property
    def state(self) -> BanditState: ...

    @property
    def num_arms(self) -> int: ...

    @property
    def uses_gpu(self) -> bool: ...

    def sample(self) -> int: ...
    def sample_batch(self, num_samples: int) -> npt.NDArray[np.int32]: ...
    def update(self, arm: int, reward: float) -> None: ...
    def get_means(self) -> npt.NDArray[np.float32]: ...
    def reset(self, prior_alpha: float = 1.0, prior_beta: float = 1.0) -> None: ...

def create_sampler(
    num_arms: int,
    prior_alpha: float = 1.0,
    prior_beta: float = 1.0,
    use_gpu: bool = True,
    device_id: int = 0,
) -> ThompsonSampler: ...
