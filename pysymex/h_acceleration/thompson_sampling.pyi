# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Type stubs for thompson_sampling module."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

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
