"""GPU-Accelerated Thompson Sampling for Path Scheduling.

Provides Bayesian multi-armed bandit sampling using Beta distributions.
Can use GPU acceleration for batch sampling when available.

Thompson Sampling enables intelligent path selection in symbolic execution
by balancing exploration of new paths with exploitation of known-good paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import numpy as np

from pysymex.h_acceleration.backends import BackendError

if TYPE_CHECKING:
    from numba.cuda.cudadrv.devicearray import DeviceNDArray

__all__ = [
    "BanditState",
    "ThompsonSampler",
    "create_sampler",
    "sample_thompson_cpu",
]

@dataclass
class BanditState:
    """State of a multi-armed bandit.

    Tracks Beta distribution parameters for each arm.

    Attributes:
        alphas: Alpha parameters (successes + prior)
        betas: Beta parameters (failures + prior)
        num_arms: Number of bandit arms
    """
    alphas: np.ndarray[tuple[int], np.dtype[np.float32]]
    betas: np.ndarray[tuple[int], np.dtype[np.float32]]
    num_arms: int

    @classmethod
    def create(
        cls,
        num_arms: int,
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
    ) -> BanditState:
        """Create new bandit state with uniform priors.

        Args:
            num_arms: Number of bandit arms
            prior_alpha: Prior success count (default: 1.0)
            prior_beta: Prior failure count (default: 1.0)

        Returns:
            Initialized BanditState
        """
        return cls(
            alphas=np.full(num_arms, prior_alpha, dtype=np.float32),
            betas=np.full(num_arms, prior_beta, dtype=np.float32),
            num_arms=num_arms,
        )

    def update(self, arm: int, reward: float) -> None:
        """Update bandit statistics with observed reward.

        Args:
            arm: Arm index to update
            reward: Reward value (0.0 to 1.0)
        """
        self.alphas[arm] += reward
        self.betas[arm] += (1.0 - reward)

    def get_means(self) -> np.ndarray[tuple[int], np.dtype[np.float32]]:
        """Compute mean success probability for each arm.

        Returns:
            Array of posterior means
        """
        result: np.ndarray[tuple[int], np.dtype[np.float32]] = (self.alphas / (self.alphas + self.betas)).astype(np.float32)
        return result

def sample_thompson_cpu(
    state: BanditState,
    rng: np.random.Generator | None = None,
) -> int:
    """Single Thompson sample using CPU.

    Draws one sample from each arm's Beta posterior and selects
    the arm with the highest sampled value.

    Args:
        state: Current bandit state
        rng: Random number generator (creates default if None)

    Returns:
        Selected arm index
    """
    if rng is None:
        rng = np.random.default_rng()

    samples = rng.beta(state.alphas, state.betas)
    return int(np.argmax(samples))

def sample_thompson_batch_cpu(
    state: BanditState,
    num_samples: int,
    rng: np.random.Generator | None = None,
) -> np.ndarray[tuple[int], np.dtype[np.int32]]:
    """Batch Thompson sampling using CPU.

    Draws multiple independent samples for parallel evaluation.

    Args:
        state: Current bandit state
        num_samples: Number of samples to draw
        rng: Random number generator (creates default if None)

    Returns:
        Array of selected arm indices
    """
    if rng is None:
        rng = np.random.default_rng()

    samples = rng.beta(
        state.alphas[np.newaxis, :],
        state.betas[np.newaxis, :],
        size=(num_samples, state.num_arms),
    )

    return np.argmax(samples, axis=1).astype(np.int32)

_cuda_available: bool = False
_cuda_kernel: dict[str, Any] | None = None
try:
    import math

    from numba import cuda
    from numba.cuda.random import xoroshiro128p_uniform_float32
    _cuda_available = cuda.is_available()

    if _cuda_available:
        @cuda.jit(device=True)
        def _beta_sample_device(
            rng_states: DeviceNDArray,
            thread_id: int,
            alpha: float,
            beta: float,
        ) -> float:
            if alpha >= 1.0 and beta >= 1.0:
                a = alpha + beta
                b = 1.0 / beta if alpha < beta else 1.0 / alpha
                c_val = alpha + 1.0 / b

                while True:
                    u1 = xoroshiro128p_uniform_float32(rng_states, thread_id)
                    u2 = xoroshiro128p_uniform_float32(rng_states, thread_id)

                    if u1 < 1e-10:
                        u1 = 1e-10

                    v = b * math.log(u1 / (1.0 - u1))
                    w = alpha * math.exp(v)

                    z = u1 * u1 * u2
                    r = c_val * v - 1.3862944
                    s = alpha + r - w

                    if s + 2.609438 >= 5.0 * z:
                        break

                    t = math.log(z)
                    if s >= t:
                        break

                    if r + a * math.log(a / (w + beta)) >= t:
                        break

                if alpha < beta:
                    return w / (w + beta)
                else:
                    return w / (w + beta)

            else:
                x = 0.0
                y = 0.0

                if alpha < 1:
                    u = xoroshiro128p_uniform_float32(rng_states, thread_id)
                    x = _gamma_sample_small(rng_states, thread_id, alpha + 1.0)
                    x = x * math.pow(u, 1.0 / alpha)
                else:
                    x = _gamma_sample_small(rng_states, thread_id, alpha)

                if beta < 1:
                    u = xoroshiro128p_uniform_float32(rng_states, thread_id)
                    y = _gamma_sample_small(rng_states, thread_id, beta + 1.0)
                    y = y * math.pow(u, 1.0 / beta)
                else:
                    y = _gamma_sample_small(rng_states, thread_id, beta)

                return x / (x + y)

        @cuda.jit(device=True)
        def _gamma_sample_small(
            rng_states: DeviceNDArray,
            thread_id: int,
            shape: float,
        ) -> float:
            d = shape - 1.0/3.0
            c = 1.0 / math.sqrt(9.0 * d)

            while True:
                while True:
                    x = _standard_normal(rng_states, thread_id)
                    v = 1.0 + c * x
                    if v > 0:
                        break

                v = v * v * v
                u = xoroshiro128p_uniform_float32(rng_states, thread_id)

                if u < 1.0 - 0.0331 * x * x * x * x:
                    return d * v

                if math.log(u) < 0.5 * x * x + d * (1.0 - v + math.log(v)):
                    return d * v

        @cuda.jit(device=True)
        def _standard_normal(
            rng_states: DeviceNDArray,
            thread_id: int,
        ) -> float:
            u1 = xoroshiro128p_uniform_float32(rng_states, thread_id)
            u2 = xoroshiro128p_uniform_float32(rng_states, thread_id)

            if u1 < 1e-10:
                u1 = 1e-10

            return math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)

        @cuda.jit
        def _thompson_sample_kernel(
            alphas: DeviceNDArray,
            betas: DeviceNDArray,
            samples: DeviceNDArray,
            rng_states: DeviceNDArray,
        ) -> None:
            tid = cuda.grid(1)
            if tid < alphas.shape[0]:
                samples[tid] = _beta_sample_device(
                    rng_states, tid, alphas[tid], betas[tid]
                )

        @cuda.jit
        def _thompson_batch_kernel(
            alphas: DeviceNDArray,
            betas: DeviceNDArray,
            selections: DeviceNDArray,
            rng_states: DeviceNDArray,
            num_samples: int,
        ) -> None:
            tid = cuda.grid(1)
            if tid >= num_samples:
                return

            num_arms = alphas.shape[0]
            best_arm = 0
            best_sample = -1.0

            for arm in range(num_arms):
                sample = _beta_sample_device(
                    rng_states, tid * num_arms + arm,
                    alphas[arm], betas[arm]
                )
                if sample > best_sample:
                    best_sample = sample
                    best_arm = arm

            selections[tid] = best_arm

        _cuda_kernel = {
            'sample': _thompson_sample_kernel,
            'batch': _thompson_batch_kernel,
        }

except ImportError:
    pass

class ThompsonSampler:
    """GPU-accelerated Thompson sampler with Beta priors.

    Provides efficient sampling from Beta posteriors using either
    CUDA kernels for batch operations or NumPy for single samples.

    Attributes:
        state: Current bandit state with Beta parameters
        backend: String indicating "CUDA" or "CPU" backend
        num_arms: Number of bandit arms
    """

    def __init__(
        self,
        num_arms: int,
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
        use_gpu: bool = True,
        seed: int | None = None,
    ) -> None:
        """Initialize Thompson sampler.

        Args:
            num_arms: Number of bandit arms
            prior_alpha: Prior alpha (success count)
            prior_beta: Prior beta (failure count)
            use_gpu: Use CUDA if available
            seed: Random seed for reproducibility
        """
        self.state = BanditState.create(num_arms, prior_alpha, prior_beta)
        self._use_gpu = use_gpu and _cuda_available
        self._rng = np.random.default_rng(seed)
        self._rng_states: DeviceNDArray | None = None

        if self._use_gpu:
            from numba.cuda.random import create_xoroshiro128p_states
            self._rng_states = create_xoroshiro128p_states(
                max(num_arms, 1024),
                seed=seed or 42,
            )

    @property
    def num_arms(self) -> int:
        return self.state.num_arms

    @property
    def backend(self) -> str:
        return "CUDA" if self._use_gpu else "CPU"

    def sample(self) -> int:
        """Draw single Thompson sample.

        Returns:
            Selected arm index
        """
        if self._use_gpu:
            return self._sample_gpu()
        return sample_thompson_cpu(self.state, self._rng)

    def _sample_gpu(self) -> int:
        """Internal GPU sampling using CUDA kernel.

        Returns:
            Selected arm index
        """
        from numba import cuda

        d_alphas = cuda.to_device(self.state.alphas)
        d_betas = cuda.to_device(self.state.betas)
        d_samples: DeviceNDArray = cuda.device_array(self.num_arms, dtype=np.float32)

        threads = max(1, min(256, self.num_arms))
        blocks = (self.num_arms + threads - 1) // threads
        if blocks == 1 and self.num_arms > 1:
            # Avoid single-block launches on tiny workloads; this reduces
            # Numba's low-occupancy warnings in test/dev environments.
            threads = max(1, self.num_arms // 2)
            blocks = (self.num_arms + threads - 1) // threads

        if _cuda_kernel is None:
            raise BackendError("CUDA kernel not available")

        _cuda_kernel['sample'][blocks, threads](
            d_alphas, d_betas, d_samples, self._rng_states
        )

        samples = d_samples.copy_to_host()
        return int(np.argmax(samples))

    def sample_batch(self, num_samples: int) -> np.ndarray[tuple[int], np.dtype[np.int32]]:
        """Draw batch of Thompson samples.

        Args:
            num_samples: Number of samples to draw

        Returns:
            Array of selected arm indices
        """
        if self._use_gpu:
            return self._sample_batch_gpu(num_samples)
        return sample_thompson_batch_cpu(self.state, num_samples, self._rng).astype(np.int32)

    def _sample_batch_gpu(self, num_samples: int) -> np.ndarray[tuple[int], np.dtype[np.int32]]:
        """Internal GPU batch sampling using CUDA kernel.

        Args:
            num_samples: Number of samples to draw

        Returns:
            Array of selected arm indices
        """
        from numba import cuda
        from numba.cuda.random import create_xoroshiro128p_states

        rng_states = create_xoroshiro128p_states(
            num_samples * self.num_arms,
            seed=int(self._rng.integers(2**31)),
        )

        d_alphas = cuda.to_device(self.state.alphas)
        d_betas = cuda.to_device(self.state.betas)
        d_selections: DeviceNDArray = cuda.device_array(num_samples, dtype=np.int32)

        threads = max(1, min(256, num_samples))
        blocks = (num_samples + threads - 1) // threads
        if blocks == 1 and num_samples > 1:
            # Same policy as single-sample path: prefer >=2 blocks for
            # small batches to avoid occupancy warnings.
            threads = max(1, num_samples // 2)
            blocks = (num_samples + threads - 1) // threads

        if _cuda_kernel is None:
            raise BackendError("CUDA kernel not available")

        _cuda_kernel['batch'][blocks, threads](
            d_alphas, d_betas, d_selections, rng_states, num_samples
        )

        return d_selections.copy_to_host()

    def update(self, arm: int, reward: float) -> None:
        """Update arm statistics with reward observation.

        Args:
            arm: Arm index that was pulled
            reward: Observed reward (0.0 to 1.0)
        """
        self.state.update(arm, reward)

    def get_means(self) -> np.ndarray[tuple[int], np.dtype[np.float32]]:
        """Get posterior mean for each arm.

        Returns:
            Array of posterior means
        """
        return self.state.get_means()

    def get_upper_confidence_bounds(
        self,
        quantile: float = 0.95,
    ) -> np.ndarray[tuple[int], np.dtype[np.float64]]:
        """Compute upper confidence bounds using Beta quantiles.

        Args:
            quantile: Confidence level (default: 0.95)

        Returns:
            Array of upper confidence bounds
        """
        try:
            from scipy import stats
        except ImportError:
            raise BackendError("SciPy required for UCBs")
        ucbs: np.ndarray[tuple[int], np.dtype[np.float64]] = np.zeros(self.num_arms)
        for i in range(self.num_arms):
            ucbs[i] = stats.beta.ppf(quantile, self.state.alphas[i], self.state.betas[i])
        return ucbs

def create_sampler(
    num_arms: int,
    use_gpu: bool = True,
    seed: int | None = None,
) -> ThompsonSampler:
    """Create Thompson sampler with default priors.

    Args:
        num_arms: Number of bandit arms
        use_gpu: Use CUDA acceleration if available
        seed: Random seed for reproducibility

    Returns:
        Initialized ThompsonSampler
    """
    return ThompsonSampler(num_arms, use_gpu=use_gpu, seed=seed)
