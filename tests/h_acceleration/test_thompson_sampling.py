"""
Thompson Sampling Tests.

Tests for the GPU-accelerated Thompson Sampling implementation.
"""

from __future__ import annotations

import pytest
import numpy as np

class TestBanditState:
    """Test BanditState dataclass."""

    def test_create_default_prior(self):
        """Test creating state with default prior."""
        from pysymex.h_acceleration.thompson_sampling import BanditState

        state = BanditState.create(5)

        assert state.num_arms == 5
        assert len(state.alphas) == 5
        assert len(state.betas) == 5
        assert np.all(state.alphas == 1.0)
        assert np.all(state.betas == 1.0)

    def test_create_custom_prior(self):
        """Test creating state with custom prior."""
        from pysymex.h_acceleration.thompson_sampling import BanditState

        state = BanditState.create(3, prior_alpha=2.0, prior_beta=1.0)

        assert np.all(state.alphas == 2.0)
        assert np.all(state.betas == 1.0)

    def test_update(self):
        """Test updating posterior."""
        from pysymex.h_acceleration.thompson_sampling import BanditState

        state = BanditState.create(3)

        state.update(0, 1.0)
        assert state.alphas[0] == 2.0
        assert state.betas[0] == 1.0

        state.update(1, 0.0)
        assert state.alphas[1] == 1.0
        assert state.betas[1] == 2.0

    def test_get_means(self):
        """Test posterior means."""
        from pysymex.h_acceleration.thompson_sampling import BanditState

        state = BanditState.create(2)
        state.update(0, 1.0)                          
        state.update(1, 0.0)                          

        means = state.get_means()

        assert np.isclose(means[0], 2/3)
        assert np.isclose(means[1], 1/3)

class TestSampleThompsonCPU:
    """Test CPU sampling implementation."""

    def test_single_sample(self):
        """Test single sample returns valid arm."""
        from pysymex.h_acceleration.thompson_sampling import BanditState, sample_thompson_cpu

        state = BanditState.create(5)
        rng = np.random.default_rng(42)

        arm = sample_thompson_cpu(state, rng)

        assert 0 <= arm < 5

    def test_deterministic_with_seed(self):
        """Test reproducibility with seed."""
        from pysymex.h_acceleration.thompson_sampling import BanditState, sample_thompson_cpu

        state = BanditState.create(5)

        arms1 = [sample_thompson_cpu(state, np.random.default_rng(42)) for _ in range(10)]
        arms2 = [sample_thompson_cpu(state, np.random.default_rng(42)) for _ in range(10)]

        assert arms1 == arms2

    def test_batch_sample(self):
        """Test batch sampling."""
        from pysymex.h_acceleration.thompson_sampling import BanditState, sample_thompson_batch_cpu

        state = BanditState.create(3)
        rng = np.random.default_rng(42)

        arms = sample_thompson_batch_cpu(state, 100, rng)

        assert len(arms) == 100
        assert np.all((arms >= 0) & (arms < 3))

    def test_biased_arm_selected_more(self):
        """Test that arm with higher posterior is selected more often."""
        from pysymex.h_acceleration.thompson_sampling import BanditState, sample_thompson_batch_cpu

        state = BanditState.create(3)

        for _ in range(20):
            state.update(0, 1.0)

        rng = np.random.default_rng(42)
        arms = sample_thompson_batch_cpu(state, 1000, rng)

        counts = np.bincount(arms, minlength=3)
        assert counts[0] > counts[1]
        assert counts[0] > counts[2]

def _cuda_available() -> bool:
    """Check if CUDA is available for testing."""
    try:
        from numba import cuda
        return cuda.is_available()
    except ImportError:
        return False

class TestThompsonSampler:
    """Test ThompsonSampler unified interface."""

    def test_cpu_backend(self):
        """Test with CPU backend."""
        from pysymex.h_acceleration.thompson_sampling import ThompsonSampler

        sampler = ThompsonSampler(5, use_gpu=False, seed=42)

        assert sampler.num_arms == 5
        assert sampler.backend == "CPU"

        arm = sampler.sample()
        assert 0 <= arm < 5

    def test_update_and_sample(self):
        """Test update affects sampling."""
        from pysymex.h_acceleration.thompson_sampling import ThompsonSampler

        sampler = ThompsonSampler(3, use_gpu=False, seed=42)

        for _ in range(50):
            sampler.update(0, 1.0)

        samples = sampler.sample_batch(100)
        counts = np.bincount(samples, minlength=3)

        assert counts[0] > 50                                     

    def test_get_means(self):
        """Test posterior means."""
        from pysymex.h_acceleration.thompson_sampling import ThompsonSampler

        sampler = ThompsonSampler(2, use_gpu=False)

        sampler.update(0, 1.0)
        sampler.update(0, 1.0)
        sampler.update(1, 0.0)

        means = sampler.get_means()

        assert means[0] > means[1]

    @pytest.mark.skipif(
        not _cuda_available(),
        reason="CUDA not available"
    )
    @pytest.mark.filterwarnings("ignore::UserWarning")
    def test_gpu_backend(self):
        """Test with CUDA backend if available."""
        from pysymex.h_acceleration.thompson_sampling import ThompsonSampler

        sampler = ThompsonSampler(5, use_gpu=True, seed=42)

        if sampler.backend == "CUDA":
            arm = sampler.sample()
            assert 0 <= arm < 5

            samples = sampler.sample_batch(100)
            assert len(samples) == 100

def _cuda_available() -> bool:
    """Check if CUDA is available for testing."""
    try:
        from numba import cuda
        return cuda.is_available()
    except ImportError:
        return False

class TestStatisticalCorrectness:
    """Statistical tests for sampling correctness."""

    def test_beta_distribution_moments(self):
        """Test that samples match expected Beta distribution moments."""
        from pysymex.h_acceleration.thompson_sampling import BanditState, sample_thompson_batch_cpu

        state = BanditState.create(1, prior_alpha=3.0, prior_beta=2.0)
        rng = np.random.default_rng(42)

        samples = rng.beta(3.0, 2.0, size=10000)

        mean = np.mean(samples)
        var = np.var(samples)

        expected_mean = 3 / 5
        expected_var = (3 * 2) / ((3 + 2)**2 * (3 + 2 + 1))

        assert np.isclose(mean, expected_mean, atol=0.02)
        assert np.isclose(var, expected_var, atol=0.01)

    def test_arm_selection_convergence(self):
        """Test that best arm is identified over time."""
        from pysymex.h_acceleration.thompson_sampling import ThompsonSampler

        sampler = ThompsonSampler(3, use_gpu=False, seed=42)

        true_probs = [0.8, 0.5, 0.2]                 
        rng = np.random.default_rng(42)

        arm_counts = np.zeros(3)
        for _ in range(500):
            arm = sampler.sample()
            arm_counts[arm] += 1

            reward = float(rng.random() < true_probs[arm])
            sampler.update(arm, reward)

        assert arm_counts[0] > arm_counts[1]
        assert arm_counts[0] > arm_counts[2]

        means = sampler.get_means()
        assert means[0] > means[1] > means[2]
