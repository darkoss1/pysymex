from hypothesis import given
from hypothesis import strategies as st
import pytest

from pysymex.accel.backends import BackendError
from pysymex.accel.sampling import (
    BanditState,
    ThompsonSampler,
    create_sampler,
    sample_thompson_batch_cpu,
    sample_thompson_cpu,
)


class TestBanditState:
    def test_create(self) -> None:
        state = BanditState.create(4, prior_alpha=2.0, prior_beta=3.0)
        assert state.num_arms == 4
        assert float(state.alphas[0]) == 2.0
        assert float(state.betas[0]) == 3.0

    @given(reward=st.floats(min_value=0.0, max_value=1.0))
    def test_update(self, reward: float) -> None:
        state = BanditState.create(3)
        old_alpha = float(state.alphas[1])
        old_beta = float(state.betas[1])
        state.update(1, reward)
        assert float(state.alphas[1]) == pytest.approx(old_alpha + reward, rel=1e-6, abs=1e-6)
        assert float(state.betas[1]) == pytest.approx(
            old_beta + (1.0 - reward), rel=1e-6, abs=1e-6
        )

    def test_get_means(self) -> None:
        state = BanditState.create(2)
        state.update(0, 1.0)
        means = state.get_means()
        assert 0.0 <= float(means[0]) <= 1.0
        assert 0.0 <= float(means[1]) <= 1.0


def test_sample_thompson_cpu() -> None:
    state = BanditState.create(5)
    arm = sample_thompson_cpu(state)
    assert 0 <= arm < 5


def test_sample_thompson_batch_cpu() -> None:
    state = BanditState.create(4)
    selections = sample_thompson_batch_cpu(state, num_samples=50)
    assert len(selections) == 50
    assert all(0 <= int(x) < 4 for x in selections)


class TestThompsonSampler:
    def test_num_arms(self) -> None:
        sampler = ThompsonSampler(6, use_gpu=False, seed=123)
        assert sampler.num_arms == 6

    def test_backend(self) -> None:
        sampler = ThompsonSampler(2, use_gpu=False)
        assert sampler.backend == "CPU"

    def test_sample(self) -> None:
        sampler = ThompsonSampler(4, use_gpu=False, seed=7)
        arm = sampler.sample()
        assert 0 <= arm < 4

    def test_sample_batch(self) -> None:
        sampler = ThompsonSampler(3, use_gpu=False, seed=99)
        selections = sampler.sample_batch(40)
        assert len(selections) == 40
        assert all(0 <= int(x) < 3 for x in selections)

    def test_update(self) -> None:
        sampler = ThompsonSampler(3, use_gpu=False)
        old_alpha = float(sampler.state.alphas[2])
        sampler.update(2, 0.25)
        assert float(sampler.state.alphas[2]) == old_alpha + 0.25

    def test_get_means(self) -> None:
        sampler = ThompsonSampler(3, use_gpu=False)
        means = sampler.get_means()
        assert len(means) == 3
        assert all(0.0 <= float(x) <= 1.0 for x in means)

    def test_get_upper_confidence_bounds(self) -> None:
        sampler = ThompsonSampler(2, use_gpu=False)
        try:
            ucbs = sampler.get_upper_confidence_bounds(0.9)
            assert len(ucbs) == 2
            assert all(0.0 <= float(x) <= 1.0 for x in ucbs)
        except BackendError as err:
            assert "SciPy required" in str(err)


def test_create_sampler() -> None:
    sampler = create_sampler(5, use_gpu=False, seed=11)
    assert isinstance(sampler, ThompsonSampler)
    assert sampler.num_arms == 5
