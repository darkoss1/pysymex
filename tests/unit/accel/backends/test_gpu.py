import pytest
import z3
from unittest.mock import patch

from pysymex.accel.backends import BackendError, BackendType
from pysymex.accel.backends import gpu
from pysymex.accel.bytecode import compile_constraint

cupy_available = gpu.is_available()


def test_is_available_returns_bool() -> None:
    assert isinstance(gpu.is_available(), bool)


def test_get_info_degrades_gracefully_when_cupy_unavailable() -> None:
    with patch.object(gpu, "cp", None):
        info = gpu.get_info()
    assert info.backend_type is BackendType.GPU
    assert info.available is False
    assert info.max_treewidth == 0
    assert info.error_message is not None


def test_get_memory_info_degrades_gracefully_when_cupy_unavailable() -> None:
    with patch.object(gpu, "cp", None):
        mem = gpu.get_memory_info()
    assert mem == {"available": False}


@pytest.mark.skipif(not cupy_available, reason="CUDA required")
@pytest.mark.timeout(30)
def test_get_info_reports_live_gpu_contract() -> None:
    info = gpu.get_info()
    assert info.backend_type is BackendType.GPU
    assert info.available is True
    assert info.max_treewidth > 0
    assert info.supports_async is True
    assert info.compute_units >= 1


@pytest.mark.skipif(not cupy_available, reason="CUDA required")
@pytest.mark.timeout(30)
def test_evaluate_bag_returns_non_empty_bitmap() -> None:
    x, y = z3.Bools("x y")
    constraint = compile_constraint(z3.And(x, y), ["x", "y"])
    bitmap = gpu.evaluate_bag(constraint)
    assert bitmap.shape == (1,)
    assert int(bitmap[0]) == 0b00001000


@pytest.mark.skipif(not cupy_available, reason="CUDA required")
@pytest.mark.timeout(30)
def test_count_sat_matches_small_known_constraint() -> None:
    x, y = z3.Bools("x y")
    constraint = compile_constraint(z3.Or(x, y), ["x", "y"])
    assert gpu.count_sat(constraint) == 3


@pytest.mark.skipif(not cupy_available, reason="CUDA required")
@pytest.mark.timeout(30)
def test_evaluate_bag_async_returns_output_and_stream() -> None:
    x, y = z3.Bools("x y")
    constraint = compile_constraint(z3.And(x, y), ["x", "y"])
    d_output, stream = gpu.evaluate_bag_async(constraint)
    assert len(d_output) == 1
    assert stream is not None


@pytest.mark.skipif(not cupy_available, reason="CUDA required")
@pytest.mark.timeout(30)
def test_evaluate_bag_projected_matches_projection_size() -> None:
    x, y = z3.Bools("x y")
    constraint = compile_constraint(z3.And(x, y), ["x", "y"])
    projected = gpu.evaluate_bag_projected(constraint, ["x"], ["x", "y"])
    assert projected.shape == (1,)
    assert int(projected[0] & 0b00000011) == 0b00000010


@pytest.mark.skipif(not cupy_available, reason="CUDA required")
@pytest.mark.timeout(30)
def test_warmup_completes_without_raising() -> None:
    assert gpu.warmup() is None


@pytest.mark.skipif(not cupy_available, reason="CUDA required")
@pytest.mark.timeout(30)
def test_clear_caches_and_bitmap_cache_are_idempotent() -> None:
    x, y = z3.Bools("x y")
    constraint = compile_constraint(z3.And(x, y), ["x", "y"])
    _ = gpu.evaluate_bag(constraint)
    gpu.clear_bitmap_cache()
    gpu.clear_bitmap_cache()
    gpu.clear_caches()
    gpu.clear_caches()


def test_gpu_entrypoints_raise_backend_error_when_cupy_missing() -> None:
    x = z3.Bool("x")
    constraint = compile_constraint(x, ["x"])
    with patch.object(gpu, "cp", None):
        with pytest.raises(BackendError, match="not available"):
            gpu.evaluate_bag(constraint)
        with pytest.raises(BackendError, match="not available"):
            gpu.count_sat(constraint)
