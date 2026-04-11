from unittest.mock import patch

import z3

from pysymex.accel.bytecode import compile_constraint
from pysymex.accel.memory import (
    GPUMemoryError,
    MemoryBudget,
    calculate_memory_budget,
    estimate_max_treewidth,
    evaluate_batched,
    get_device_memory_info,
)


class TestGPUMemoryError:
    def test_initialization(self) -> None:
        err = GPUMemoryError("oom")
        assert str(err) == "oom"


class TestMemoryBudget:
    def test_output_mb(self) -> None:
        budget = MemoryBudget(1024 * 1024, 0, 0, 1024 * 1024, 1)
        assert budget.output_mb == 1.0

    def test_total_mb(self) -> None:
        budget = MemoryBudget(0, 0, 0, 2 * 1024 * 1024, 1)
        assert budget.total_mb == 2.0

    def test_fits_in_memory(self) -> None:
        budget = MemoryBudget(0, 0, 0, 2 * 1024 * 1024, 1)
        assert budget.fits_in_memory(3) is True
        assert budget.fits_in_memory(1) is False


def test_calculate_memory_budget() -> None:
    budget = calculate_memory_budget(num_variables=10, num_instructions=20)
    assert budget.total_threads == 1 << 10
    assert budget.output_bytes == ((1 << 10) + 7) // 8
    assert budget.instruction_bytes == 20 * 16
    assert budget.total_device_bytes >= budget.output_bytes + budget.instruction_bytes


def test_estimate_max_treewidth() -> None:
    assert estimate_max_treewidth(256) <= 30
    assert estimate_max_treewidth(1_000_000) == 30


def test_get_device_memory_info() -> None:
    info = get_device_memory_info()
    assert "available" in info


def test_evaluate_batched() -> None:
    x = z3.Bool("x")
    constraint = compile_constraint(x, ["x"])

    class _Result:
        def __init__(self) -> None:
            self.bitmap = b"\x01"

    class _Dispatcher:
        def evaluate_bag(self, c: object):
            assert c is constraint
            return _Result()

    with patch("pysymex.accel.dispatcher.get_dispatcher", return_value=_Dispatcher()):
        bitmap = evaluate_batched(constraint)
    assert bitmap == b"\x01"
