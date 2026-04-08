from __future__ import annotations

from typing import cast

import numpy as np
import numpy.typing as npt
import z3

from pysymex.h_acceleration.backends import BackendInfo, BackendType
from pysymex.h_acceleration.bytecode import CompiledConstraint, compile_constraint
from pysymex.h_acceleration.dispatcher import Backend, GPUDispatcher


class _FakeBackend:
    def __init__(self, name: str) -> None:
        self.name = name

    def evaluate_bag(self, constraint: CompiledConstraint) -> npt.NDArray[np.uint8]:
        return cast(npt.NDArray[np.uint8], constraint.instructions.view(np.uint8)[:1])

    def get_info(self) -> BackendInfo:
        return BackendInfo(
            backend_type=BackendType.REFERENCE,
            name=self.name,
            available=True,
            max_treewidth=30,
        )

    def warmup(self) -> None:
        return None


class _TestableDispatcher(GPUDispatcher):
    def set_test_routing_state(
        self,
        *,
        backends: dict[BackendType, Backend],
        infos: dict[BackendType, BackendInfo],
    ) -> None:
        self._forced_backend = None
        self._selected_backend = BackendType.CPU
        self._backends = backends
        self._backend_info = infos

    def set_ewma(self, backend_type: BackendType, value_ms: float) -> None:
        self._backend_latency_ewma_ms[backend_type] = value_ms

    def select_backend_for_test(self, constraint: CompiledConstraint) -> BackendType:
        return self._select_backend_for_constraint(constraint)


def _constraint(num_variables: int, instruction_count: int = 4) -> CompiledConstraint:
    names = [f"x{i}" for i in range(num_variables)]
    exprs = [z3.Bool(name) for name in names]
    conjunction = z3.And(*exprs) if exprs else z3.BoolVal(True)
    _ = instruction_count
    return compile_constraint(conjunction, names)


def test_dispatcher_gpu_guardrail_falls_back_to_cpu() -> None:
    disp = _TestableDispatcher(force_backend=None)
    disp.set_test_routing_state(
        backends={
            BackendType.GPU: _FakeBackend("gpu"),
            BackendType.CPU: _FakeBackend("cpu"),
        },
        infos={
            BackendType.GPU: BackendInfo(
                backend_type=BackendType.GPU,
                name="gpu",
                available=True,
                max_treewidth=40,
                device_memory_mb=1,
            ),
            BackendType.CPU: BackendInfo(
                backend_type=BackendType.CPU,
                name="cpu",
                available=True,
                max_treewidth=40,
            ),
        },
    )

    result = disp.evaluate_bag(_constraint(num_variables=25))
    assert result.backend_used == BackendType.CPU
    stats = disp.get_routing_stats()
    guardrails = stats.get("guardrail_fallbacks")
    assert isinstance(guardrails, int)
    assert guardrails >= 1


def test_dispatcher_uses_latency_ewma_for_routing() -> None:
    disp = _TestableDispatcher(force_backend=None)
    disp.set_test_routing_state(
        backends={
            BackendType.GPU: _FakeBackend("gpu"),
            BackendType.CPU: _FakeBackend("cpu"),
        },
        infos={
            BackendType.GPU: BackendInfo(
                backend_type=BackendType.GPU,
                name="gpu",
                available=True,
                max_treewidth=30,
            ),
            BackendType.CPU: BackendInfo(
                backend_type=BackendType.CPU,
                name="cpu",
                available=True,
                max_treewidth=30,
            ),
        },
    )
    disp.set_ewma(BackendType.GPU, 40.0)
    disp.set_ewma(BackendType.CPU, 3.0)

    selected = disp.select_backend_for_test(_constraint(num_variables=8))
    assert selected == BackendType.CPU
