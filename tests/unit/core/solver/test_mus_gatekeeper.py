"""Tests for pysymex.core.solver.mus_gatekeeper."""

import z3
from typing import List, Optional

from pysymex.core.solver.mus_gatekeeper import MUSGatekeeper, AsyncMUSWorker


class TestMUSGatekeeper:
    def test_extract_mus_sync_returns_none_on_empty(self) -> None:
        gatekeeper = MUSGatekeeper()
        constraints: List[z3.BoolRef] = []
        result = gatekeeper.extract_mus_sync(constraints)
        assert result is None

    def test_extract_mus_sync_returns_none_on_sat(self) -> None:
        gatekeeper = MUSGatekeeper()
        x = z3.Bool("x")
        constraints: List[z3.BoolRef] = [x, z3.BoolVal(True)]
        result = gatekeeper.extract_mus_sync(constraints)
        assert result is None

    def test_extract_mus_sync_returns_core_indices_on_unsat(self) -> None:
        gatekeeper = MUSGatekeeper()
        x = z3.Bool("x")
        constraints: List[z3.BoolRef] = [x, z3.Not(x)]
        result = gatekeeper.extract_mus_sync(constraints)
        assert result is not None
        assert set(result) == {0, 1}


class TestAsyncMUSWorker:
    def test_dispatch_ignores_over_max_depth(self) -> None:
        gatekeeper = MUSGatekeeper()
        worker = AsyncMUSWorker(gatekeeper)
        called = False

        def callback(res: Optional[List[int]]) -> None:
            nonlocal called
            called = True

        constraints: List[z3.BoolRef] = []
        worker.dispatch(constraints, callback, current_depth=10, max_depth=5)
        assert called is False

    def test_dispatch_invokes_callback_with_result(self) -> None:
        gatekeeper = MUSGatekeeper()
        worker = AsyncMUSWorker(gatekeeper)
        received_result: Optional[List[int]] = []

        def callback(res: Optional[List[int]]) -> None:
            nonlocal received_result
            received_result = res

        constraints: List[z3.BoolRef] = []
        worker.dispatch(constraints, callback, current_depth=0, max_depth=5)
        assert received_result is None

    def test_dispatch_handles_exception_gracefully(self) -> None:
        class FaultyGatekeeper(MUSGatekeeper):
            def extract_mus_sync(self, constraints: List[z3.BoolRef]) -> Optional[List[int]]:
                raise RuntimeError("simulated error")

        gatekeeper = FaultyGatekeeper()
        worker = AsyncMUSWorker(gatekeeper)
        received_result: Optional[List[int]] = [1]

        def callback(res: Optional[List[int]]) -> None:
            nonlocal received_result
            received_result = res

        constraints: List[z3.BoolRef] = []
        worker.dispatch(constraints, callback, current_depth=0, max_depth=5)
        assert received_result is None

    def test_wait_all_completes(self) -> None:
        gatekeeper = MUSGatekeeper()
        worker = AsyncMUSWorker(gatekeeper)
        result = worker.wait_all()
        assert result is None
