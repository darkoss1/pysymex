import threading
import time
from typing import Callable, Dict, List, Optional, Set

import z3

class MUSGatekeeper:
    """
    Hybrid MUS Gatekeeper for PySyMex v2.
    Uses Z3 Activation-Literal Core Extraction to find Minimal Unsatisfiable Subsets (MUS).
    Replaces flawed message-passing with precise structural contradiction extraction.
    """
    __slots__ = ("timeout_ms",)

    def __init__(self, timeout_ms: int = 5000) -> None:
        self.timeout_ms = timeout_ms

    def extract_mus_sync(self, constraints: List[z3.BoolRef]) -> Optional[List[int]]:
        """
        Synchronously extracts the MUS from a list of Z3 constraints.
        Wraps each constraint in a pure boolean activation literal.
        Returns a list of indices representing the conflicting constraints, or None if SAT.
        Uses an isolated Context for thread-safety during background evaluation.
        """
        if not constraints:
            return None

        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)
        solver.set("timeout", self.timeout_ms)
        solver.set("core.minimize", True)

        activation_literals: List[z3.BoolRef] = []
        literal_to_idx: Dict[str, int] = {}
        
        prefix = f"alpha_{id(self)}_{time.perf_counter_ns()}"

        import threading
        if not hasattr(self, "_translate_lock"):
            self._translate_lock = threading.Lock()

        for i, constraint in enumerate(constraints):
            alpha = z3.Bool(f"{prefix}_{i}", ctx=ctx)
            with self._translate_lock:
                local_constraint = constraint.translate(ctx)
            solver.add(z3.Implies(alpha, local_constraint))
            activation_literals.append(alpha)
            literal_to_idx[str(alpha)] = i

        result = solver.check(*activation_literals)

        if result == z3.unsat:
            core = solver.unsat_core()
            return [literal_to_idx[str(lit)] for lit in core]
        
        return None

class AsyncMUSWorker:
    """
    Asynchronous Core Learning worker for the Hybrid MUS Gatekeeper.
    Performs MUS extraction in a background thread. If it returns UNSAT later, 
    the path will be killed retroactively by the main VM loop via the callback.
    """
    __slots__ = ("gatekeeper", "_lock", "_active_threads")

    def __init__(self, gatekeeper: MUSGatekeeper) -> None:
        self.gatekeeper = gatekeeper
        self._lock = threading.Lock()
        self._active_threads: Set[threading.Thread] = set()

    def dispatch(self, constraints: List[z3.BoolRef], callback: Callable[[Optional[List[int]]], None]) -> threading.Thread | None:
        """
        Dispatches MUS extraction to a background thread.
        Callback is invoked with the result (List of indices if UNSAT, else None).
        Limits active threads to prevent GIL thrashing during path explosion.
        """
        with self._lock:
            if len(self._active_threads) >= 4:
                return None

        def worker() -> None:
            try:
                result = self.gatekeeper.extract_mus_sync(constraints)
                callback(result)
            except Exception:
                callback(None)
            finally:
                with self._lock:
                    self._active_threads.discard(threading.current_thread())

        thread = threading.Thread(target=worker, daemon=True)
        with self._lock:
            self._active_threads.add(thread)
            
        thread.start()
        return thread

    def wait_all(self, timeout: Optional[float] = None) -> None:
        """Waits for all active extraction threads to complete. Used for synchronization and testing."""
        with self._lock:
            threads = list(self._active_threads)
            
        for t in threads:
            t.join(timeout=timeout)
