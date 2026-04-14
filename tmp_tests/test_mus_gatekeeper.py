import threading
import time
from typing import List, Optional

import pytest
import z3

from pysymex.core.solver.mus_gatekeeper import AsyncMUSWorker, MUSGatekeeper

def test_mus_gatekeeper_sat():
    gatekeeper = MUSGatekeeper()
    x = z3.Int('x')
    y = z3.Int('y')
    
    constraints = [
        x > 0,
        y > 0,
        x + y == 10
    ]
    
    result = gatekeeper.extract_mus_sync(constraints)
    assert result is None  # Because it's SAT

def test_mus_gatekeeper_unsat_core():
    gatekeeper = MUSGatekeeper()
    x = z3.Int('x')
    
    constraints = [
        x > 10,
        x < 5,
        x == 12  # This is the actual value, but x > 10 and x < 5 is the core
    ]
    
    result = gatekeeper.extract_mus_sync(constraints)
    assert result is not None
    # The contradiction is between constraints at index 0 (x > 10) and 1 (x < 5)
    assert set(result) == {0, 1}

def test_async_mus_worker_sat():
    gatekeeper = MUSGatekeeper()
    worker = AsyncMUSWorker(gatekeeper)
    
    x = z3.Int('x')
    constraints = [x > 0, x < 10]
    
    result_container: list[Optional[List[int]]] = []
    
    def callback(res: Optional[List[int]]) -> None:
        result_container.append(res)
        
    thread = worker.dispatch(constraints, callback)
    worker.wait_all()
    
    assert len(result_container) == 1
    assert result_container[0] is None

def test_async_mus_worker_unsat():
    gatekeeper = MUSGatekeeper()
    worker = AsyncMUSWorker(gatekeeper)
    
    x = z3.Int('x')
    y = z3.Int('y')
    # Unsat core is constraints[0] and constraints[2]
    constraints = [x > 10, y > 5, x < 0]
    
    result_container: list[Optional[List[int]]] = []
    
    def callback(res: Optional[List[int]]) -> None:
        result_container.append(res)
        
    worker.dispatch(constraints, callback)
    worker.wait_all()
    
    assert len(result_container) == 1
    assert result_container[0] is not None
    assert set(result_container[0]) == {0, 2}
