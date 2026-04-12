import pytest
from typing import cast
from pysymex.analysis.contracts.decorators import (
    get_function_contract, requires, ensures, invariant, loop_invariant, function_contracts
)
from pysymex.analysis.contracts.types import ContractKind

def test_get_function_contract() -> None:
    """Test get_function_contract behavior."""
    @requires("x > 0")
    def foo(x: int) -> int: return x
    
    contract = get_function_contract(foo)
    assert contract is not None
    assert contract.function_name == "foo"
    
    def bar(x: int) -> int: return x
    assert get_function_contract(bar) is None

def test_requires() -> None:
    """Test requires behavior."""
    @requires("x > 0", "must be pos")
    def dummy(x: int) -> int: return x
    
    contract = get_function_contract(dummy)
    assert contract is not None
    assert len(contract.preconditions) == 1
    assert contract.preconditions[0].condition == "x > 0"
    assert contract.preconditions[0].message == "must be pos"

def test_ensures() -> None:
    """Test ensures behavior."""
    @ensures("result() > 0", "must be pos")
    def dummy() -> int: return 1
    
    contract = get_function_contract(dummy)
    assert contract is not None
    assert len(contract.postconditions) == 1
    assert contract.postconditions[0].condition == "result() > 0"
    assert contract.postconditions[0].message == "must be pos"

def test_invariant() -> None:
    """Test invariant behavior."""
    @invariant("self.x > 0")
    class Dummy:
        def __init__(self, x: int):
            self.x = x
            
    assert hasattr(Dummy, "__invariants__")
    invs = getattr(Dummy, "__invariants__")
    assert len(invs) == 1
    assert invs[0].kind == ContractKind.INVARIANT
    assert invs[0].condition == "self.x > 0"

def test_loop_invariant() -> None:
    """Test loop_invariant behavior."""
    inv = loop_invariant("i < n")
    assert inv.kind == ContractKind.LOOP_INVARIANT
    assert inv.condition == "i < n"
