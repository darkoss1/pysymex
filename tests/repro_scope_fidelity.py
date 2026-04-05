import pytest
from pysymex.api import scan_file
from pysymex.analysis.invariants import invariant

@invariant("self.balance >= 0")
class BankAccount:
    def __init__(self, b):
        self.balance = b
    
    def withdraw(self, amount):
        # In isolation, balance could be negative. 
        # With invariant, engine should assume balance >= 0.
        self.balance -= amount
        # This assertion should ALWAYS hold if balance was >= 0 initially.
        # If the engine doesn't know about the invariant, it might think 
        # balance could be -1, and then -1 - amount >= -amount would be -1 >= 0 which is false.
        assert self.balance >= -amount

def test_scope_fidelity():
    import os
    with open("repro_scope.py", "w") as f:
        f.write("""
from pysymex.analysis.invariants import invariant

@invariant("self.balance >= 0")
class BankAccount:
    def __init__(self, b):
        self.balance = b
    
    def withdraw(self, amount):
        self.balance -= amount
        assert self.balance >= -amount
""")
    
    result = scan_file("repro_scope.py")
    
    # Clean up
    if os.path.exists("repro_scope.py"):
        os.remove("repro_scope.py")
    
    # If the engine doesn't know about the invariant, it will find an assertion error
    # for cases where self.balance < 0 initially.
    assertion_errors = [i for i in result.issues if i['kind'] == 'ASSERTION_ERROR']
    
    # WE WANT 0 assertion errors because the invariant should be assumed.
    assert len(assertion_errors) == 0, f"Found unexpected assertion errors: {assertion_errors}"

if __name__ == "__main__":
    test_scope_fidelity()
