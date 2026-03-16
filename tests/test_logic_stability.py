import pytest
import z3
from pysymex.core.state import VMState
from pysymex.core.types import SymbolicValue, SymbolicString
from pysymex.core.types_containers import SymbolicDict, SymbolicList, SymbolicObject
from pysymex.execution.dispatcher import OpcodeDispatcher
import dis

class DummyInstr:
    def __init__(self, opname, argval):
        self.opname = opname
        self.argval = argval
        self.argrepr = str(argval)
        self.arg = argval

def test_dict_merge_logic():
    """Verify that DICT_MERGE correctly updates a symbolic dictionary."""
    state = VMState()
    
    # Create target dict
    d1, _ = SymbolicDict.symbolic("d1")
    d1._concrete_items = {}
    
    # Create source dict with one item
    key = SymbolicString.from_const("key1")
    val = SymbolicValue.from_const(42)
    d2 = SymbolicDict.empty("d2")
    d2._concrete_items = {"key1": val}
    d2 = d2.__setitem__(key, val)
    
    # Push to stack: container at bottom, source at top
    state = state.push(d1)
    state = state.push(d2)
    
    # Simulate DICT_MERGE(1)
    instr = DummyInstr("DICT_MERGE", 1)
    ctx = OpcodeDispatcher()
    
    from pysymex.execution.opcodes.collections import handle_collection_update
    result = handle_collection_update(instr, state, ctx)
    
    new_state = result.new_states[0]
    # Source popped, container at stack[-1] should be updated
    updated_d = new_state.stack[-1]
    
    assert isinstance(updated_d, SymbolicDict)
    # Check if key1 exists in updated_d
    lookup_val, presence = updated_d[key]
    
    solver = z3.Solver()
    solver.add(presence)
    assert solver.check() == z3.sat
    
    # Check value
    solver.add(lookup_val.z3_int == 42)
    assert solver.check() == z3.sat

def test_list_extend_logic():
    """Verify that LIST_EXTEND correctly extends a symbolic list."""
    state = VMState()
    
    # Create target list [1, 2]
    l1 = SymbolicList.from_const([1, 2])
    l1._concrete_items = [SymbolicValue.from_const(1), SymbolicValue.from_const(2)]
    
    # Create source list [3]
    l2 = SymbolicList.from_const([3])
    l2._concrete_items = [SymbolicValue.from_const(3)]
    
    state = state.push(l1)
    state = state.push(l2)
    
    # Simulate LIST_EXTEND(1)
    instr = DummyInstr("LIST_EXTEND", 1)
    ctx = OpcodeDispatcher()
    
    from pysymex.execution.opcodes.collections import handle_list_extend
    result = handle_list_extend(instr, state, ctx)
    
    new_state = result.new_states[0]
    updated_l = new_state.stack[-1]
    
    assert isinstance(updated_l, SymbolicList)
    
    solver = z3.Solver()
    # Length should be 3
    solver.add(updated_l.z3_len == 3)
    assert solver.check() == z3.sat
    
    # Check elements
    for i, expected in enumerate([1, 2, 3]):
        elem = updated_l[SymbolicValue.from_const(i)]
        solver.push()
        solver.add(elem.z3_int == expected)
        assert solver.check() == z3.sat
        solver.pop()

def test_match_mapping_logic():
    """Verify that MATCH_MAPPING correctly identifies a dictionary subject."""
    state = VMState()
    d = SymbolicDict.empty("d")
    state = state.push(d)
    
    instr = DummyInstr("MATCH_MAPPING", 0)
    ctx = OpcodeDispatcher()
    
    from pysymex.execution.opcodes.control import handle_match_mapping
    result = handle_match_mapping(instr, state, ctx)
    
    new_state = result.new_states[0]
    match_res = new_state.peek()
    
    solver = z3.Solver()
    solver.add(match_res.z3_bool)
    assert solver.check() == z3.sat
    
    # Negative case: subject is an int
    state2 = VMState().push(SymbolicValue.from_const(10))
    result2 = handle_match_mapping(instr, state2, ctx)
    match_res2 = result2.new_states[0].peek()
    
    solver2 = z3.Solver()
    solver2.add(match_res2.z3_bool)
    assert solver2.check() == z3.unsat

if __name__ == "__main__":
    pytest.main([__file__])
