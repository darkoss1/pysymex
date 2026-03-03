"""
Tests for pysymex Memory Model - Phase 14

Comprehensive tests for:
- SymbolicAddress allocation and arithmetic
- SymbolicHeap read/write operations
- Aliasing analysis (may-alias, must-alias)
- Memory regions (stack, heap, globals)
- SymbolicArray and SymbolicMap operations
- Memory snapshots and restoration
"""

import pytest

import z3


from pysymex.core.memory_model import (
    MemoryRegion,
    SymbolicAddress,
    HeapObject,
    StackFrame,
    SymbolicHeap,
    HeapSnapshot,
    MemoryState,
    MemorySnapshot,
    AliasingAnalyzer,
    SymbolicArray,
    SymbolicMap,
)


class TestSymbolicAddress:
    """Tests for SymbolicAddress class."""

    def test_create_concrete_address(self):
        """Test creating an address with concrete values."""

        addr = SymbolicAddress(MemoryRegion.HEAP, base=1000, offset=0)

        assert addr.region == MemoryRegion.HEAP

        assert z3.is_bv_value(addr.base)

        assert addr.base.as_long() == 1000

        assert addr.offset.as_long() == 0

    def test_create_with_offset(self):
        """Test creating an address with non-zero offset."""

        addr = SymbolicAddress(MemoryRegion.HEAP, base=1000, offset=8)

        assert addr.base.as_long() == 1000

        assert addr.offset.as_long() == 8

    def test_effective_address(self):
        """Test effective address computation."""

        addr = SymbolicAddress(MemoryRegion.HEAP, base=1000, offset=24)

        simplified = z3.simplify(addr.effective_address)

        assert simplified.as_long() == 1024

    def test_add_offset(self):
        """Test adding offset to create new address."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000, offset=0)

        addr2 = addr1.add_offset(16)

        assert addr1.offset.as_long() == 0

        assert z3.simplify(addr2.offset).as_long() == 16

        assert addr1.region == addr2.region

    def test_symbolic_base(self):
        """Test address with symbolic base."""

        sym_base = z3.BitVec("ptr", 64)

        addr = SymbolicAddress(MemoryRegion.HEAP, base=sym_base, offset=0)

        assert z3.eq(addr.base, sym_base)

    def test_symbolic_offset(self):
        """Test address with symbolic offset."""

        sym_offset = z3.BitVec("idx", 64)

        addr = SymbolicAddress(MemoryRegion.HEAP, base=1000, offset=sym_offset)

        assert z3.eq(addr.offset, sym_offset)

    def test_same_region_true(self):
        """Test same_region for addresses in same region."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=2000)

        assert addr1.same_region(addr2)

    def test_same_region_false(self):
        """Test same_region for addresses in different regions."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        addr2 = SymbolicAddress(MemoryRegion.STACK, base=2000)

        assert not addr1.same_region(addr2)

    def test_may_alias_concrete_same(self):
        """Test may_alias for same concrete addresses."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        solver = z3.Solver()

        assert addr1.may_alias(addr2, solver)

    def test_may_alias_concrete_different(self):
        """Test may_alias for different concrete addresses."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=2000)

        solver = z3.Solver()

        assert not addr1.may_alias(addr2, solver)

    def test_may_alias_different_regions(self):
        """Test may_alias returns False for different regions."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        addr2 = SymbolicAddress(MemoryRegion.STACK, base=1000)

        solver = z3.Solver()

        assert not addr1.may_alias(addr2, solver)

    def test_may_alias_symbolic(self):
        """Test may_alias with symbolic addresses."""

        x = z3.BitVec("x", 64)

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=x)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        solver = z3.Solver()

        assert addr1.may_alias(addr2, solver)

    def test_may_alias_symbolic_constrained(self):
        """Test may_alias with constrained symbolic addresses."""

        x = z3.BitVec("x", 64)

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=x)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        solver = z3.Solver()

        solver.add(z3.UGT(x, z3.BitVecVal(2000, 64)))

        assert not addr1.may_alias(addr2, solver)

    def test_must_alias_concrete_same(self):
        """Test must_alias for same concrete addresses."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        solver = z3.Solver()

        assert addr1.must_alias(addr2, solver)

    def test_must_alias_concrete_different(self):
        """Test must_alias for different concrete addresses."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=2000)

        solver = z3.Solver()

        assert not addr1.must_alias(addr2, solver)

    def test_must_alias_symbolic_unconstrained(self):
        """Test must_alias with unconstrained symbolic - should be False."""

        x = z3.BitVec("x", 64)

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=x)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        solver = z3.Solver()

        assert not addr1.must_alias(addr2, solver)

    def test_must_alias_symbolic_constrained(self):
        """Test must_alias with equality constrained symbolic."""

        x = z3.BitVec("x", 64)

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=x)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        solver = z3.Solver()

        solver.add(x == z3.BitVecVal(1000, 64))

        assert addr1.must_alias(addr2, solver)

    def test_type_tag(self):
        """Test type tag preservation."""

        addr = SymbolicAddress(MemoryRegion.HEAP, base=1000, type_tag="list")

        assert addr.type_tag == "list"

    def test_equality(self):
        """Test address equality."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000, offset=8)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=1000, offset=8)

        addr3 = SymbolicAddress(MemoryRegion.HEAP, base=1000, offset=16)

        assert addr1 == addr2

        assert addr1 != addr3

    def test_hash(self):
        """Test address hashing for use in sets/dicts."""

        addr1 = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=2000)

        addr_set = {addr1, addr2}

        assert len(addr_set) == 2


class TestHeapObject:
    """Tests for HeapObject class."""

    def test_create_heap_object(self):
        """Test creating a heap object."""

        addr = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        obj = HeapObject(address=addr, type_name="list")

        assert obj.type_name == "list"

        assert obj.is_mutable

        assert obj.size == 1

    def test_set_and_get_field(self):
        """Test setting and getting fields."""

        addr = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        obj = HeapObject(address=addr, type_name="Point")

        obj.set_field("x", 10)

        obj.set_field("y", 20)

        assert obj.get_field("x") == 10

        assert obj.get_field("y") == 20

        assert obj.get_field("z") is None

    def test_has_field(self):
        """Test checking field existence."""

        addr = SymbolicAddress(MemoryRegion.HEAP, base=1000)

        obj = HeapObject(address=addr, type_name="Point")

        obj.set_field("x", 10)

        assert obj.has_field("x")

        assert not obj.has_field("y")

    def test_immutable_object(self):
        """Test that immutable objects cannot be modified."""

        addr = SymbolicAddress(MemoryRegion.CONST, base=1000)

        obj = HeapObject(address=addr, type_name="tuple", is_mutable=False)

        with pytest.raises(ValueError, match="Cannot modify immutable"):
            obj.set_field("item", 42)


class TestStackFrame:
    """Tests for StackFrame class."""

    def test_create_frame(self):
        """Test creating a stack frame."""

        frame = StackFrame(function_name="test_func")

        assert frame.function_name == "test_func"

        assert frame.parent_frame is None

    def test_local_variables(self):
        """Test local variable operations."""

        frame = StackFrame(function_name="test_func")

        frame.set_local("x", 10)

        frame.set_local("y", 20)

        assert frame.get_local("x") == 10

        assert frame.get_local("y") == 20

        assert frame.get_local("z") is None

    def test_has_local(self):
        """Test checking local existence."""

        frame = StackFrame(function_name="test_func")

        frame.set_local("x", 10)

        assert frame.has_local("x")

        assert not frame.has_local("y")

    def test_delete_local(self):
        """Test deleting local variables."""

        frame = StackFrame(function_name="test_func")

        frame.set_local("x", 10)

        assert frame.has_local("x")

        frame.delete_local("x")

        assert not frame.has_local("x")

    def test_parent_frame_chain(self):
        """Test parent frame linking."""

        parent = StackFrame(function_name="outer")

        child = StackFrame(function_name="inner", parent_frame=parent)

        assert child.parent_frame is parent

        assert parent.parent_frame is None


class TestSymbolicHeap:
    """Tests for SymbolicHeap class."""

    def test_allocate(self):
        """Test basic allocation."""

        heap = SymbolicHeap()

        addr = heap.allocate("list")

        assert addr.region == MemoryRegion.HEAP

        assert addr.type_tag == "list"

    def test_allocate_multiple(self):
        """Test multiple allocations get different addresses."""

        heap = SymbolicHeap()

        addr1 = heap.allocate("list")

        addr2 = heap.allocate("dict")

        base1 = z3.simplify(addr1.effective_address).as_long()

        base2 = z3.simplify(addr2.effective_address).as_long()

        assert base1 != base2

    def test_write_and_read(self):
        """Test writing and reading values."""

        heap = SymbolicHeap()

        addr = heap.allocate("int")

        heap.write(addr, 42)

        value = heap.read(addr)

        assert value == 42

    def test_write_and_read_field(self):
        """Test writing and reading specific fields."""

        heap = SymbolicHeap()

        addr = heap.allocate("Point")

        heap.write(addr, 10, "x")

        heap.write(addr, 20, "y")

        assert heap.read(addr, "x") == 10

        assert heap.read(addr, "y") == 20

    def test_read_uninitialized(self):
        """Test reading uninitialized memory returns symbolic."""

        heap = SymbolicHeap()

        addr = heap.allocate("int")

        value = heap.read(addr, "unset_field")

        assert value is None

    def test_free(self):
        """Test freeing memory."""

        heap = SymbolicHeap()

        addr = heap.allocate("temp")

        heap.free(addr)

        with pytest.raises(ValueError, match="Use after free"):
            heap.read(addr)

    def test_double_free(self):
        """Test double free detection."""

        heap = SymbolicHeap()

        addr = heap.allocate("temp")

        heap.free(addr)

        with pytest.raises(ValueError, match="Double free"):
            heap.free(addr)

    def test_write_after_free(self):
        """Test write after free detection."""

        heap = SymbolicHeap()

        addr = heap.allocate("temp")

        heap.free(addr)

        with pytest.raises(ValueError, match="freed memory"):
            heap.write(addr, 42)

    def test_get_object(self):
        """Test getting the heap object."""

        heap = SymbolicHeap()

        addr = heap.allocate("list")

        heap.write(addr, [1, 2, 3], "items")

        obj = heap.get_object(addr)

        assert obj is not None

        assert obj.type_name == "list"

        assert obj.get_field("items") == [1, 2, 3]

    def test_reference_tracking(self):
        """Test reference tracking."""

        heap = SymbolicHeap()

        addr = heap.allocate("list")

        heap.add_reference(addr, "my_list")

        heap.add_reference(addr, "alias")

        refs = heap.get_references(addr)

        assert "my_list" in refs

        assert "alias" in refs

    def test_remove_reference(self):
        """Test removing references."""

        heap = SymbolicHeap()

        addr = heap.allocate("list")

        heap.add_reference(addr, "my_list")

        heap.remove_reference(addr, "my_list")

        refs = heap.get_references(addr)

        assert "my_list" not in refs

    def test_snapshot_and_restore(self):
        """Test heap snapshot and restoration."""

        heap = SymbolicHeap()

        addr = heap.allocate("counter")

        heap.write(addr, 0, "value")

        snapshot = heap.snapshot()

        heap.write(addr, 100, "value")

        assert heap.read(addr, "value") == 100

        heap.restore(snapshot)

        assert heap.read(addr, "value") == 0

    def test_allocate_in_different_regions(self):
        """Test allocation in different memory regions."""

        heap = SymbolicHeap()

        heap_addr = heap.allocate("list", region=MemoryRegion.HEAP)

        const_addr = heap.allocate("tuple", region=MemoryRegion.CONST)

        assert heap_addr.region == MemoryRegion.HEAP

        assert const_addr.region == MemoryRegion.CONST


class TestMemoryState:
    """Tests for MemoryState class."""

    def test_push_and_pop_frame(self):
        """Test pushing and popping stack frames."""

        state = MemoryState()

        frame1 = state.push_frame("outer")

        assert state.current_frame == frame1

        frame2 = state.push_frame("inner")

        assert state.current_frame == frame2

        popped = state.pop_frame()

        assert popped == frame2

        assert state.current_frame == frame1

    def test_local_variables(self):
        """Test local variable access through MemoryState."""

        state = MemoryState()

        state.push_frame("test")

        state.set_local("x", 10)

        assert state.get_local("x") == 10

    def test_global_variables(self):
        """Test global variable access."""

        state = MemoryState()

        state.set_global("CONSTANT", 42)

        assert state.get_global("CONSTANT") == 42

    def test_allocate_object(self):
        """Test object allocation through MemoryState."""

        state = MemoryState()

        addr = state.allocate_object("Point", {"x": 0, "y": 0})

        assert state.read_field(addr, "x") == 0

        assert state.read_field(addr, "y") == 0

    def test_write_field(self):
        """Test writing object fields."""

        state = MemoryState()

        addr = state.allocate_object("Counter")

        state.write_field(addr, "count", 0)

        state.write_field(addr, "count", 1)

        assert state.read_field(addr, "count") == 1

    def test_frame_isolation(self):
        """Test that frames isolate local variables."""

        state = MemoryState()

        state.push_frame("outer")

        state.set_local("x", 10)

        state.push_frame("inner")

        state.set_local("x", 20)

        assert state.get_local("x") == 20

        state.pop_frame()

        assert state.get_local("x") == 10

    def test_memory_snapshot(self):
        """Test full memory state snapshot."""

        state = MemoryState()

        state.push_frame("test")

        state.set_local("x", 10)

        state.set_global("G", 100)

        snapshot = state.snapshot()

        state.set_local("x", 20)

        state.set_global("G", 200)

        state.restore(snapshot)

        assert state.get_local("x") == 10

        assert state.get_global("G") == 100


class TestAliasingAnalyzer:
    """Tests for AliasingAnalyzer class."""

    def test_add_address(self):
        """Test adding addresses to analyzer."""

        heap = SymbolicHeap()

        analyzer = AliasingAnalyzer(heap)

        addr = heap.allocate("list")

        analyzer.add_address(addr)

        may_aliases = analyzer.get_may_aliases(addr)

        assert addr in may_aliases

    def test_get_may_aliases_same(self):
        """Test may_aliases finds same address."""

        heap = SymbolicHeap()

        analyzer = AliasingAnalyzer(heap)

        addr1 = heap.allocate("list")

        addr2 = SymbolicAddress(MemoryRegion.HEAP, base=addr1.base)

        analyzer.add_address(addr1)

        analyzer.add_address(addr2)

        aliases = analyzer.get_may_aliases(addr1)

        assert addr2 in aliases

    def test_are_disjoint_different_addresses(self):
        """Test are_disjoint for different concrete addresses."""

        heap = SymbolicHeap()

        analyzer = AliasingAnalyzer(heap)

        addr1 = heap.allocate("list")

        addr2 = heap.allocate("dict")

        assert analyzer.are_disjoint(addr1, addr2)

    def test_are_disjoint_same_address(self):
        """Test are_disjoint for same address."""

        heap = SymbolicHeap()

        analyzer = AliasingAnalyzer(heap)

        addr = heap.allocate("list")

        assert not analyzer.are_disjoint(addr, addr)


class TestSymbolicArray:
    """Tests for SymbolicArray class."""

    def test_create_array(self):
        """Test creating a symbolic array."""

        arr = SymbolicArray("my_list")

        constraints = arr.get_constraints()

        assert len(constraints) >= 1

    def test_symbolic_length(self):
        """Test accessing symbolic length."""

        arr = SymbolicArray("my_list")

        assert isinstance(arr.length, z3.ArithRef)

    def test_get_element_concrete(self):
        """Test getting element at concrete index."""

        arr = SymbolicArray("my_list")

        elem = arr.get(0)

        assert isinstance(elem, z3.ExprRef)

    def test_get_element_symbolic(self):
        """Test getting element at symbolic index."""

        arr = SymbolicArray("my_list")

        idx = z3.Int("i")

        elem = arr.get(idx)

        assert isinstance(elem, z3.ExprRef)

    def test_set_element(self):
        """Test setting element (functional update)."""

        arr1 = SymbolicArray("my_list")

        arr2 = arr1.set(0, z3.IntVal(42))

        solver = z3.Solver()

        solver.add(arr2.get(0) == 42)

        assert solver.check() == z3.sat

    def test_append(self):
        """Test appending element."""

        arr1 = SymbolicArray("my_list")

        arr2 = arr1.append(z3.IntVal(99))

        solver = z3.Solver()

        solver.add(arr1.length == 5)

        solver.add(arr2.length == arr1.length + 1)

        assert solver.check() == z3.sat

    def test_in_bounds(self):
        """Test bounds checking."""

        arr = SymbolicArray("my_list")

        solver = z3.Solver()

        solver.add(arr.length == 10)

        solver.push()

        solver.add(arr.in_bounds(5))

        assert solver.check() == z3.sat

        solver.pop()

        solver.push()

        solver.add(arr.in_bounds(15))

        assert solver.check() == z3.unsat

        solver.pop()

    def test_in_bounds_negative(self):
        """Test that negative indices are out of bounds."""

        arr = SymbolicArray("my_list")

        solver = z3.Solver()

        solver.add(arr.length == 10)

        solver.add(arr.in_bounds(-1))

        assert solver.check() == z3.unsat


class TestSymbolicMap:
    """Tests for SymbolicMap class."""

    def test_create_map(self):
        """Test creating a symbolic map."""

        m = SymbolicMap("my_dict")

        assert m.name == "my_dict"

    def test_set_and_get(self):
        """Test setting and getting values."""

        m1 = SymbolicMap("my_dict")

        m2 = m1.set(z3.IntVal(1), z3.IntVal(100))

        solver = z3.Solver()

        solver.add(m2.get(z3.IntVal(1)) == 100)

        assert solver.check() == z3.sat

    def test_contains_after_set(self):
        """Test that key exists after set."""

        m1 = SymbolicMap("my_dict")

        m2 = m1.set(z3.IntVal(1), z3.IntVal(100))

        solver = z3.Solver()

        solver.add(m2.contains(z3.IntVal(1)))

        assert solver.check() == z3.sat

    def test_not_contains_initially(self):
        """Test that keys don't exist initially."""

        m = SymbolicMap("my_dict")

        solver = z3.Solver()

        solver.add(m.contains(z3.IntVal(42)))

        assert solver.check() == z3.unsat

    def test_delete(self):
        """Test deleting a key."""

        m1 = SymbolicMap("my_dict")

        m2 = m1.set(z3.IntVal(1), z3.IntVal(100))

        m3 = m2.delete(z3.IntVal(1))

        solver = z3.Solver()

        solver.add(m3.contains(z3.IntVal(1)))

        assert solver.check() == z3.unsat

    def test_get_with_default(self):
        """Test get with default value."""

        m = SymbolicMap("my_dict")

        default = z3.IntVal(-1)

        value = m.get(z3.IntVal(999), default)

        solver = z3.Solver()

        solver.add(value == -1)

        assert solver.check() == z3.sat

    def test_symbolic_keys(self):
        """Test map with symbolic keys."""

        m1 = SymbolicMap("my_dict")

        key = z3.Int("k")

        m2 = m1.set(key, z3.IntVal(42))

        solver = z3.Solver()

        solver.add(m2.contains(key))

        assert solver.check() == z3.sat


class TestMemoryModelIntegration:
    """Integration tests for the memory model."""

    def test_list_mutation_tracking(self):
        """Test tracking mutations to a list object."""

        state = MemoryState()

        state.push_frame("test")

        list_addr = state.allocate_object("list", {"length": 0})

        state.set_local("my_list", list_addr)

        state.write_field(list_addr, "length", 1)

        state.write_field(list_addr, "item_0", 42)

        assert state.read_field(list_addr, "length") == 1

        assert state.read_field(list_addr, "item_0") == 42

    def test_aliasing_detection(self):
        """Test detecting when two variables alias."""

        state = MemoryState()

        state.push_frame("test")

        obj_addr = state.allocate_object("Counter", {"value": 0})

        state.set_local("a", obj_addr)

        state.set_local("b", obj_addr)

        state.write_field(obj_addr, "value", 10)

        assert state.read_field(state.get_local("a"), "value") == 10

    def test_function_call_memory_isolation(self):
        """Test that function calls properly isolate memory."""

        state = MemoryState()

        state.push_frame("outer")

        state.set_local("x", 100)

        state.push_frame("inner")

        state.set_local("x", 200)

        assert state.get_local("x") == 200

        state.pop_frame()

        assert state.get_local("x") == 100

    def test_heap_object_survives_frame_pop(self):
        """Test that heap objects survive stack frame pops."""

        state = MemoryState()

        state.push_frame("creator")

        obj_addr = state.allocate_object("Persistent", {"data": "important"})

        state.set_global("saved_addr", obj_addr)

        state.pop_frame()

        saved = state.get_global("saved_addr")

        assert state.read_field(saved, "data") == "important"

    def test_symbolic_array_with_constraints(self):
        """Test using symbolic arrays with constraints."""

        arr = SymbolicArray("data")

        solver = z3.Solver()

        solver.add(arr.length == 3)

        for i in range(3):
            solver.add(arr.get(i) > 0)

        total = arr.get(0) + arr.get(1) + arr.get(2)

        solver.add(total == 100)

        assert solver.check() == z3.sat

        model = solver.model()

        for i in range(3):
            val = model.eval(arr.get(i))

            assert val.as_long() > 0

    def test_symbolic_map_lookup_chain(self):
        """Test chained map operations."""

        m = SymbolicMap("config")

        m = m.set(z3.IntVal(1), z3.IntVal(10))

        m = m.set(z3.IntVal(2), z3.IntVal(20))

        m = m.set(z3.IntVal(3), z3.IntVal(30))

        solver = z3.Solver()

        solver.add(m.contains(z3.IntVal(1)))

        solver.add(m.contains(z3.IntVal(2)))

        solver.add(m.contains(z3.IntVal(3)))

        solver.add(m.get(z3.IntVal(1)) == 10)

        solver.add(m.get(z3.IntVal(2)) == 20)

        solver.add(m.get(z3.IntVal(3)) == 30)

        assert solver.check() == z3.sat


class TestEdgeCases:
    """Edge case and corner case tests."""

    def test_empty_stack(self):
        """Test operations with empty stack."""

        state = MemoryState()

        assert state.current_frame is None

        assert state.get_local("x") is None

        result = state.pop_frame()

        assert result is None

    def test_large_allocation(self):
        """Test allocating large objects."""

        heap = SymbolicHeap()

        addr = heap.allocate("large_array", size=1000)

        assert addr is not None

    def test_many_allocations(self):
        """Test many sequential allocations."""

        heap = SymbolicHeap()

        addresses = []

        for i in range(100):
            addr = heap.allocate(f"obj_{i}")

            addresses.append(addr)

        concrete_addrs = [z3.simplify(a.effective_address).as_long() for a in addresses]

        assert len(set(concrete_addrs)) == 100

    def test_deeply_nested_frames(self):
        """Test deeply nested stack frames."""

        state = MemoryState()

        for i in range(100):
            state.push_frame(f"func_{i}")

            state.set_local("depth", i)

        assert state.get_local("depth") == 99

        for i in range(100):
            state.pop_frame()

        assert state.current_frame is None
