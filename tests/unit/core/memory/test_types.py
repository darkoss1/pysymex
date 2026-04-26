import pysymex.core.memory.types
import z3


class TestMemoryRegion:
    """Test suite for pysymex.core.memory.types.MemoryRegion."""

    def test_initialization(self) -> None:
        """Scenario: enum members exist; expected stable region names."""
        assert [member.name for member in pysymex.core.memory.types.MemoryRegion] == [
            "STACK",
            "HEAP",
            "GLOBAL",
            "CONST",
        ]


class TestSymbolicAddress:
    """Test suite for pysymex.core.memory.types.SymbolicAddress."""

    def test_effective_address(self) -> None:
        """Scenario: base plus offset; expected bit-vector effective address sum."""
        addr = pysymex.core.memory.types.SymbolicAddress(
            region=pysymex.core.memory.types.MemoryRegion.HEAP,
            base=10,
            offset=3,
            type_tag="int",
        )
        assert z3.simplify(addr.effective_address).as_long() == 13

    def test_add_offset(self) -> None:
        """Scenario: add offset creates a new address; expected updated effective value."""
        base_addr = pysymex.core.memory.types.SymbolicAddress(
            region=pysymex.core.memory.types.MemoryRegion.HEAP,
            base=100,
            offset=5,
            type_tag="obj",
        )
        moved = base_addr.add_offset(7)
        assert z3.simplify(moved.effective_address).as_long() == 112

    def test_same_region(self) -> None:
        """Scenario: compare regions; expected true only for identical regions."""
        left = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.STACK, 1
        )
        right = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.STACK, 2
        )
        assert left.same_region(right) is True

    def test_may_alias(self) -> None:
        """Scenario: equal concrete addresses in same region; expected potential aliasing."""
        solver = z3.Solver()
        a = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.HEAP, 42
        )
        b = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.HEAP, 42
        )
        assert a.may_alias(b, solver) is True

    def test_must_alias(self) -> None:
        """Scenario: same concrete address and region; expected proven aliasing."""
        solver = z3.Solver()
        a = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.GLOBAL, 5
        )
        b = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.GLOBAL, 5
        )
        assert a.must_alias(b, solver) is True


class TestHeapObject:
    """Test suite for pysymex.core.memory.types.HeapObject."""

    def test_get_field(self) -> None:
        """Scenario: get existing field; expected exact stored value."""
        addr = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.HEAP, 1
        )
        obj = pysymex.core.memory.types.HeapObject(address=addr, type_name="Box", fields={"x": 9})
        assert obj.get_field("x") == 9

    def test_set_field(self) -> None:
        """Scenario: set mutable field; expected map contains new value."""
        addr = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.HEAP, 2
        )
        obj = pysymex.core.memory.types.HeapObject(address=addr, type_name="Box")
        obj.set_field("answer", 42)
        assert obj.fields["answer"] == 42

    def test_has_field(self) -> None:
        """Scenario: field presence query; expected true for existing key."""
        addr = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.HEAP, 3
        )
        obj = pysymex.core.memory.types.HeapObject(address=addr, type_name="Box", fields={"k": 1})
        assert obj.has_field("k") is True


class TestStackFrame:
    """Test suite for pysymex.core.memory.types.StackFrame."""

    def test_get_local(self) -> None:
        """Scenario: retrieve existing local; expected stored value."""
        frame = pysymex.core.memory.types.StackFrame("f", locals={"x": 3})
        assert frame.get_local("x") == 3

    def test_set_local(self) -> None:
        """Scenario: assign local variable; expected locals dict update."""
        frame = pysymex.core.memory.types.StackFrame("f")
        frame.set_local("y", 4)
        assert frame.locals["y"] == 4

    def test_has_local(self) -> None:
        """Scenario: check local existence; expected true for inserted name."""
        frame = pysymex.core.memory.types.StackFrame("f", locals={"z": 8})
        assert frame.has_local("z") is True

    def test_delete_local(self) -> None:
        """Scenario: delete existing local; expected key removal from frame."""
        frame = pysymex.core.memory.types.StackFrame("f", locals={"tmp": 1})
        frame.delete_local("tmp")
        assert "tmp" not in frame.locals
