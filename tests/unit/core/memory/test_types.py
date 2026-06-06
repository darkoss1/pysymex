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

    def test_same_region(self) -> None:
        """Scenario: compare regions; expected true only for identical regions."""
        left = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.STACK, 1
        )
        right = pysymex.core.memory.types.SymbolicAddress(
            pysymex.core.memory.types.MemoryRegion.STACK, 2
        )
        assert left.same_region(right) is True


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
