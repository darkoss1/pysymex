import pysymex.core.memory.collections.lists
import z3

class TestOpResult:
    """Test suite for pysymex.core.memory.collections.lists.OpResult."""
    def test_success(self) -> None:
        """Scenario: no error message is present; expected success flag is true."""
        result = pysymex.core.memory.collections.lists.OpResult(value=1)
        assert result.success is True

    def test_with_constraint(self) -> None:
        """Scenario: add one constraint; expected result stores that exact constraint."""
        result = pysymex.core.memory.collections.lists.OpResult(value=None)
        constraint = z3.Int("x") > 0
        updated = result.with_constraint(constraint)
        assert updated.constraints == [constraint]


class TestSymbolicListOps:
    """Test suite for pysymex.core.memory.collections.lists.SymbolicListOps."""
    def test_length(self) -> None:
        """Scenario: concrete list length; expected exact integer size."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.length([1, 2, 3])
        assert result.value == 3

    def test_getitem(self) -> None:
        """Scenario: concrete index lookup; expected selected element value."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.getitem([10, 20, 30], 1)
        assert result.value == 20

    def test_setitem(self) -> None:
        """Scenario: concrete assignment in range; expected updated list snapshot."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.setitem([1, 2, 3], 1, 99)
        assert result.modified_collection == [1, 99, 3]

    def test_append(self) -> None:
        """Scenario: append to concrete list; expected item added at tail."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.append([1, 2], 3)
        assert result.modified_collection == [1, 2, 3]

    def test_extend(self) -> None:
        """Scenario: extend concrete list with concrete items; expected concatenated list."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.extend([1, 2], [3, 4])
        assert result.modified_collection == [1, 2, 3, 4]

    def test_pop(self) -> None:
        """Scenario: pop default index from concrete list; expected last item returned."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.pop([1, 2, 3])
        assert result.value == 3

    def test_insert(self) -> None:
        """Scenario: insert into concrete list; expected shifted list state."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.insert([1, 3], 1, 2)
        assert result.modified_collection == [1, 2, 3]

    def test_remove(self) -> None:
        """Scenario: remove first matching value; expected first occurrence deleted."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.remove([1, 2, 2, 3], 2)
        assert result.modified_collection == [1, 2, 3]

    def test_index(self) -> None:
        """Scenario: find index in concrete list; expected first matching position."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.index([4, 5, 6, 5], 5)
        assert result.value == 1

    def test_count(self) -> None:
        """Scenario: count repeated value in concrete list; expected exact multiplicity."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.count([1, 2, 2, 3], 2)
        assert result.value == 2

    def test_reverse(self) -> None:
        """Scenario: reverse concrete list in place; expected reversed ordering."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.reverse([1, 2, 3])
        assert result.modified_collection == [3, 2, 1]

    def test_contains(self) -> None:
        """Scenario: membership check on concrete list; expected boolean inclusion result."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.contains([1, 2, 3], 2)
        assert result.value is True

    def test_slice(self) -> None:
        """Scenario: concrete slicing with bounds; expected exact slice segment."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.slice([1, 2, 3, 4], 1, 3)
        assert result.value == [2, 3]

    def test_concatenate(self) -> None:
        """Scenario: concatenate two concrete lists; expected merged sequence."""
        result = pysymex.core.memory.collections.lists.SymbolicListOps.concatenate([1, 2], [3, 4])
        assert result.value == [1, 2, 3, 4]


class TestSymbolicStringOps:
    """Test suite for pysymex.core.memory.collections.lists.SymbolicStringOps."""
    def test_length(self) -> None:
        """Scenario: concrete string length; expected character count."""
        result = pysymex.core.memory.collections.lists.SymbolicStringOps.length("core")
        assert result.value == 4

    def test_contains(self) -> None:
        """Scenario: substring containment on concrete string; expected true match."""
        result = pysymex.core.memory.collections.lists.SymbolicStringOps.contains("symbolic", "bol")
        assert result.value is True

    def test_concatenate(self) -> None:
        """Scenario: concatenate concrete strings; expected exact concatenation."""
        result = pysymex.core.memory.collections.lists.SymbolicStringOps.concatenate("py", "symex")
        assert result.value == "pysymex"

    def test_startswith(self) -> None:
        """Scenario: prefix check on concrete string; expected positive prefix match."""
        result = pysymex.core.memory.collections.lists.SymbolicStringOps.startswith("solver", "sol")
        assert result.value is True

    def test_endswith(self) -> None:
        """Scenario: suffix check on concrete string; expected positive suffix match."""
        result = pysymex.core.memory.collections.lists.SymbolicStringOps.endswith("solver", "ver")
        assert result.value is True
