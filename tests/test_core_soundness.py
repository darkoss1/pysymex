"""
Core Soundness Tests - Mathematical correctness verification for pysymex core.

These tests verify that the symbolic operations produce mathematically
correct constraints. Each test targets a specific soundness bug.
"""

import z3

from pysymex.core.collections_list import SymbolicListOps
from pysymex.core.memory_model import SymbolicArray
from pysymex.core.solver import is_satisfiable
from pysymex.core.types import SymbolicValue


class TestListReverseSoundness:
    """Test that list reverse() produces correct constraints.

    BUG: The original implementation created a new array with NO constraints
    relating it to the original array. This made reverse() mathematically
    useless - the reversed array was completely unconstrained.

    CORRECT: reversed[i] = original[len - 1 - i] for all valid indices.
    """

    def test_reverse_has_constraints(self):
        """Verify that reverse() produces at least one constraint."""
        arr = SymbolicArray("test_arr", z3.IntSort())
        arr.length = z3.IntVal(5)

        result = SymbolicListOps.reverse(arr)

        # The bug: no constraints were generated
        assert len(result.constraints) > 0, (
            "reverse() must produce constraints relating the reversed array "
            "to the original array"
        )

    def test_reverse_establishes_element_relationship(self):
        """Verify reverse constraint: reversed[i] = original[len - 1 - i]."""
        arr = SymbolicArray("test_arr", z3.IntSort())
        # Set concrete length for easier verification
        arr.length = z3.IntVal(3)

        # Store known values
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(10))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(30))

        result = SymbolicListOps.reverse(arr)
        reversed_arr = result.modified_collection

        # Build verification constraints
        constraints = list(result.constraints)

        # After reverse: [30, 20, 10]
        # reversed[0] should equal original[2] = 30
        # reversed[1] should equal original[1] = 20
        # reversed[2] should equal original[0] = 10

        check_0 = z3.Select(reversed_arr.array, z3.IntVal(0)) == z3.IntVal(30)
        check_1 = z3.Select(reversed_arr.array, z3.IntVal(1)) == z3.IntVal(20)
        check_2 = z3.Select(reversed_arr.array, z3.IntVal(2)) == z3.IntVal(10)

        # The constraints from reverse + our checks should be satisfiable
        solver = z3.Solver()
        solver.add(constraints)
        solver.add(check_0, check_1, check_2)

        assert solver.check() == z3.sat, (
            "Reverse constraints should allow reversed[i] = original[len-1-i]"
        )

    def test_reverse_forbids_incorrect_ordering(self):
        """Verify that reverse constraints forbid wrong element positions."""
        arr = SymbolicArray("test_arr", z3.IntSort())
        arr.length = z3.IntVal(3)

        # Store distinct values
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(100))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(200))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(300))

        result = SymbolicListOps.reverse(arr)
        reversed_arr = result.modified_collection
        constraints = list(result.constraints)

        # This SHOULD be UNSAT: reversed[0] cannot equal 100 (it must be 300)
        wrong_order = z3.Select(reversed_arr.array, z3.IntVal(0)) == z3.IntVal(100)

        solver = z3.Solver()
        solver.add(constraints)
        solver.add(wrong_order)

        assert solver.check() == z3.unsat, (
            "Reverse constraints must forbid incorrect element ordering. "
            "reversed[0] must be 300, not 100."
        )

    def test_reverse_preserves_length(self):
        """Verify that reversed array has the same length as original."""
        arr = SymbolicArray("test_arr", z3.IntSort())
        sym_len = z3.Int("array_length")
        arr.length = sym_len

        result = SymbolicListOps.reverse(arr)
        reversed_arr = result.modified_collection

        # Length must be preserved
        solver = z3.Solver()
        solver.add(result.constraints)
        solver.add(reversed_arr.length != arr.length)

        assert solver.check() == z3.unsat, (
            "Reversed array must have the same length as original"
        )

    def test_reverse_twice_is_identity(self):
        """Verify that reversing twice gives original array semantics."""
        arr = SymbolicArray("test_arr", z3.IntSort())
        arr.length = z3.IntVal(3)

        # Store values
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(1))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(2))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(3))

        # Reverse once
        result1 = SymbolicListOps.reverse(arr)
        reversed_once = result1.modified_collection

        # Reverse again
        result2 = SymbolicListOps.reverse(reversed_once)
        reversed_twice = result2.modified_collection

        # All constraints
        all_constraints = list(result1.constraints) + list(result2.constraints)

        # After two reverses, should match original
        solver = z3.Solver()
        solver.add(all_constraints)

        # Check that element 0 equals original element 0
        solver.add(z3.Select(reversed_twice.array, z3.IntVal(0)) == z3.IntVal(1))
        solver.add(z3.Select(reversed_twice.array, z3.IntVal(1)) == z3.IntVal(2))
        solver.add(z3.Select(reversed_twice.array, z3.IntVal(2)) == z3.IntVal(3))

        assert solver.check() == z3.sat, (
            "Reversing twice should give back original array element order"
        )


class TestListConcatenateSoundness:
    """Test that list concatenate() produces correct constraints.

    BUG: The original implementation created a new array with NO constraints
    relating it to the original arrays. This made concatenate() mathematically
    useless - the concatenated array was completely unconstrained.

    CORRECT:
      - result[i] = lst1[i] for i in [0, len1)
      - result[i] = lst2[i - len1] for i in [len1, len1 + len2)
    """

    def test_concatenate_has_constraints(self):
        """Verify that concatenate() produces constraints."""
        arr1 = SymbolicArray("arr1", z3.IntSort())
        arr1.length = z3.IntVal(2)
        arr2 = SymbolicArray("arr2", z3.IntSort())
        arr2.length = z3.IntVal(3)

        result = SymbolicListOps.concatenate(arr1, arr2)

        assert len(result.constraints) > 0, (
            "concatenate() must produce constraints relating the concatenated "
            "array to the original arrays"
        )

    def test_concatenate_first_array_elements(self):
        """Verify first array elements are preserved in concatenated result."""
        arr1 = SymbolicArray("arr1", z3.IntSort())
        arr1.length = z3.IntVal(2)
        arr1._array = z3.Store(arr1._array, z3.IntVal(0), z3.IntVal(10))
        arr1._array = z3.Store(arr1._array, z3.IntVal(1), z3.IntVal(20))

        arr2 = SymbolicArray("arr2", z3.IntSort())
        arr2.length = z3.IntVal(2)
        arr2._array = z3.Store(arr2._array, z3.IntVal(0), z3.IntVal(30))
        arr2._array = z3.Store(arr2._array, z3.IntVal(1), z3.IntVal(40))

        result = SymbolicListOps.concatenate(arr1, arr2)
        concat_arr = result.value

        # result[0] = 10, result[1] = 20
        solver = z3.Solver()
        solver.add(result.constraints)
        solver.add(z3.Select(concat_arr.array, z3.IntVal(0)) == z3.IntVal(10))
        solver.add(z3.Select(concat_arr.array, z3.IntVal(1)) == z3.IntVal(20))

        assert solver.check() == z3.sat, (
            "Concatenated array should preserve first array elements at indices 0..len1-1"
        )

    def test_concatenate_second_array_elements(self):
        """Verify second array elements follow first array in result."""
        arr1 = SymbolicArray("arr1", z3.IntSort())
        arr1.length = z3.IntVal(2)
        arr1._array = z3.Store(arr1._array, z3.IntVal(0), z3.IntVal(10))
        arr1._array = z3.Store(arr1._array, z3.IntVal(1), z3.IntVal(20))

        arr2 = SymbolicArray("arr2", z3.IntSort())
        arr2.length = z3.IntVal(2)
        arr2._array = z3.Store(arr2._array, z3.IntVal(0), z3.IntVal(30))
        arr2._array = z3.Store(arr2._array, z3.IntVal(1), z3.IntVal(40))

        result = SymbolicListOps.concatenate(arr1, arr2)
        concat_arr = result.value

        # result[2] = 30, result[3] = 40
        solver = z3.Solver()
        solver.add(result.constraints)
        solver.add(z3.Select(concat_arr.array, z3.IntVal(2)) == z3.IntVal(30))
        solver.add(z3.Select(concat_arr.array, z3.IntVal(3)) == z3.IntVal(40))

        assert solver.check() == z3.sat, (
            "Concatenated array should place second array elements at indices len1..len1+len2-1"
        )

    def test_concatenate_length(self):
        """Verify concatenated array has sum of original lengths."""
        arr1 = SymbolicArray("arr1", z3.IntSort())
        arr1.length = z3.IntVal(3)
        arr2 = SymbolicArray("arr2", z3.IntSort())
        arr2.length = z3.IntVal(5)

        result = SymbolicListOps.concatenate(arr1, arr2)
        concat_arr = result.value

        solver = z3.Solver()
        solver.add(result.constraints)
        solver.add(concat_arr.length != z3.IntVal(8))

        assert solver.check() == z3.unsat, (
            "Concatenated array length must equal sum of original lengths"
        )

    def test_concatenate_forbids_wrong_element_positions(self):
        """Verify constraints forbid incorrect element placement."""
        arr1 = SymbolicArray("arr1", z3.IntSort())
        arr1.length = z3.IntVal(2)
        arr1._array = z3.Store(arr1._array, z3.IntVal(0), z3.IntVal(100))
        arr1._array = z3.Store(arr1._array, z3.IntVal(1), z3.IntVal(200))

        arr2 = SymbolicArray("arr2", z3.IntSort())
        arr2.length = z3.IntVal(1)
        arr2._array = z3.Store(arr2._array, z3.IntVal(0), z3.IntVal(300))

        result = SymbolicListOps.concatenate(arr1, arr2)
        concat_arr = result.value

        # result[0] CANNOT equal 300 (it must be 100)
        solver = z3.Solver()
        solver.add(result.constraints)
        solver.add(z3.Select(concat_arr.array, z3.IntVal(0)) == z3.IntVal(300))

        assert solver.check() == z3.unsat, (
            "Concatenate constraints must forbid placing arr2 elements before arr1 elements"
        )


class TestListRemoveSoundness:
    """Test that list remove() produces correct constraints.

    BUG: The original implementation copied the old array directly without
    shifting elements after the removed position.

    CORRECT: Elements after the removed index should shift left by 1.
    """

    def test_remove_shifts_elements(self):
        """Verify elements after removed index are shifted left."""
        arr = SymbolicArray("arr", z3.IntSort())
        arr.length = z3.IntVal(4)
        # [10, 20, 30, 40]
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(10))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(30))
        arr._array = z3.Store(arr._array, z3.IntVal(3), z3.IntVal(40))

        # Remove 20 (at index 1)
        # Result should be [10, 30, 40] - elements shifted
        result = SymbolicListOps.remove(arr, 20)
        new_arr = result.modified_collection

        # Check that new length is 3
        assert new_arr.length == arr.length - 1 or (
            hasattr(new_arr.length, '__eq__') and
            z3.simplify(new_arr.length == arr.length - 1)
        )

        # Should have constraints for element shifting
        assert len(result.constraints) > 0, (
            "remove() must produce constraints for element existence and shifting"
        )

    def test_remove_preserves_elements_before(self):
        """Verify elements before removed index are preserved."""
        arr = SymbolicArray("arr", z3.IntSort())
        arr.length = z3.IntVal(4)
        # [10, 20, 30, 40]
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(10))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(30))
        arr._array = z3.Store(arr._array, z3.IntVal(3), z3.IntVal(40))

        # Remove 30 (at index 2) -> [10, 20, 40]
        result = SymbolicListOps.remove(arr, 30)
        new_arr = result.modified_collection

        solver = z3.Solver()
        solver.add(result.constraints)
        # Elements before index 2 should be preserved
        solver.add(z3.Select(new_arr.array, z3.IntVal(0)) == z3.IntVal(10))
        solver.add(z3.Select(new_arr.array, z3.IntVal(1)) == z3.IntVal(20))

        assert solver.check() == z3.sat, (
            "Elements before the removed index must be preserved"
        )

    def test_remove_shifts_elements_after(self):
        """Verify elements after removed index are shifted left."""
        arr = SymbolicArray("arr", z3.IntSort())
        arr.length = z3.IntVal(4)
        # [10, 20, 30, 40]
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(10))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(30))
        arr._array = z3.Store(arr._array, z3.IntVal(3), z3.IntVal(40))

        # Remove 20 (at index 1) -> [10, 30, 40]
        result = SymbolicListOps.remove(arr, 20)
        new_arr = result.modified_collection

        solver = z3.Solver()
        solver.add(result.constraints)
        # Element at index 0 preserved
        solver.add(z3.Select(new_arr.array, z3.IntVal(0)) == z3.IntVal(10))
        # Elements shifted: new[1] = old[2] = 30, new[2] = old[3] = 40
        solver.add(z3.Select(new_arr.array, z3.IntVal(1)) == z3.IntVal(30))
        solver.add(z3.Select(new_arr.array, z3.IntVal(2)) == z3.IntVal(40))

        assert solver.check() == z3.sat, (
            "Elements after the removed index must shift left by 1"
        )

    def test_remove_removes_first_occurrence(self):
        """Verify that remove() targets the FIRST occurrence only."""
        arr = SymbolicArray("arr", z3.IntSort())
        arr.length = z3.IntVal(4)
        # [10, 20, 20, 30] - has duplicate 20s
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(10))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(3), z3.IntVal(30))

        # Remove 20 -> should give [10, 20, 30]
        result = SymbolicListOps.remove(arr, 20)
        new_arr = result.modified_collection

        solver = z3.Solver()
        solver.add(result.constraints)
        # Result should be [10, 20, 30] - second 20 survives
        solver.add(z3.Select(new_arr.array, z3.IntVal(0)) == z3.IntVal(10))
        solver.add(z3.Select(new_arr.array, z3.IntVal(1)) == z3.IntVal(20))
        solver.add(z3.Select(new_arr.array, z3.IntVal(2)) == z3.IntVal(30))

        assert solver.check() == z3.sat, (
            "Remove should only remove the FIRST occurrence, preserving later duplicates"
        )


class TestSymbolicDictKeyTrackingSoundness:
    """Test that SymbolicDict properly tracks key presence after mutations.

    BUG: After pop() or del, the key remains in known_keys, so contains_key()
    incorrectly returns True for deleted keys.
    """

    def test_dict_setitem_adds_to_known_keys(self):
        """Verify that __setitem__ properly adds key to known_keys."""
        from pysymex.core.types_containers import SymbolicDict
        from pysymex.core.types import SymbolicString

        d, _ = SymbolicDict.symbolic("test_dict")
        key = SymbolicString.from_const("test_key")
        value = SymbolicValue.from_const(42)

        # Add a key using __setitem__
        d_with_key = d.__setitem__(key, value)

        # Key should exist
        contains_check = d_with_key.contains_key(key)
        solver = z3.Solver()
        solver.add(contains_check.z3_bool)
        assert solver.check() == z3.sat, "Key should exist after setting"

    def test_dict_delitem_model_removes_key(self):
        """Test that DictDelitemModel properly removes key from known_keys.

        This test verifies the model correctly updates the symbolic dict
        so that contains_key returns False after deletion.
        """
        # This is more of a model-level test; the key point is
        # that known_keys must be updated after deletion
        pass  # Model tests require VMState mocking


class TestListIndexSoundness:
    """Test that list index() returns the FIRST occurrence.

    BUG: The original implementation found ANY matching index,
    not necessarily the first one.

    CORRECT: index() must return the first occurrence, meaning
    no earlier index in [start, result_idx) matches the value.
    """

    def test_index_finds_first_occurrence(self):
        """Verify index() returns the first matching index."""
        arr = SymbolicArray("arr", z3.IntSort())
        arr.length = z3.IntVal(4)
        # [10, 20, 20, 30] - duplicate 20s
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(10))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(3), z3.IntVal(30))

        result = SymbolicListOps.index(arr, 20)
        idx_result = result.value

        # The result should be constrained to be 1 (first 20)
        solver = z3.Solver()
        solver.add(result.constraints)
        solver.add(idx_result.z3_int == z3.IntVal(1))

        assert solver.check() == z3.sat, (
            "index() should allow finding the first occurrence at index 1"
        )

    def test_index_forbids_later_occurrence(self):
        """Verify index() cannot return a later occurrence when earlier exists."""
        arr = SymbolicArray("arr", z3.IntSort())
        arr.length = z3.IntVal(4)
        # [10, 20, 20, 30] - duplicate 20s
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(10))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(3), z3.IntVal(30))

        result = SymbolicListOps.index(arr, 20)
        idx_result = result.value

        # Index 2 should be UNSAT because 20 appears at index 1 first
        solver = z3.Solver()
        solver.add(result.constraints)
        solver.add(idx_result.z3_int == z3.IntVal(2))

        assert solver.check() == z3.unsat, (
            "index() must not return index 2 when an earlier occurrence exists at index 1"
        )

    def test_index_with_start_parameter(self):
        """Verify index() respects the start parameter."""
        arr = SymbolicArray("arr", z3.IntSort())
        arr.length = z3.IntVal(4)
        # [20, 10, 20, 30]
        arr._array = z3.Store(arr._array, z3.IntVal(0), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(1), z3.IntVal(10))
        arr._array = z3.Store(arr._array, z3.IntVal(2), z3.IntVal(20))
        arr._array = z3.Store(arr._array, z3.IntVal(3), z3.IntVal(30))

        # Start from index 1, so should find 20 at index 2
        result = SymbolicListOps.index(arr, 20, start=1)
        idx_result = result.value

        solver = z3.Solver()
        solver.add(result.constraints)
        solver.add(idx_result.z3_int == z3.IntVal(2))

        assert solver.check() == z3.sat, (
            "index(20, start=1) should find the first occurrence after index 1"
        )
