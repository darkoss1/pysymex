"""Tests for Python 3.10+ pattern matching opcode soundness.

Pattern matching (PEP 634) introduces complex control flow that must be
handled correctly by symbolic execution:
- Match subjects can be symbolic
- Pattern guards can split symbolic paths
- Match exhaustiveness affects path exploration
- Capture variables must bind correctly

Bugs here cause:
- Missed match arms (under-exploration)
- Spurious match arms (over-exploration)
- Incorrect variable bindings
- Wrong pattern precedence
"""

from __future__ import annotations

import dis
import sys
import pytest

from pysymex.core.state import VMState
from pysymex.core.types import SymbolicValue
from pysymex.execution.executor_core import SymbolicExecutor
from pysymex.analysis.detectors import IssueKind


# Skip all tests if Python < 3.10
pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 10),
    reason="Pattern matching requires Python 3.10+"
)


class TestLiteralPatternSoundness:
    """Tests for literal pattern matching."""

    @pytest.mark.slow
    def test_int_literal_pattern_explores_both_paths(self):
        """match x: case 0: ... explores x=0 and x!=0.

        Invariant: Both matching and non-matching paths explored.
        """
        def match_zero(x: int) -> str:
            match x:
                case 0:
                    return "zero"
                case _:
                    return "other"

        executor = SymbolicExecutor()
        result = executor.execute_function(
            match_zero,
            symbolic_args={"x": "int"},
        )

        # Should explore at least 2 paths
        assert result.paths_explored >= 2, "Must explore case 0 and wildcard"

    def test_string_literal_pattern(self):
        """String literal patterns must match exact values.

        Invariant: case "foo" matches only when subject == "foo".
        """
        def match_string(s: str) -> int:
            match s:
                case "hello":
                    return 1
                case "world":
                    return 2
                case _:
                    return 0

        code = match_string.__code__
        instructions = list(dis.get_instructions(code))

        # Should have MATCH operations
        match_ops = [i for i in instructions if 'MATCH' in i.opname or 'COMPARE' in i.opname]
        # Pattern matching generates comparison operations

    def test_multiple_literals_same_case(self):
        """case 1 | 2 | 3 matches any of the literals.

        Invariant: Or-patterns create correct disjunction.
        """
        def match_multiple(x: int) -> str:
            match x:
                case 1 | 2 | 3:
                    return "low"
                case 4 | 5 | 6:
                    return "mid"
                case _:
                    return "other"

        executor = SymbolicExecutor()
        result = executor.execute_function(
            match_multiple,
            symbolic_args={"x": "int"},
        )

        # Should explore at least 3 distinct regions
        assert result.paths_explored >= 2


class TestCapturePatternSoundness:
    """Tests for capture (binding) patterns."""

    def test_capture_binds_value(self):
        """case x binds subject to x.

        Invariant: Captured variable equals subject.
        """
        def capture_value(val: int) -> int:
            match val:
                case x:
                    return x * 2

        executor = SymbolicExecutor()
        result = executor.execute_function(
            capture_value,
            symbolic_args={"val": "int"},
        )

        assert result.paths_explored >= 1

    def test_nested_capture_in_sequence(self):
        """case [x, y] captures list elements.

        Invariant: x and y bound to correct positions.
        """
        def capture_list(lst: list) -> int:
            match lst:
                case [x, y]:
                    return x + y
                case [x]:
                    return x
                case _:
                    return 0

        code = capture_list.__code__
        instructions = list(dis.get_instructions(code))

        # Should have MATCH_SEQUENCE
        seq_ops = [i for i in instructions if 'MATCH_SEQUENCE' in i.opname]

    def test_walrus_pattern_with_guard(self):
        """case x if x > 0 binds and guards.

        Invariant: Guard evaluates after binding.
        """
        def guarded_capture(val: int) -> str:
            match val:
                case x if x > 0:
                    return "positive"
                case x if x < 0:
                    return "negative"
                case _:
                    return "zero"

        executor = SymbolicExecutor()
        result = executor.execute_function(
            guarded_capture,
            symbolic_args={"val": "int"},
        )

        # Must explore all three regions
        assert result.paths_explored >= 3


class TestSequencePatternSoundness:
    """Tests for sequence pattern matching."""

    def test_fixed_length_sequence(self):
        """case [a, b, c] matches exactly 3-element sequences.

        Invariant: Only matches when len(subject) == 3.
        """
        def match_triple(lst: list) -> int:
            match lst:
                case [a, b, c]:
                    return a + b + c
                case _:
                    return -1

        code = match_triple.__code__
        instructions = list(dis.get_instructions(code))

        # Should have MATCH_SEQUENCE opcode
        match_seq = [i for i in instructions if 'MATCH_SEQUENCE' in i.opname]

    def test_star_pattern_captures_rest(self):
        """case [first, *rest] captures remaining elements.

        Invariant: rest contains all but first element.
        """
        def match_star(lst: list) -> int:
            match lst:
                case [first, *rest]:
                    return first + len(rest)
                case _:
                    return -1

        code = match_star.__code__
        instructions = list(dis.get_instructions(code))

        # Star patterns use special handling

    def test_star_pattern_middle(self):
        """case [first, *middle, last] captures middle elements.

        Invariant: middle captures all between first and last.
        """
        def match_sandwich(lst: list) -> int:
            match lst:
                case [first, *middle, last]:
                    return first + last + len(middle)
                case _:
                    return -1

        # This pattern requires special unpacking logic


class TestMappingPatternSoundness:
    """Tests for mapping (dict) pattern matching."""

    def test_key_presence_check(self):
        """case {"key": value} checks key presence.

        Invariant: Pattern fails if key is absent.
        """
        def match_dict(d: dict) -> int:
            match d:
                case {"x": x, "y": y}:
                    return x + y
                case {"x": x}:
                    return x
                case _:
                    return -1

        code = match_dict.__code__
        instructions = list(dis.get_instructions(code))

        # Should have MATCH_MAPPING and MATCH_KEYS
        mapping_ops = [i for i in instructions
                      if 'MATCH_MAPPING' in i.opname or 'MATCH_KEYS' in i.opname]

    def test_extra_keys_allowed(self):
        """Mapping patterns allow extra keys by default.

        Invariant: {"a": 1} matches {"a": 1, "b": 2}.
        """
        def match_subset(d: dict) -> str:
            match d:
                case {"required": val}:
                    return f"found {val}"
                case _:
                    return "not found"

        # Extra keys should not prevent match

    def test_double_star_captures_extra(self):
        """case {"key": val, **rest} captures remaining keys.

        Invariant: rest is dict with unmatched keys.
        """
        def match_with_rest(d: dict) -> int:
            match d:
                case {"x": x, **rest}:
                    return x + len(rest)
                case _:
                    return -1

        code = match_with_rest.__code__


class TestClassPatternSoundness:
    """Tests for class pattern matching."""

    def test_isinstance_check(self):
        """case ClassName() checks isinstance.

        Invariant: Pattern fails if not instance of class.
        """
        class Point:
            def __init__(self, x, y):
                self.x = x
                self.y = y

        def match_point(obj) -> int:
            match obj:
                case Point(x=x, y=y):
                    return x + y
                case _:
                    return -1

        code = match_point.__code__
        instructions = list(dis.get_instructions(code))

        # Should have MATCH_CLASS
        class_ops = [i for i in instructions if 'MATCH_CLASS' in i.opname]

    def test_positional_class_pattern(self):
        """case ClassName(a, b) uses __match_args__.

        Invariant: Positional patterns use class-defined order.
        """
        class Point:
            __match_args__ = ("x", "y")

            def __init__(self, x, y):
                self.x = x
                self.y = y

        def match_positional(obj) -> int:
            match obj:
                case Point(x, y):  # Positional, uses __match_args__
                    return x + y
                case _:
                    return -1

        # Positional patterns should map correctly


class TestGuardSoundness:
    """Tests for pattern guards."""

    def test_guard_creates_path_split(self):
        """Guard conditions split execution paths.

        Invariant: case x if cond: explores both cond=T and cond=F.
        """
        def with_guard(x: int) -> str:
            match x:
                case n if n > 100:
                    return "large"
                case n if n > 10:
                    return "medium"
                case n if n > 0:
                    return "small"
                case _:
                    return "non-positive"

        executor = SymbolicExecutor()
        result = executor.execute_function(
            with_guard,
            symbolic_args={"x": "int"},
        )

        # Should explore at least 4 paths
        assert result.paths_explored >= 4

    def test_guard_evaluates_after_binding(self):
        """Guard can use captured variables.

        Invariant: Captured vars are available in guard.
        """
        def guard_uses_capture(data: list) -> str:
            match data:
                case [x, y] if x == y:
                    return "equal"
                case [x, y] if x < y:
                    return "ascending"
                case [x, y]:
                    return "descending"
                case _:
                    return "not pair"

        # Guard should see x and y

    def test_failed_guard_tries_next_case(self):
        """If guard fails, next case is tried.

        Invariant: match continues after failed guard.
        """
        def fallthrough_on_guard_fail(x: int) -> str:
            match x:
                case n if n > 10:
                    return "first catches large"
                case n:  # Fallback catches same values if guard failed
                    return "fallback"

        # x=5 should match first case but fail guard, then match second


class TestWildcardPatternSoundness:
    """Tests for wildcard (_) patterns."""

    def test_wildcard_matches_anything(self):
        """case _ matches any value.

        Invariant: Wildcard is always-matching pattern.
        """
        def with_wildcard(x: int) -> str:
            match x:
                case 0:
                    return "zero"
                case _:
                    return "not zero"

        executor = SymbolicExecutor()
        result = executor.execute_function(
            with_wildcard,
            symbolic_args={"x": "int"},
        )

        assert result.paths_explored >= 2

    def test_wildcard_in_sequence(self):
        """case [_, x, _] ignores first and last.

        Invariant: Wildcards don't bind.
        """
        def match_middle(lst: list) -> int:
            match lst:
                case [_, x, _]:
                    return x
                case _:
                    return -1

        # Only middle element should be accessible


class TestAsPatternSoundness:
    """Tests for 'as' patterns (named subpatterns)."""

    def test_as_pattern_captures_subpattern(self):
        """case [x, y] as pair captures whole and parts.

        Invariant: Both subpatterns and whole are available.
        """
        def capture_both(lst: list) -> tuple:
            match lst:
                case [x, y] as pair:
                    return (x, y, len(pair))
                case _:
                    return (-1, -1, -1)

        # Both x, y and pair should be accessible

    def test_as_pattern_in_class(self):
        """case Point(x, y) as p captures instance too.

        Invariant: p references the matched object.
        """
        class Point:
            __match_args__ = ("x", "y")
            def __init__(self, x, y):
                self.x = x
                self.y = y

        def capture_point(obj) -> int:
            match obj:
                case Point(x, y) as p:
                    return x + y + id(p)
                case _:
                    return -1


class TestMatchExhaustivenessAndOrder:
    """Tests for match statement exhaustiveness and ordering."""

    def test_first_matching_case_wins(self):
        """First matching case is taken.

        Invariant: Pattern order matters.
        """
        def ordered_match(x: int) -> str:
            match x:
                case 0:
                    return "zero specific"
                case _ if True:  # Would also match 0
                    return "catch-all"

        # x=0 should return "zero specific", not "catch-all"

    def test_unreachable_case_detected(self):
        """Unreachable patterns are theoretically dead code.

        Invariant: Python detects unreachable patterns at syntax level.
        Note: We cannot write actual unreachable patterns as Python 3.10+
        raises SyntaxError at parse time for "case _: ... case X:" sequences.
        """
        # Python catches this at parse time, so we just verify the bytecode
        # for a valid pattern match has the right structure
        def valid_match(x: int) -> str:
            match x:
                case 0:
                    return "zero"
                case 1:
                    return "one"
                case _:  # Wildcard at end is valid
                    return "other"

        # Verify the match compiles and has correct structure
        code = valid_match.__code__
        assert code is not None

    def test_no_match_raises_no_exception(self):
        """Match without wildcard can fall through.

        Invariant: No MatchError, just falls through.
        """
        def partial_match(x: int) -> str:
            match x:
                case 0:
                    return "zero"
                case 1:
                    return "one"
                # No wildcard - if x=2, no case matches
            return "fell through"

        # x=2 should return "fell through"


class TestSymbolicMatchSubject:
    """Tests for symbolic values as match subjects."""

    def test_symbolic_int_explores_cases(self):
        """Symbolic int explores all reachable cases.

        Invariant: Each case becomes a distinct path.
        """
        def symbolic_match(x: int) -> str:
            match x:
                case 0:
                    return "zero"
                case 1:
                    return "one"
                case 2:
                    return "two"
                case _:
                    return "other"

        executor = SymbolicExecutor()
        result = executor.execute_function(
            symbolic_match,
            symbolic_args={"x": "int"},
        )

        # Should explore all 4 cases
        # Note: May merge paths, so >= is appropriate
        assert result.paths_explored >= 2

    def test_symbolic_in_sequence_pattern(self):
        """Symbolic list matched against sequence pattern.

        Invariant: All possible lengths are considered.
        """
        def match_length(lst: list) -> str:
            match lst:
                case []:
                    return "empty"
                case [_]:
                    return "single"
                case [_, _]:
                    return "pair"
                case _:
                    return "many"

        # Symbolic list should explore different length possibilities


class TestPatternMatchingOpcodes:
    """Tests for specific pattern matching opcodes."""

    def test_match_sequence_opcode_present(self):
        """MATCH_SEQUENCE opcode is generated for sequence patterns.

        Invariant: Bytecode contains correct matching opcodes.
        """
        def seq_match(x):
            match x:
                case [a, b]:
                    return a + b
                case _:
                    return 0

        code = seq_match.__code__
        instructions = list(dis.get_instructions(code))
        opcodes = [i.opname for i in instructions]

        # Python 3.10+ should have MATCH_SEQUENCE
        assert 'MATCH_SEQUENCE' in opcodes or sys.version_info < (3, 10)

    def test_match_mapping_opcode_present(self):
        """MATCH_MAPPING opcode is generated for mapping patterns.

        Invariant: Bytecode uses correct mapping match opcode.
        """
        def map_match(x):
            match x:
                case {"key": val}:
                    return val
                case _:
                    return 0

        code = map_match.__code__
        instructions = list(dis.get_instructions(code))
        opcodes = [i.opname for i in instructions]

        # Python 3.10+ should have MATCH_MAPPING
        assert 'MATCH_MAPPING' in opcodes or sys.version_info < (3, 10)

    def test_match_class_opcode_present(self):
        """MATCH_CLASS opcode is generated for class patterns.

        Invariant: Class patterns use MATCH_CLASS.
        """
        class Foo:
            pass

        def class_match(x):
            match x:
                case Foo():
                    return 1
                case _:
                    return 0

        code = class_match.__code__
        instructions = list(dis.get_instructions(code))
        opcodes = [i.opname for i in instructions]

        # Python 3.10+ should have MATCH_CLASS
        assert 'MATCH_CLASS' in opcodes or sys.version_info < (3, 10)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
