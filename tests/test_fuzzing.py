"""Tests for property-based testing (fuzzing) infrastructure."""

import z3
from hypothesis import given, settings
from hypothesis import strategies as st

from pysymex.core.types import SymbolicValue
from pysymex.testing.fuzzing import (
    ConformanceGenerator,
    # Property tests
    ConformanceTest,
    # Bytecode strategies
    MockInstruction,
    # Stateful testing
    SymbolicStateMachine,
    arithmetic_ops,
    comparison_ops,
    invariants,
    mock_instructions,
    postconditions,
    # Contract strategies
    preconditions,
    symbolic_booleans,
    symbolic_dicts,
    symbolic_floats,
    # Value strategies
    symbolic_integers,
    # Collection strategies
    symbolic_lists,
    symbolic_none,
    symbolic_sets,
    symbolic_strings,
    symbolic_tuples,
    symbolic_values,
    z3_arithmetic_exprs,
    z3_bool_exprs,
    z3_bool_vars,
    z3_int_constants,
    # Z3 strategies
    z3_int_vars,
)

# =============================================================================
# Value Strategy Tests
# =============================================================================


class TestValueStrategies:
    """Tests for value generation strategies."""

    @given(symbolic_integers())
    @settings(max_examples=20)
    def test_symbolic_integers(self, sv):
        """Test symbolic integer generation."""
        assert isinstance(sv, SymbolicValue)

    @given(symbolic_booleans())
    @settings(max_examples=10)
    def test_symbolic_booleans(self, sv):
        """Test symbolic boolean generation."""
        assert isinstance(sv, SymbolicValue)

    @given(symbolic_strings(max_size=10))
    @settings(max_examples=20)
    def test_symbolic_strings(self, sv):
        """Test symbolic string generation."""
        assert isinstance(sv, SymbolicValue)

    @given(symbolic_floats())
    @settings(max_examples=20)
    def test_symbolic_floats(self, sv):
        """Test symbolic float generation."""
        assert isinstance(sv, SymbolicValue)

    @given(symbolic_none())
    @settings(max_examples=5)
    def test_symbolic_none(self, sv):
        """Test symbolic None generation."""
        assert isinstance(sv, SymbolicValue)

    @given(symbolic_values())
    @settings(max_examples=30)
    def test_symbolic_values(self, sv):
        """Test any symbolic value generation."""
        assert isinstance(sv, SymbolicValue)


class TestCollectionStrategies:
    """Tests for collection generation strategies."""

    @given(symbolic_lists(st.integers(), max_size=5))
    @settings(max_examples=20)
    def test_symbolic_lists(self, sv):
        """Test symbolic list generation."""
        assert isinstance(sv, SymbolicValue)

    @given(symbolic_dicts(max_size=3))
    @settings(max_examples=20)
    def test_symbolic_dicts(self, sv):
        """Test symbolic dict generation."""
        assert isinstance(sv, SymbolicValue)

    @given(symbolic_sets(st.integers(-10, 10), max_size=5))
    @settings(max_examples=20)
    def test_symbolic_sets(self, sv):
        """Test symbolic set generation."""
        assert isinstance(sv, SymbolicValue)

    @given(symbolic_tuples(st.integers(), st.booleans()))
    @settings(max_examples=20)
    def test_symbolic_tuples(self, sv):
        """Test symbolic tuple generation."""
        assert isinstance(sv, SymbolicValue)


# =============================================================================
# Z3 Strategy Tests
# =============================================================================


class TestZ3Strategies:
    """Tests for Z3 expression strategies."""

    @given(z3_int_vars())
    @settings(max_examples=20)
    def test_z3_int_vars(self, var):
        """Test Z3 integer variable generation."""
        assert z3.is_int(var)

    @given(z3_bool_vars())
    @settings(max_examples=20)
    def test_z3_bool_vars(self, var):
        """Test Z3 boolean variable generation."""
        assert z3.is_bool(var)

    @given(z3_int_constants())
    @settings(max_examples=20)
    def test_z3_int_constants(self, const):
        """Test Z3 integer constant generation."""
        assert z3.is_int(const)

    @given(z3_arithmetic_exprs(depth=2))
    @settings(max_examples=30)
    def test_z3_arithmetic_exprs(self, expr):
        """Test Z3 arithmetic expression generation."""
        assert z3.is_arith(expr)  # type: ignore[reportAttributeAccessIssue]
        # Should be able to simplify
        simplified = z3.simplify(expr)
        assert simplified is not None

    @given(z3_bool_exprs(depth=2))
    @settings(max_examples=30)
    def test_z3_bool_exprs(self, expr):
        """Test Z3 boolean expression generation."""
        assert z3.is_bool(expr)
        # Should be decidable
        solver = z3.Solver()
        solver.add(expr)
        result = solver.check()
        assert result in (z3.sat, z3.unsat)


# =============================================================================
# Bytecode Strategy Tests
# =============================================================================


class TestBytecodeStrategies:
    """Tests for bytecode generation strategies."""

    @given(arithmetic_ops())
    @settings(max_examples=20)
    def test_arithmetic_ops(self, op):
        """Test arithmetic operation generation."""
        assert isinstance(op, int)
        assert 0 <= op <= 20  # Valid binary op codes

    @given(comparison_ops())
    @settings(max_examples=20)
    def test_comparison_ops(self, op):
        """Test comparison operation generation."""
        assert isinstance(op, int)
        assert 0 <= op <= 5  # <, <=, ==, !=, >, >=

    @given(mock_instructions())
    @settings(max_examples=30)
    def test_mock_instructions(self, instr):
        """Test mock instruction generation."""
        assert isinstance(instr, MockInstruction)
        assert isinstance(instr.opname, str)

    def test_mock_instruction_opcode(self):
        """Test getting opcode from mock instruction."""
        instr = MockInstruction("POP_TOP")
        assert instr.opcode > 0  # Should be a valid opcode


# =============================================================================
# Contract Strategy Tests
# =============================================================================


class TestContractStrategies:
    """Tests for contract generation strategies."""

    @given(preconditions())
    @settings(max_examples=30)
    def test_preconditions(self, pre):
        """Test precondition generation."""
        assert isinstance(pre, str)
        assert any(op in pre for op in [">", "<", "=", "!"])

    @given(postconditions())
    @settings(max_examples=30)
    def test_postconditions(self, post):
        """Test postcondition generation."""
        assert isinstance(post, str)
        assert len(post) > 0

    @given(invariants())
    @settings(max_examples=20)
    def test_invariants(self, inv):
        """Test invariant generation."""
        assert isinstance(inv, str)
        assert "i" in inv or "n" in inv


# =============================================================================
# Stateful Machine Tests
# =============================================================================


class TestStatefulMachine:
    """Tests for stateful testing machine."""

    def test_machine_creation(self):
        """Test creating state machine."""
        machine = SymbolicStateMachine()
        assert machine.stack == []
        assert machine.locals == {}

    def test_push_and_pop(self):
        """Test push and pop operations."""
        machine = SymbolicStateMachine()
        machine.stack.append(42)
        assert len(machine.stack) == 1
        val = machine.stack.pop()
        assert val == 42

    def test_store_and_load(self):
        """Test store and load operations."""
        machine = SymbolicStateMachine()
        machine.locals["x"] = 100
        assert machine.locals["x"] == 100

    def test_binary_operations(self):
        """Test binary operations."""
        machine = SymbolicStateMachine()
        machine.stack.append(10)
        machine.stack.append(5)

        # Simulate add
        b = machine.stack.pop()
        a = machine.stack.pop()
        machine.stack.append(a + b)

        assert machine.stack[-1] == 15


# =============================================================================
# Property Tests
# =============================================================================


class TestPropertyTests:
    """Tests that property tests work correctly."""

    @given(st.integers(), st.integers())
    @settings(max_examples=20)
    def test_addition_commutative(self, a, b):
        """Addition should be commutative."""
        assert a + b == b + a

    @given(st.integers(), st.integers(), st.integers())
    @settings(max_examples=20)
    def test_addition_associative(self, a, b, c):
        """Addition should be associative."""
        assert (a + b) + c == a + (b + c)

    @given(st.lists(st.integers(), min_size=1, max_size=10))
    @settings(max_examples=20)
    def test_list_properties(self, xs):
        """Test list length property."""
        assert len(xs) >= 1


# =============================================================================
# Conformance Tests
# =============================================================================


class TestConformanceGenerator:
    """Tests for conformance test generator."""

    def test_create_generator(self):
        """Test creating generator."""
        gen = ConformanceGenerator()
        assert gen.tests == []

    def test_add_expression_test(self):
        """Test adding expression test."""
        gen = ConformanceGenerator()
        gen.add_expression_test("test1", "1 + 2")

        assert len(gen.tests) == 1
        assert gen.tests[0].expected_result == 3

    def test_add_expression_with_error(self):
        """Test adding expression that raises."""
        gen = ConformanceGenerator()
        gen.add_expression_test("test_div_zero", "1 / 0")

        assert len(gen.tests) == 1
        assert gen.tests[0].expected_exception == ZeroDivisionError

    def test_add_statement_test(self):
        """Test adding statement test."""
        gen = ConformanceGenerator()
        gen.add_statement_test("test_assign", "x = 5", "x")

        assert len(gen.tests) == 1
        assert gen.tests[0].expected_result == 5

    def test_generate_arithmetic_tests(self):
        """Test generating arithmetic tests."""
        gen = ConformanceGenerator()
        gen.generate_arithmetic_tests()

        assert len(gen.tests) > 100  # Should generate many tests

    def test_generate_comparison_tests(self):
        """Test generating comparison tests."""
        gen = ConformanceGenerator()
        gen.generate_comparison_tests()

        assert len(gen.tests) > 50

    def test_generate_boolean_tests(self):
        """Test generating boolean tests."""
        gen = ConformanceGenerator()
        gen.generate_boolean_tests()

        assert len(gen.tests) > 10

    def test_generate_list_tests(self):
        """Test generating list tests."""
        gen = ConformanceGenerator()
        gen.generate_list_tests()

        assert len(gen.tests) > 5

    def test_generate_dict_tests(self):
        """Test generating dict tests."""
        gen = ConformanceGenerator()
        gen.generate_dict_tests()

        assert len(gen.tests) > 5

    def test_generate_all(self):
        """Test generating all conformance tests."""
        gen = ConformanceGenerator()
        tests = gen.generate_all()

        assert len(tests) > 200

    def test_to_pytest_code(self):
        """Test generating pytest code."""
        gen = ConformanceGenerator()
        gen.add_expression_test("simple_add", "1 + 1")

        code = gen.to_pytest_code()

        assert "def test_simple_add" in code
        assert "assert result == 2" in code


class TestConformanceTest:
    """Tests for ConformanceTest dataclass."""

    def test_create_test(self):
        """Test creating conformance test."""
        test = ConformanceTest(
            name="test1",
            code="1 + 2",
            expected_result=3,
        )

        assert test.name == "test1"
        assert test.expected_result == 3

    def test_test_with_exception(self):
        """Test conformance test with expected exception."""
        test = ConformanceTest(
            name="test_error",
            code="1/0",
            expected_result=None,
            expected_exception=ZeroDivisionError,
        )

        assert test.expected_exception == ZeroDivisionError


# =============================================================================
# Integration Tests
# =============================================================================


class TestFuzzingIntegration:
    """Integration tests for fuzzing infrastructure."""

    @given(symbolic_integers(), symbolic_integers())
    @settings(max_examples=20)
    def test_symbolic_arithmetic(self, a, b):
        """Test arithmetic with symbolic values."""
        # Both should be SymbolicValue instances
        assert isinstance(a, SymbolicValue)
        assert isinstance(b, SymbolicValue)

    @given(z3_arithmetic_exprs(depth=1))
    @settings(max_examples=20)
    def test_z3_solver_integration(self, expr):
        """Test Z3 solver with generated expressions."""
        solver = z3.Solver()

        # Add constraint: expr > 0
        solver.add(expr > 0)

        # Should be able to check
        result = solver.check()
        assert result in (z3.sat, z3.unsat, z3.unknown)

    def test_conformance_execution(self):
        """Test that conformance tests execute correctly."""
        gen = ConformanceGenerator()
        gen.add_expression_test("simple", "2 * 3 + 4")

        test = gen.tests[0]

        # Execute the test
        result = eval(test.code)
        assert result == test.expected_result
