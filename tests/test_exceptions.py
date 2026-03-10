"""
Tests for Phase 18: Exception Modeling.

Tests symbolic exception handling, try/except/finally blocks,
@raises contracts, and exception flow analysis.
"""

import z3

from pysymex.core.exceptions import (
    # Registry
    BUILTIN_EXCEPTIONS,
    # Analyzer
    ExceptionAnalyzer,
    # Types and Categories
    ExceptionCategory,
    # Handlers and Blocks
    ExceptionHandler,
    # Exception Path and State
    ExceptionPath,
    ExceptionState,
    # Contracts
    RaisesContract,
    # Symbolic Exception
    SymbolicException,
    TryBlock,
    check_invariant_violation,
    check_postcondition_violation,
    check_precondition_violation,
    # Utilities
    create_exception_from_opcode,
    get_exception_category,
    get_exception_hierarchy,
    is_builtin_exception,
    merge_exception_states,
    propagate_exception,
    raises,
)

# =============================================================================
# Exception Category Tests
# =============================================================================


class TestExceptionCategory:
    """Tests for exception categorization."""

    def test_runtime_error_category(self):
        """RuntimeError has RUNTIME category."""
        cat = get_exception_category(RuntimeError)
        assert cat == ExceptionCategory.RUNTIME

    def test_type_error_category(self):
        """TypeError has TYPE category."""
        cat = get_exception_category(TypeError)
        assert cat == ExceptionCategory.TYPE

    def test_value_error_category(self):
        """ValueError has VALUE category."""
        cat = get_exception_category(ValueError)
        assert cat == ExceptionCategory.VALUE

    def test_key_error_category(self):
        """KeyError has LOOKUP category."""
        cat = get_exception_category(KeyError)
        assert cat == ExceptionCategory.LOOKUP

    def test_index_error_category(self):
        """IndexError has LOOKUP category."""
        cat = get_exception_category(IndexError)
        assert cat == ExceptionCategory.LOOKUP

    def test_zero_division_category(self):
        """ZeroDivisionError has ARITHMETIC category."""
        cat = get_exception_category(ZeroDivisionError)
        assert cat == ExceptionCategory.ARITHMETIC

    def test_attribute_error_category(self):
        """AttributeError has ATTRIBUTE category."""
        cat = get_exception_category(AttributeError)
        assert cat == ExceptionCategory.ATTRIBUTE

    def test_name_error_category(self):
        """NameError has NAME category."""
        cat = get_exception_category(NameError)
        assert cat == ExceptionCategory.NAME

    def test_io_error_category(self):
        """IOError has IO category."""
        cat = get_exception_category(IOError)
        assert cat == ExceptionCategory.IO

    def test_assertion_error_category(self):
        """AssertionError has ASSERTION category."""
        cat = get_exception_category(AssertionError)
        assert cat == ExceptionCategory.ASSERTION

    def test_stop_iteration_category(self):
        """StopIteration has STOP_ITERATION category."""
        cat = get_exception_category(StopIteration)
        assert cat == ExceptionCategory.STOP_ITERATION

    def test_custom_exception_category(self):
        """Custom exception has CUSTOM category."""

        class MyError(Exception):
            pass

        cat = get_exception_category(MyError)
        assert cat == ExceptionCategory.CUSTOM

    def test_derived_inherits_category(self):
        """Derived exceptions inherit parent category."""
        # FileNotFoundError is subclass of IOError
        cat = get_exception_category(FileNotFoundError)
        assert cat == ExceptionCategory.IO


# =============================================================================
# Symbolic Exception Tests
# =============================================================================


class TestSymbolicException:
    """Tests for SymbolicException class."""

    def test_concrete_exception(self):
        """Create concrete exception."""
        exc = SymbolicException.concrete(ValueError, "bad value", raised_at=10)
        assert exc.type_name == "ValueError"
        assert exc.message == "bad value"
        assert exc.raised_at == 10
        assert exc.is_unconditional()

    def test_symbolic_exception(self):
        """Create symbolic exception with condition."""
        cond = z3.Bool("x_negative")
        exc = SymbolicException.symbolic("exc1", ValueError, cond, raised_at=20)
        assert exc.type_name == "ValueError"
        assert exc.condition is cond
        assert not exc.is_unconditional()

    def test_exception_type_name_from_string(self):
        """Exception with string type name."""
        exc = SymbolicException(exc_type="CustomError")
        assert exc.type_name == "CustomError"

    def test_may_occur_sat(self):
        """Exception may occur when condition is satisfiable."""
        solver = z3.Solver()
        x = z3.Int("x")
        cond = x < 0
        exc = SymbolicException.symbolic("exc", ValueError, cond)

        assert exc.may_occur(solver)  # x < 0 is satisfiable

    def test_may_occur_unsat(self):
        """Exception cannot occur when condition is unsatisfiable."""
        solver = z3.Solver()
        x = z3.Int("x")
        solver.add(x > 0)  # x is positive
        cond = x < 0  # Exception when negative
        exc = SymbolicException.symbolic("exc", ValueError, cond)

        assert not exc.may_occur(solver)

    def test_must_occur(self):
        """Exception must occur when negation is unsatisfiable."""
        solver = z3.Solver()
        x = z3.Int("x")
        solver.add(x < 0)  # x is negative
        cond = x < 0  # Exception when negative
        exc = SymbolicException.symbolic("exc", ValueError, cond)

        assert exc.must_occur(solver)

    def test_exception_str(self):
        """String representation."""
        exc = SymbolicException.concrete(ValueError, "test msg")
        assert "ValueError" in str(exc)
        assert "test msg" in str(exc)


# =============================================================================
# Exception Handler Tests
# =============================================================================


class TestExceptionHandler:
    """Tests for ExceptionHandler class."""

    def test_catches_matching_type(self):
        """Handler catches matching exception type."""
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        exc = SymbolicException.concrete(ValueError, "test")
        assert handler.catches(exc)

    def test_catches_subclass(self):
        """Handler catches subclass exceptions."""
        handler = ExceptionHandler(exc_types=(LookupError,), target_pc=100)
        exc = SymbolicException.concrete(KeyError, "key")
        assert handler.catches(exc)

    def test_not_catches_unrelated(self):
        """Handler doesn't catch unrelated exceptions."""
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        exc = SymbolicException.concrete(TypeError, "type")
        assert not handler.catches(exc)

    def test_bare_except_catches_all(self):
        """Bare except catches all exceptions."""
        handler = ExceptionHandler(exc_types=None, target_pc=100)
        exc = SymbolicException.concrete(RuntimeError, "any")
        assert handler.catches(exc)

    def test_multiple_types(self):
        """Handler with multiple exception types."""
        handler = ExceptionHandler(exc_types=(ValueError, TypeError), target_pc=100)
        assert handler.catches(SymbolicException.concrete(ValueError, "val"))
        assert handler.catches(SymbolicException.concrete(TypeError, "type"))
        assert not handler.catches(SymbolicException.concrete(KeyError, "key"))

    def test_catches_type_directly(self):
        """Test catches_type method."""
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        assert handler.catches_type(ValueError)
        assert not handler.catches_type(TypeError)


# =============================================================================
# Try Block Tests
# =============================================================================


class TestTryBlock:
    """Tests for TryBlock class."""

    def test_in_try_block(self):
        """Check if PC is in try block."""
        block = TryBlock(try_start=10, try_end=50)
        assert block.in_try_block(10)
        assert block.in_try_block(30)
        assert not block.in_try_block(50)
        assert not block.in_try_block(5)

    def test_find_handler_match(self):
        """Find matching handler."""
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        block = TryBlock(try_start=10, try_end=50, handlers=[handler])

        exc = SymbolicException.concrete(ValueError, "test")
        found = block.find_handler(exc)
        assert found is handler

    def test_find_handler_no_match(self):
        """No matching handler."""
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        block = TryBlock(try_start=10, try_end=50, handlers=[handler])

        exc = SymbolicException.concrete(TypeError, "test")
        found = block.find_handler(exc)
        assert found is None

    def test_find_handler_first_match(self):
        """First matching handler is returned."""
        handler1 = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        handler2 = ExceptionHandler(exc_types=(Exception,), target_pc=200)
        block = TryBlock(try_start=10, try_end=50, handlers=[handler1, handler2])

        exc = SymbolicException.concrete(ValueError, "test")
        found = block.find_handler(exc)
        assert found is handler1


# =============================================================================
# Exception Path Tests
# =============================================================================


class TestExceptionPath:
    """Tests for ExceptionPath class."""

    def test_create_path(self):
        """Create exception path."""
        exc = SymbolicException.concrete(ValueError, "test")
        path = ExceptionPath(exception=exc)
        assert path.exception is exc
        assert not path.propagated
        assert path.caught_by is None

    def test_add_condition(self):
        """Add path condition."""
        exc = SymbolicException.concrete(ValueError, "test")
        path = ExceptionPath(exception=exc)

        cond = z3.Bool("cond")
        path.add_condition(cond)
        # Should be conjunction of True and cond

    def test_mark_caught(self):
        """Mark exception as caught."""
        exc = SymbolicException.concrete(ValueError, "test")
        path = ExceptionPath(exception=exc)
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)

        path.mark_caught(handler)
        assert path.caught_by is handler
        assert not path.propagated

    def test_mark_propagated(self):
        """Mark exception as propagated."""
        exc = SymbolicException.concrete(ValueError, "test")
        path = ExceptionPath(exception=exc)

        path.mark_propagated()
        assert path.propagated


# =============================================================================
# Exception State Tests
# =============================================================================


class TestExceptionState:
    """Tests for ExceptionState class."""

    def test_push_pop_try(self):
        """Push and pop try blocks."""
        state = ExceptionState()
        block = TryBlock(try_start=10, try_end=50)

        state.push_try(block)
        assert state.current_try() is block

        popped = state.pop_try()
        assert popped is block
        assert state.current_try() is None

    def test_nested_try_blocks(self):
        """Nested try blocks maintain order."""
        state = ExceptionState()
        block1 = TryBlock(try_start=10, try_end=100)
        block2 = TryBlock(try_start=20, try_end=50)

        state.push_try(block1)
        state.push_try(block2)

        assert state.current_try() is block2
        state.pop_try()
        assert state.current_try() is block1

    def test_raise_exception(self):
        """Raise exception creates path."""
        state = ExceptionState()
        exc = SymbolicException.concrete(ValueError, "test", raised_at=30)

        path = state.raise_exception(exc)
        assert state.current_exception is exc
        assert path in state.exception_paths

    def test_handle_exception_found(self):
        """Handle exception finds handler."""
        state = ExceptionState()
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        block = TryBlock(try_start=10, try_end=50, handlers=[handler])
        state.push_try(block)

        exc = SymbolicException.concrete(ValueError, "test", raised_at=30)
        found_handler, target_pc = state.handle_exception(exc)

        assert found_handler is handler
        assert target_pc == 100

    def test_handle_exception_not_found(self):
        """Handle exception with no matching handler."""
        state = ExceptionState()
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        block = TryBlock(try_start=10, try_end=50, handlers=[handler])
        state.push_try(block)

        exc = SymbolicException.concrete(TypeError, "test", raised_at=30)
        found_handler, target_pc = state.handle_exception(exc)

        assert found_handler is None
        assert target_pc is None

    def test_clear_exception(self):
        """Clear current exception."""
        state = ExceptionState()
        exc = SymbolicException.concrete(ValueError, "test")
        state.raise_exception(exc)

        state.clear_exception()
        assert state.current_exception is None

    def test_suppress_exception(self):
        """Suppress exception."""
        state = ExceptionState()
        exc = SymbolicException.concrete(ValueError, "test")
        state.raise_exception(exc)

        state.suppress(exc)
        assert exc in state.suppressed
        assert state.current_exception is None

    def test_clone_state(self):
        """Clone exception state."""
        state = ExceptionState()
        block = TryBlock(try_start=10, try_end=50)
        state.push_try(block)
        exc = SymbolicException.concrete(ValueError, "test")
        state.raise_exception(exc)

        cloned = state.clone()
        assert len(cloned.try_stack) == 1
        assert cloned.current_exception is exc

        # Modifications don't affect original
        cloned.pop_try()
        assert len(state.try_stack) == 1


# =============================================================================
# Raises Contract Tests
# =============================================================================


class TestRaisesContract:
    """Tests for RaisesContract class."""

    def test_contract_matches_type(self):
        """Contract matches exception type."""
        contract = RaisesContract(exc_type=ValueError)
        exc = SymbolicException.concrete(ValueError, "test")
        assert contract.matches(exc)

    def test_contract_not_matches_different_type(self):
        """Contract doesn't match different type."""
        contract = RaisesContract(exc_type=ValueError)
        exc = SymbolicException.concrete(TypeError, "test")
        assert not contract.matches(exc)

    def test_contract_matches_subclass(self):
        """Contract matches subclass."""
        contract = RaisesContract(exc_type=LookupError)
        exc = SymbolicException.concrete(KeyError, "key")
        assert contract.matches(exc)

    def test_contract_with_message(self):
        """Contract with message pattern."""
        contract = RaisesContract(exc_type=ValueError, message="negative")
        exc_match = SymbolicException.concrete(ValueError, "negative number")
        exc_no_match = SymbolicException.concrete(ValueError, "too large")

        assert contract.matches(exc_match)
        assert not contract.matches(exc_no_match)

    def test_contract_type_name(self):
        """Contract type_name property."""
        contract1 = RaisesContract(exc_type=ValueError)
        assert contract1.type_name == "ValueError"

        contract2 = RaisesContract(exc_type="CustomError")
        assert contract2.type_name == "CustomError"


class TestRaisesDecorator:
    """Tests for @raises decorator."""

    def test_raises_decorator(self):
        """Apply @raises decorator."""

        @raises(ValueError, when="x < 0")
        def sqrt(x):
            if x < 0:
                raise ValueError("negative")
            return x**0.5

        assert hasattr(sqrt, "__raises__")
        assert len(sqrt.__raises__) == 1  # type: ignore[reportFunctionMemberAccess]
        assert sqrt.__raises__[0].exc_type is ValueError  # type: ignore[reportFunctionMemberAccess]
        assert sqrt.__raises__[0].condition == "x < 0"  # type: ignore[reportFunctionMemberAccess]

    def test_multiple_raises(self):
        """Multiple @raises decorators."""

        @raises(ValueError, when="x < 0")
        @raises(TypeError, when="not isinstance(x, (int, float))")
        def sqrt(x):
            pass

        assert len(sqrt.__raises__) == 2  # type: ignore[reportFunctionMemberAccess]


# =============================================================================
# Exception Analyzer Tests
# =============================================================================


class TestExceptionAnalyzer:
    """Tests for ExceptionAnalyzer class."""

    def test_add_potential_exception(self):
        """Add potential exception."""
        analyzer = ExceptionAnalyzer()
        exc = SymbolicException.concrete(ValueError, "test")
        analyzer.add_potential_exception(exc)

        assert exc in analyzer.get_potential_exceptions()

    def test_get_exceptions_of_type(self):
        """Get exceptions of specific type."""
        analyzer = ExceptionAnalyzer()
        analyzer.add_potential_exception(SymbolicException.concrete(ValueError, "val"))
        analyzer.add_potential_exception(SymbolicException.concrete(TypeError, "type"))
        analyzer.add_potential_exception(SymbolicException.concrete(KeyError, "key"))

        value_errors = analyzer.get_exceptions_of_type(ValueError)
        assert len(value_errors) == 1

        lookup_errors = analyzer.get_exceptions_of_type(LookupError)
        assert len(lookup_errors) == 1  # KeyError is LookupError

    def test_analyze_division_concrete_zero(self):
        """Analyze division by concrete zero."""
        analyzer = ExceptionAnalyzer()
        exc = analyzer.analyze_division(0, pc=10)

        assert exc is not None
        assert exc.type_name == "ZeroDivisionError"
        assert exc.is_unconditional()

    def test_analyze_division_concrete_nonzero(self):
        """Analyze division by concrete nonzero."""
        analyzer = ExceptionAnalyzer()
        exc = analyzer.analyze_division(5, pc=10)

        assert exc is None

    def test_analyze_assertion_false(self):
        """Analyze assertion with False condition."""
        analyzer = ExceptionAnalyzer()
        exc = analyzer.analyze_assertion(False, "test failed", pc=10)

        assert exc is not None
        assert exc.type_name == "AssertionError"
        assert exc.is_unconditional()

    def test_analyze_assertion_true(self):
        """Analyze assertion with True condition."""
        analyzer = ExceptionAnalyzer()
        exc = analyzer.analyze_assertion(True, "test passed", pc=10)

        assert exc is None

    def test_check_unhandled_exceptions(self):
        """Check for unhandled exceptions."""
        analyzer = ExceptionAnalyzer()
        state = ExceptionState()

        exc = SymbolicException.concrete(ValueError, "test")
        path = state.raise_exception(exc)
        path.mark_propagated()

        unhandled = analyzer.check_unhandled_exceptions(state)
        assert len(unhandled) == 1
        assert unhandled[0] is exc

    def test_verify_raises_contract_satisfied(self):
        """Verify raises contract is satisfied."""
        analyzer = ExceptionAnalyzer()
        analyzer.add_potential_exception(SymbolicException.concrete(ValueError, "negative"))

        contract = RaisesContract(exc_type=ValueError)
        satisfied, error = analyzer.verify_raises_contract(contract)

        assert satisfied
        assert error is None

    def test_verify_raises_contract_not_satisfied(self):
        """Verify raises contract is not satisfied."""
        analyzer = ExceptionAnalyzer()
        analyzer.add_potential_exception(SymbolicException.concrete(TypeError, "type"))

        contract = RaisesContract(exc_type=ValueError)
        satisfied, error = analyzer.verify_raises_contract(contract)

        assert not satisfied
        assert "ValueError" in error  # type: ignore[reportOperatorIssue]


# =============================================================================
# Utility Function Tests
# =============================================================================


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_create_exception_from_opcode(self):
        """Create exception from opcode."""
        exc = create_exception_from_opcode(ValueError, ("bad",), pc=10)
        assert exc.type_name == "ValueError"
        assert exc.args == ("bad",)
        assert exc.raised_at == 10

    def test_propagate_exception_caught(self):
        """Propagate exception that gets caught."""
        state = ExceptionState()
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        block = TryBlock(try_start=10, try_end=50, handlers=[handler])
        state.push_try(block)

        exc = SymbolicException.concrete(ValueError, "test")
        handled, target_pc = propagate_exception(state, exc)

        assert handled
        assert target_pc == 100

    def test_propagate_exception_not_caught(self):
        """Propagate exception that isn't caught."""
        state = ExceptionState()

        exc = SymbolicException.concrete(ValueError, "test")
        handled, target_pc = propagate_exception(state, exc)

        assert not handled
        assert target_pc is None

    def test_merge_exception_states(self):
        """Merge multiple exception states."""
        state1 = ExceptionState()
        state1.raise_exception(SymbolicException.concrete(ValueError, "val"))

        state2 = ExceptionState()
        state2.raise_exception(SymbolicException.concrete(TypeError, "type"))

        merged = merge_exception_states([state1, state2])
        assert len(merged.exception_paths) == 2

    def test_check_precondition_violation(self):
        """Create precondition violation exception."""
        cond = z3.Bool("valid")
        exc = check_precondition_violation(cond, "must be valid", pc=10)

        assert exc is not None
        assert exc.type_name == "AssertionError"
        # Condition should be Not(cond) - violation when cond is false

    def test_check_postcondition_violation(self):
        """Create postcondition violation exception."""
        cond = z3.Bool("result_valid")
        exc = check_postcondition_violation(cond, "result must be valid", pc=20)

        assert exc is not None
        assert exc.type_name == "AssertionError"

    def test_check_invariant_violation(self):
        """Create invariant violation exception."""
        cond = z3.Bool("invariant")
        exc = check_invariant_violation(cond, "invariant broken", pc=30)

        assert exc is not None
        assert exc.type_name == "AssertionError"


# =============================================================================
# Registry Tests
# =============================================================================


class TestExceptionRegistry:
    """Tests for exception registry."""

    def test_builtin_exceptions_contains_common(self):
        """BUILTIN_EXCEPTIONS contains common exceptions."""
        assert ValueError in BUILTIN_EXCEPTIONS
        assert TypeError in BUILTIN_EXCEPTIONS
        assert KeyError in BUILTIN_EXCEPTIONS
        assert IndexError in BUILTIN_EXCEPTIONS
        assert ZeroDivisionError in BUILTIN_EXCEPTIONS

    def test_is_builtin_exception_true(self):
        """is_builtin_exception returns True for builtins."""
        assert is_builtin_exception(ValueError)
        assert is_builtin_exception(Exception)
        assert is_builtin_exception(BaseException)

    def test_is_builtin_exception_false(self):
        """is_builtin_exception returns False for custom."""

        class MyError(Exception):
            pass

        assert not is_builtin_exception(MyError)

    def test_get_exception_hierarchy(self):
        """Get exception hierarchy."""
        hierarchy = get_exception_hierarchy(ValueError)
        assert ValueError in hierarchy
        assert Exception in hierarchy
        assert BaseException in hierarchy


# =============================================================================
# Integration Tests
# =============================================================================


class TestExceptionIntegration:
    """Integration tests for exception handling."""

    def test_try_except_flow(self):
        """Test complete try/except flow."""
        state = ExceptionState()

        # Enter try block
        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        block = TryBlock(try_start=10, try_end=50, handlers=[handler])
        state.push_try(block)

        # Raise exception inside try
        exc = SymbolicException.concrete(ValueError, "test", raised_at=30)
        path = state.raise_exception(exc)

        # Find handler
        found, target = state.handle_exception(exc)
        assert found is handler
        assert target == 100

        # Mark caught
        path.mark_caught(handler)
        state.clear_exception()

        # Pop try block
        state.pop_try()

        assert state.current_exception is None
        assert len(state.exception_paths) == 1
        assert state.exception_paths[0].caught_by is handler

    def test_nested_exception_handling(self):
        """Test nested try/except blocks."""
        state = ExceptionState()

        # Outer try catches Exception
        outer_handler = ExceptionHandler(exc_types=(Exception,), target_pc=200)
        outer_block = TryBlock(try_start=10, try_end=100, handlers=[outer_handler])
        state.push_try(outer_block)

        # Inner try catches ValueError
        inner_handler = ExceptionHandler(exc_types=(ValueError,), target_pc=100)
        inner_block = TryBlock(try_start=20, try_end=50, handlers=[inner_handler])
        state.push_try(inner_block)

        # Raise TypeError (not caught by inner, caught by outer)
        exc = SymbolicException.concrete(TypeError, "test", raised_at=30)

        found, target = state.handle_exception(exc)
        # Should find outer handler (traverses stack in reverse)
        assert found is outer_handler
        assert target == 200

    def test_exception_propagation_chain(self):
        """Test exception propagates through multiple blocks."""
        analyzer = ExceptionAnalyzer()
        state = ExceptionState()

        # Try block that doesn't catch ValueError
        handler = ExceptionHandler(exc_types=(TypeError,), target_pc=100)
        block = TryBlock(try_start=10, try_end=50, handlers=[handler])
        state.push_try(block)

        # Raise ValueError
        exc = SymbolicException.concrete(ValueError, "test", raised_at=30)
        path = state.raise_exception(exc)

        # Try to handle - should fail
        found, target = state.handle_exception(exc)
        assert found is None

        # Mark as propagated
        path.mark_propagated()

        # Analyzer should detect unhandled
        unhandled = analyzer.check_unhandled_exceptions(state)
        assert len(unhandled) == 1

    def test_symbolic_exception_with_solver(self):
        """Test symbolic exception with Z3 solver."""
        solver = z3.Solver()
        x = z3.Int("x")

        # x can be any value
        # Exception occurs when x < 0
        exc = SymbolicException.symbolic(
            "div_check",
            ValueError,
            x < 0,
            raised_at=10,
        )

        # Without constraints, exception may occur
        assert exc.may_occur(solver)

        # With x > 0, exception cannot occur
        solver.add(x > 0)
        assert not exc.may_occur(solver)

        # Reset and test must_occur
        solver.reset()
        solver.add(x < 0)
        assert exc.must_occur(solver)

    def test_raises_contract_with_analyzer(self):
        """Test @raises contract verification."""

        @raises(ValueError, when="x < 0")
        def sqrt(x):
            if x < 0:
                raise ValueError("negative")
            return x**0.5

        analyzer = ExceptionAnalyzer()

        # Simulate raising ValueError
        x = z3.Int("x")
        exc = SymbolicException.symbolic(
            "sqrt_exc",
            ValueError,
            x < 0,
            raised_at=10,
        )
        analyzer.add_potential_exception(exc)

        # Verify contract
        contract = sqrt.__raises__[0]  # type: ignore[reportFunctionMemberAccess]
        satisfied, error = analyzer.verify_raises_contract(contract)
        assert satisfied
