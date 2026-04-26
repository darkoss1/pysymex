import pysymex.core.exceptions.analyzer
import pysymex.core.exceptions.types
import z3


class TestExceptionAnalyzer:
    """Test suite for pysymex.core.exceptions.analyzer.ExceptionAnalyzer."""

    def test_add_potential_exception(self) -> None:
        """Scenario: add potential exception; expected list contains it."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        analyzer.add_potential_exception(exc)
        assert analyzer.get_potential_exceptions() == [exc]

    def test_get_potential_exceptions(self) -> None:
        """Scenario: no exceptions added; expected empty list."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        assert analyzer.get_potential_exceptions() == []

    def test_get_exceptions_of_type(self) -> None:
        """Scenario: filter by ValueError type; expected matching exception returned."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        analyzer.add_potential_exception(exc)
        assert analyzer.get_exceptions_of_type(ValueError) == [exc]

    def test_verify_raises_contract(self) -> None:
        """Scenario: matching potential exception and contract; expected satisfied result."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        analyzer.add_potential_exception(
            pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        )
        ok, message = analyzer.verify_raises_contract(
            pysymex.core.exceptions.types.RaisesContract(ValueError)
        )
        assert (ok, message) == (True, None)

    def test_check_unhandled_exceptions(self) -> None:
        """Scenario: one propagated exception path; expected one unhandled exception."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        state = pysymex.core.exceptions.types.ExceptionState()
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        path = state.raise_exception(exc)
        path.mark_propagated()
        assert analyzer.check_unhandled_exceptions(state) == [exc]

    def test_analyze_division(self) -> None:
        """Scenario: concrete divisor zero; expected concrete ZeroDivisionError exception."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        exc = analyzer.analyze_division(0, pc=1)
        assert exc is not None and exc.type_name == "ZeroDivisionError"

    def test_analyze_index_access(self) -> None:
        """Scenario: index access with unknown object shape; expected no synthesized exception."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        assert analyzer.analyze_index_access(object(), 0, pc=1) is None

    def test_analyze_key_access(self) -> None:
        """Scenario: key access without known container semantics; expected symbolic KeyError."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        exc = analyzer.analyze_key_access({}, "k", pc=2)
        assert exc is not None and exc.type_name == "KeyError"

    def test_analyze_attribute_access(self) -> None:
        """Scenario: attribute access on None; expected concrete AttributeError."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        exc = analyzer.analyze_attribute_access(None, "x", pc=2)
        assert exc is not None and exc.type_name == "AttributeError"

    def test_analyze_assertion(self) -> None:
        """Scenario: false assertion condition; expected concrete AssertionError."""
        analyzer = pysymex.core.exceptions.analyzer.ExceptionAnalyzer()
        exc = analyzer.analyze_assertion(False, "boom", pc=3)
        assert exc is not None and exc.type_name == "AssertionError"


def test_create_exception_from_opcode() -> None:
    """Scenario: create from opcode helper; expected provided type reflected in result."""
    exc = pysymex.core.exceptions.analyzer.create_exception_from_opcode(ValueError, ("x",), pc=4)
    assert exc.type_name == "ValueError"


def test_propagate_exception() -> None:
    """Scenario: no handlers available; expected exception not handled."""
    state = pysymex.core.exceptions.types.ExceptionState()
    handled, target = pysymex.core.exceptions.analyzer.propagate_exception(
        state, pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
    )
    assert (handled, target) == (False, None)


def test_merge_exception_states() -> None:
    """Scenario: merge empty list; expected fresh empty ExceptionState."""
    merged = pysymex.core.exceptions.analyzer.merge_exception_states([])
    assert isinstance(merged, pysymex.core.exceptions.types.ExceptionState)


def test_check_precondition_violation() -> None:
    """Scenario: precondition helper; expected symbolic AssertionError result."""
    exc = pysymex.core.exceptions.analyzer.check_precondition_violation(z3.Bool("c"), "m", pc=1)
    assert exc is not None and exc.type_name == "AssertionError"


def test_check_postcondition_violation() -> None:
    """Scenario: postcondition helper; expected symbolic AssertionError result."""
    exc = pysymex.core.exceptions.analyzer.check_postcondition_violation(z3.Bool("c"), "m", pc=1)
    assert exc is not None and exc.type_name == "AssertionError"


def test_check_invariant_violation() -> None:
    """Scenario: invariant helper; expected symbolic AssertionError result."""
    exc = pysymex.core.exceptions.analyzer.check_invariant_violation(z3.Bool("c"), "m", pc=1)
    assert exc is not None and exc.type_name == "AssertionError"


def test_is_builtin_exception() -> None:
    """Scenario: built-in exception lookup for ValueError; expected true."""
    assert pysymex.core.exceptions.analyzer.is_builtin_exception(ValueError) is True


def test_get_exception_hierarchy() -> None:
    """Scenario: hierarchy for ValueError; expected ValueError present in list."""
    assert ValueError in pysymex.core.exceptions.analyzer.get_exception_hierarchy(ValueError)
