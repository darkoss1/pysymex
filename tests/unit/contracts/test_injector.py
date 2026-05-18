from __future__ import annotations

import z3

from pysymex.contracts.injector import (
    inject_preconditions_initial,
    inject_postconditions,
    inject_call_preconditions,
)
from pysymex.core.state import create_initial_state
from pysymex.contracts.decorators import requires, ensures
from pysymex.analysis.detectors import IssueKind


class MockStackValue:
    """Mock stack value with z3_int property for testing."""

    def __init__(self, val: z3.ExprRef) -> None:
        self.z3_int = val


class TestInjector:
    """Test suite for contracts/injector.py."""

    def test_inject_preconditions_initial_no_contract(self) -> None:
        """Verify inject_preconditions_initial returns unmodified state if no contract."""
        state = create_initial_state()

        def my_func() -> None:
            pass

        new_state = inject_preconditions_initial(state, my_func)
        assert new_state is state

    def test_inject_preconditions_initial_with_contract(self) -> None:
        """Verify inject_preconditions_initial injects precondition constraints."""
        x = z3.Int("x")
        state = create_initial_state(local_vars={"x": MockStackValue(x)})  # type: ignore

        @requires("x > 0")
        def my_func(x: int) -> None:
            pass

        new_state = inject_preconditions_initial(state, my_func)
        assert len(new_state.path_constraints) == 1

    def test_inject_postconditions_no_contract(self) -> None:
        """Verify inject_postconditions returns None if no contract."""
        state = create_initial_state()

        def my_func() -> None:
            pass

        issue = inject_postconditions(state, my_func, None, None)
        assert issue is None

    def test_inject_postconditions_violated(self) -> None:
        """Verify inject_postconditions returns Issue if postcondition is violated."""
        # path constraint is empty, we assert postcondition returns > 0, but return value is 0.
        # This means Not(return > 0) is SAT.
        state = create_initial_state()
        ret_val = MockStackValue(z3.IntVal(0))

        @ensures("__result__ > 0")
        def my_func() -> int:
            return 0

        issue = inject_postconditions(state, my_func, ret_val, None)  # type: ignore
        assert issue is not None
        assert "may be violated" in issue.message

    def test_inject_postconditions_holds(self) -> None:
        """Verify inject_postconditions returns None if postcondition holds."""
        # state constraint x == 1, postcondition __return__ == x.
        # Wait, if we use a mock return value that is a fresh variable, we need path constraints.
        # Let's just use z3.IntVal(1) as return value.
        state = create_initial_state()
        ret_val = MockStackValue(z3.IntVal(1))
        # Add return value to local_vars so __result__ symbol can be resolved
        state.local_vars["__result__"] = ret_val  # type: ignore
        # Add constraint using the actual z3 value from ret_val
        state = state.add_constraint(ret_val.z3_int > 0)  # type: ignore

        @ensures("__result__ > 0")
        def my_func() -> int:
            return 1

        issue = inject_postconditions(state, my_func, ret_val, None)  # type: ignore
        assert issue is None

    def test_inject_postconditions_uses_path_constraints(self) -> None:
        """Postconditions are checked against the current feasible return path."""
        x = z3.Int("x")
        state = create_initial_state()
        state = state.add_constraint(x > 0)
        ret_val = MockStackValue(x)

        @ensures("__result__ > 0")
        def my_func(x: int) -> int:
            return x

        issue = inject_postconditions(state, my_func, ret_val, None)  # type: ignore[arg-type]
        assert issue is None

    def test_inject_postconditions_compile_failure_is_unknown(self) -> None:
        """Unsupported postconditions are visible as unknown, not silently verified."""
        state = create_initial_state()
        ret_val = MockStackValue(z3.IntVal(1))

        def unsupported(__result__: z3.ArithRef) -> object:
            _ = __result__
            return object()

        @ensures(unsupported)  # type: ignore[arg-type]  # invalid predicate exercises UNKNOWN path
        def my_func() -> int:
            return 1

        issue = inject_postconditions(state, my_func, ret_val, None)  # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind is IssueKind.UNKNOWN
        assert "could not be checked" in issue.message

    def test_inject_call_preconditions_no_contract(self) -> None:
        """Verify inject_call_preconditions returns None if no contract."""
        state = create_initial_state()

        def my_func() -> None:
            pass

        issue = inject_call_preconditions(state, my_func, [], {})
        assert issue is None

    def test_inject_call_preconditions_violated(self) -> None:
        """Verify inject_call_preconditions returns Issue if precondition is violated."""
        state = create_initial_state()
        x_val = MockStackValue(z3.IntVal(0))

        @requires("x > 0")
        def my_func(x: int) -> None:
            pass

        issue = inject_call_preconditions(state, my_func, [x_val], {})
        assert issue is not None
        assert "may be violated" in issue.message

    def test_inject_call_preconditions_holds(self) -> None:
        """Verify inject_call_preconditions returns None if precondition holds."""
        state = create_initial_state()
        x_val = MockStackValue(z3.IntVal(1))

        @requires("x > 0")
        def my_func(x: int) -> None:
            pass

        issue = inject_call_preconditions(state, my_func, [x_val], {})
        assert issue is None

    def test_inject_call_preconditions_compile_failure_is_unknown(self) -> None:
        """Unsupported call preconditions are visible as unknown."""
        state = create_initial_state()
        x_val = MockStackValue(z3.IntVal(1))

        def unsupported(x: z3.ArithRef) -> object:
            _ = x
            return object()

        @requires(unsupported)  # type: ignore[arg-type]  # invalid predicate exercises UNKNOWN path
        def my_func(x: int) -> None:
            pass

        issue = inject_call_preconditions(state, my_func, [x_val], {})
        assert issue is not None
        assert issue.kind is IssueKind.UNKNOWN
        assert "could not be checked" in issue.message
