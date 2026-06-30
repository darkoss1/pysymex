from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
import z3

from pysymex._internal.contracts.binding.snapshots import runtime_contract_frame
from pysymex._internal.contracts.decorators import assumes, ensures, requires
from pysymex._internal.contracts.runtime.calls import inject_call_preconditions
from pysymex._internal.contracts.runtime.entry import inject_preconditions_initial
from pysymex._internal.contracts.runtime.returns import inject_postconditions
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


def create_initial_state(local_vars: dict[str, StackValue] | None = None) -> VMState:
    """Create the minimal root state needed by contract runtime tests."""
    return VMState(local_vars=local_vars, global_vars={"__name__": "__main__"})


class MockStackValue:
    """Mock stack value with z3_int property for testing."""

    def __init__(self, val: z3.ExprRef) -> None:
        self.z3_int = val


class TestRuntimeHooks:
    """Test suite for contract runtime hook behavior."""

    def test_inject_preconditions_initial_no_contract(self) -> None:
        """Verify inject_preconditions_initial returns unmodified state if no contract."""
        state = create_initial_state()

        def my_func() -> None:
            pass

        new_state, issues, postconditions_supported = inject_preconditions_initial(state, my_func)
        assert new_state is state
        assert issues == []
        assert postconditions_supported is True

    def test_inject_preconditions_initial_with_contract(self) -> None:
        """Verify inject_preconditions_initial injects precondition constraints."""
        x = z3.Int("x")
        state = create_initial_state(local_vars={"x": MockStackValue(x)})  # type: ignore

        @requires("x > 0")
        def my_func(x: int) -> None:
            pass

        new_state, issues, postconditions_supported = inject_preconditions_initial(state, my_func)
        assert len(new_state.path_constraints) == 1
        assert issues == []
        assert postconditions_supported is True

    def test_inject_preconditions_initial_compile_failure_is_visible(self) -> None:
        """Unsupported entry preconditions produce unknown evidence."""
        state = create_initial_state()

        @requires("mystery(x) > 0")
        def my_func(x: int) -> None:
            pass

        _new_state, issues, postconditions_supported = inject_preconditions_initial(state, my_func)
        assert len(issues) == 1
        assert issues[0].kind is IssueKind.UNKNOWN
        assert "could not be checked" in issues[0].message
        assert postconditions_supported is False

    def test_inject_initial_assumption_compile_failure_is_visible(self) -> None:
        """An unmodeled assumption cannot silently narrow verification."""
        state = create_initial_state()

        @assumes("mystery(x) > 0")
        def my_func(x: int) -> None:
            pass

        _new_state, issues, postconditions_supported = inject_preconditions_initial(state, my_func)
        assert len(issues) == 1
        assert issues[0].kind is IssueKind.UNKNOWN
        assert "could not be modeled" in issues[0].message
        assert postconditions_supported is False

    def test_unexpected_entry_injection_failure_is_not_classified_as_unsupported(self) -> None:
        state = create_initial_state()

        @requires("x > 0")
        def my_func(x: int) -> None:
            pass

        with patch(
            "pysymex._internal.contracts.types.Contract.compile",
            side_effect=RuntimeError("internal failure"),
        ):
            with pytest.raises(RuntimeError, match="internal failure"):
                inject_preconditions_initial(state, my_func)

    def test_inject_postconditions_no_contract(self) -> None:
        """Verify inject_postconditions returns None if no contract."""
        state = create_initial_state()

        def my_func() -> None:
            pass

        issues = inject_postconditions(state, my_func, None, None)
        assert issues == []

    def test_inject_postconditions_violated(self) -> None:
        """Verify inject_postconditions returns Issue if postcondition is violated."""
        # path constraint is empty, we assert postcondition returns > 0, but return value is 0.
        # This means Not(return > 0) is SAT.
        state = create_initial_state()
        ret_val = MockStackValue(z3.IntVal(0))

        @ensures("__result__ > 0")
        def my_func() -> int:
            return 0

        issues = inject_postconditions(state, my_func, ret_val, None)  # type: ignore
        assert len(issues) == 1
        issue = issues[0]
        assert issue is not None
        assert "may be violated" in issue.message

    def test_inject_postconditions_reports_multiple_violations(self) -> None:
        """Every violated postcondition remains a distinct result."""
        state = create_initial_state()
        ret_val = MockStackValue(z3.IntVal(0))

        @ensures("__result__ > 10")
        @ensures("__result__ < -10")
        def my_func() -> int:
            return 0

        issues = inject_postconditions(state, my_func, ret_val, None)  # type: ignore[arg-type]

        assert len(issues) == 2
        assert all(issue.kind is IssueKind.CONTRACT_VIOLATION for issue in issues)
        assert any("__result__ > 10" in issue.message for issue in issues)
        assert any("__result__ < -10" in issue.message for issue in issues)

    def test_inject_postconditions_preserves_unsupported_alongside_violation(self) -> None:
        """An unsupported clause cannot be folded into a definite violation."""
        state = create_initial_state()
        ret_val = MockStackValue(z3.IntVal(0))

        def unsupported(__result__: z3.ArithRef) -> object:
            return object()

        @ensures(unsupported)  # type: ignore[arg-type]
        @ensures("__result__ > 10")
        def my_func() -> int:
            return 0

        issues = inject_postconditions(state, my_func, ret_val, None)  # type: ignore[arg-type]

        assert [issue.kind for issue in issues] == [
            IssueKind.CONTRACT_VIOLATION,
            IssueKind.UNKNOWN,
        ]

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

        issues = inject_postconditions(state, my_func, ret_val, None)  # type: ignore
        assert issues == []

    def test_inject_postconditions_uses_path_constraints(self) -> None:
        """Postconditions are checked against the current feasible return path."""
        x = z3.Int("x")
        state = create_initial_state()
        state = state.add_constraint(x > 0)
        ret_val = MockStackValue(x)

        @ensures("__result__ > 0")
        def my_func(x: int) -> int:
            return x

        issues = inject_postconditions(state, my_func, ret_val, None)  # type: ignore[arg-type]
        assert issues == []

    def test_inject_postconditions_supports_shallow_old_attribute_snapshot(self) -> None:
        """Shallow scalar attributes can be compared against entry snapshots."""
        balance = z3.Int("balance")
        receiver = SymbolicObject("self", 1, z3.IntVal(1), {1})
        state = create_initial_state(local_vars={"self": receiver})
        state = state.store_heap(1, {"balance": balance})

        @ensures("self.balance == old(self.balance) + 1")
        def my_func(self: object) -> int:
            return 0

        frame = runtime_contract_frame(my_func, dict(state.local_vars.items()), state.memory)
        state = state.store_heap(1, {"balance": balance + 1})

        issues = inject_postconditions(
            state,
            my_func,
            MockStackValue(z3.IntVal(0)),
            None,
            old_symbols=frame.old_symbols,
        )
        assert issues == []

    def test_inject_postconditions_supports_old_collection_length_snapshot(self) -> None:
        """Modeled collection lengths can be compared to entry lengths."""
        items = SymbolicObject("xs", 1, z3.IntVal(1), {1})
        state = create_initial_state(local_vars={"xs": items})
        state = state.store_heap(1, SymbolicList.empty("xs"))

        @ensures("len(result()) == old(len(xs))")
        def my_func(xs: list[int]) -> list[int]:
            return xs

        frame = runtime_contract_frame(my_func, dict(state.local_vars.items()), state.memory)

        issues = inject_postconditions(
            state,
            my_func,
            SymbolicList.empty("result"),
            None,
            old_symbols=frame.old_symbols,
        )
        assert issues == []

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

        issues = inject_postconditions(state, my_func, ret_val, None)  # type: ignore[arg-type]
        assert len(issues) == 1
        issue = issues[0]
        assert issue is not None
        assert issue.kind is IssueKind.UNKNOWN
        assert "could not be checked" in issue.message

    def test_inject_call_preconditions_no_contract(self) -> None:
        """Verify inject_call_preconditions returns no issues if no contract."""
        state = create_initial_state()

        def my_func() -> None:
            pass

        new_state, issues = inject_call_preconditions(state, my_func, [], {})
        assert new_state is state
        assert issues == []

    def test_inject_call_preconditions_violated(self) -> None:
        """Verify inject_call_preconditions returns Issue if precondition is violated."""
        state = create_initial_state()
        x_val = MockStackValue(z3.IntVal(0))

        @requires("x > 0")
        def my_func(x: int) -> None:
            pass

        new_state, issues = inject_call_preconditions(state, my_func, [x_val], {})
        assert new_state is not None
        assert len(issues) == 1
        assert "may be violated" in issues[0].message

    def test_inject_call_preconditions_holds(self) -> None:
        """Verify inject_call_preconditions returns None if precondition holds."""
        state = create_initial_state()
        x_val = MockStackValue(z3.IntVal(1))

        @requires("x > 0")
        def my_func(x: int) -> None:
            pass

        new_state, issues = inject_call_preconditions(state, my_func, [x_val], {})
        assert new_state is not None
        assert issues == []

    def test_inject_call_preconditions_preserves_multiple_violations(self) -> None:
        """Every failed callee requirement remains independently visible."""
        state = create_initial_state()
        x_val = MockStackValue(z3.Int("x"))

        @requires("x > 0")
        @requires("x < 0")
        def my_func(x: int) -> None:
            pass

        new_state, issues = inject_call_preconditions(state, my_func, [x_val], {})
        assert new_state is not None
        assert len(issues) == 2
        assert all(issue.kind is IssueKind.CONTRACT_VIOLATION for issue in issues)

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

        new_state, issues = inject_call_preconditions(state, my_func, [x_val], {})
        assert new_state is None
        assert len(issues) == 1
        assert issues[0].kind is IssueKind.UNKNOWN
        assert "could not be checked" in issues[0].message
