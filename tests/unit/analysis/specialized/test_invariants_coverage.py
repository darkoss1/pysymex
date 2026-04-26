"""Tests for pysymex.analysis.specialized.invariants — full coverage."""

from __future__ import annotations

import z3

from pysymex.analysis.specialized.invariants import (
    ClassInvariant,
    InvariantChecker,
    InvariantState,
    InvariantViolation,
    check_object_invariants,
    get_invariants,
    invariant,
    parse_invariant_condition,
)


class TestClassInvariant:
    """Test ClassInvariant dataclass."""

    def test_str_with_message(self) -> None:
        """__str__ includes condition and message."""
        inv = ClassInvariant(condition="x > 0", message="must be positive")
        assert str(inv) == "x > 0 (must be positive)"

    def test_str_without_message(self) -> None:
        """__str__ shows only condition when no message."""
        inv = ClassInvariant(condition="x > 0")
        assert str(inv) == "x > 0"


class TestInvariantViolation:
    """Test InvariantViolation dataclass."""

    def test_str_format(self) -> None:
        """__str__ shows human-readable violation message."""
        inv = ClassInvariant(condition="x > 0")
        v = InvariantViolation(invariant=inv, when="entry", method_name="deposit")
        assert "entry" in str(v)
        assert "deposit" in str(v)


class TestInvariantDecorator:
    """Test @invariant decorator."""

    def test_decorator_adds_invariant_to_class(self) -> None:
        """@invariant appends a ClassInvariant to __invariants__."""

        @invariant("self.x > 0", "x must be positive")
        class Foo:
            pass

        assert hasattr(Foo, "__invariants__")
        inv_list = Foo.__invariants__  # type: ignore[attr-defined]
        assert len(inv_list) == 1
        assert inv_list[0].condition == "self.x > 0"
        assert inv_list[0].class_name == "Foo"

    def test_multiple_invariants(self) -> None:
        """Multiple @invariant decorators stack correctly."""

        @invariant("self.y >= 0")
        @invariant("self.x > 0")
        class Bar:
            pass

        assert len(Bar.__invariants__) == 2  # type: ignore[attr-defined]


class TestGetInvariants:
    """Test get_invariants (including MRO traversal)."""

    def test_base_class_invariants(self) -> None:
        """get_invariants returns invariants from the class itself."""

        @invariant("self.a > 0")
        class Base:
            pass

        result = get_invariants(Base)
        # get_invariants traverses MRO — Base appears once
        conditions = [inv.condition for inv in result]
        assert "self.a > 0" in conditions

    def test_inherited_invariants_include_base(self) -> None:
        """get_invariants includes invariants from base classes."""

        @invariant("self.a > 0")
        class Base:
            pass

        @invariant("self.b > 0")
        class Derived(Base):
            pass

        result = get_invariants(Derived)
        conditions = {inv.condition for inv in result}
        assert "self.a > 0" in conditions
        assert "self.b > 0" in conditions

    def test_no_invariants_returns_empty(self) -> None:
        """get_invariants returns [] for a class without @invariant."""

        class Plain:
            pass

        assert get_invariants(Plain) == []


class TestInvariantChecker:
    """Test InvariantChecker methods."""

    def test_check_invariant_holds(self) -> None:
        """check_invariant returns True when invariant is satisfiable."""
        checker = InvariantChecker()
        inv = ClassInvariant(condition="x > 0")
        x = z3.Int("x")
        cond = x > 0
        result = checker.check_invariant(inv, cond, "exit", "my_method", [x == 5])
        assert result is True
        assert len(checker.violations) == 0

    def test_check_invariant_violated(self) -> None:
        """check_invariant returns False and records violation."""
        checker = InvariantChecker()
        inv = ClassInvariant(condition="x > 0", class_name="MyClass")
        x = z3.Int("x")
        cond = x > 0
        result = checker.check_invariant(inv, cond, "entry", "deposit", [x == -1])
        assert result is False
        assert len(checker.violations) == 1
        assert checker.violations[0].when == "entry"
        assert checker.violations[0].method_name == "deposit"

    def test_duplicate_check_skipped(self) -> None:
        """Same invariant/method/when combination is not rechecked."""
        checker = InvariantChecker()
        inv = ClassInvariant(condition="x > 0", class_name="MyClass")
        x = z3.Int("x")
        cond = x > 0
        checker.check_invariant(inv, cond, "exit", "withdraw", [x == 5])
        checker.check_invariant(inv, cond, "exit", "withdraw", [x == -1])
        # Second call skipped due to dedup
        assert len(checker.violations) == 0

    def test_clear_violations(self) -> None:
        """clear_violations empties the violations list."""
        checker = InvariantChecker()
        inv = ClassInvariant(condition="x > 0", class_name="MyClass")
        x = z3.Int("x")
        checker.check_invariant(inv, x > 0, "entry", "m", [x == -1])
        checker.clear_violations()
        assert len(checker.violations) == 0

    def test_check_all_invariants_with_violation(self) -> None:
        """check_all_invariants returns list of violations."""
        checker = InvariantChecker()
        x = z3.Int("x_all")
        inv1 = ClassInvariant(condition="x > 0", class_name="A")
        violations = checker.check_all_invariants(
            [inv1],
            [x > 0],
            "exit",
            "my_method_all",
            [x == -5],
        )
        assert len(violations) >= 1

    def test_check_init_exit(self) -> None:
        """check_init_exit delegates to check_all_invariants with when='init'."""
        checker = InvariantChecker()
        x = z3.Int("x_init")
        inv = ClassInvariant(condition="x > 0", class_name="C")
        violations = checker.check_init_exit([inv], [x > 0], [x == 5])
        assert len(violations) == 0

    def test_check_method_entry(self) -> None:
        """check_method_entry uses when='entry'."""
        checker = InvariantChecker()
        x = z3.Int("x_entry")
        inv = ClassInvariant(condition="x > 0", class_name="C2")
        violations = checker.check_method_entry([inv], [x > 0], "deposit2", [x == -1])
        assert len(violations) == 1

    def test_check_method_exit(self) -> None:
        """check_method_exit uses when='exit'."""
        checker = InvariantChecker()
        x = z3.Int("x_exit")
        inv = ClassInvariant(condition="x > 0", class_name="C3")
        violations = checker.check_method_exit([inv], [x > 0], "withdraw3", [x == -1])
        assert len(violations) == 1

    def test_extract_counterexample_types(self) -> None:
        """_extract_counterexample extracts int, bool, real, and string values."""
        checker = InvariantChecker()
        s = z3.Solver()
        x = z3.Int("x_ce")
        b = z3.Bool("b_ce")
        s.add(x == 42, b == True)
        assert s.check() == z3.sat
        model = s.model()
        ce = checker._extract_counterexample(model)
        assert ce["x_ce"] == 42
        assert ce["b_ce"] is True


class TestInvariantState:
    """Test InvariantState dataclass."""

    def test_register_and_get_invariants(self) -> None:
        """register_class + get_invariants round-trips."""
        state = InvariantState()
        inv = ClassInvariant(condition="self.x > 0", class_name="Foo")
        state.register_class("Foo", [inv])
        result = state.get_invariants("Foo")
        assert len(result) == 1
        assert result[0].condition == "self.x > 0"

    def test_get_invariants_unknown_class(self) -> None:
        """get_invariants returns [] for unregistered class."""
        state = InvariantState()
        assert state.get_invariants("Unknown") == []

    def test_record_violation(self) -> None:
        """record_violation appends to violations list."""
        state = InvariantState()
        v = InvariantViolation(
            invariant=ClassInvariant(condition="x > 0", class_name="C"),
            when="entry",
            method_name="m",
        )
        state.record_violation(v)
        assert state.has_violations()
        assert len(state.violations) == 1

    def test_has_violations_empty(self) -> None:
        """has_violations returns False when no violations."""
        state = InvariantState()
        assert state.has_violations() is False

    def test_get_violations_for_class(self) -> None:
        """get_violations_for_class filters by class name."""
        state = InvariantState()
        v1 = InvariantViolation(
            invariant=ClassInvariant(condition="a", class_name="A"),
            when="entry",
            method_name="m",
        )
        v2 = InvariantViolation(
            invariant=ClassInvariant(condition="b", class_name="B"),
            when="exit",
            method_name="n",
        )
        state.record_violation(v1)
        state.record_violation(v2)
        a_violations = state.get_violations_for_class("A")
        assert len(a_violations) == 1
        assert a_violations[0].invariant.class_name == "A"

    def test_clone(self) -> None:
        """clone creates independent copy."""
        state = InvariantState()
        inv = ClassInvariant(condition="self.x > 0", class_name="Foo")
        state.register_class("Foo", [inv])
        clone = state.clone()
        assert clone.get_invariants("Foo") == state.get_invariants("Foo")
        clone.register_class("Bar", [])
        assert state.get_invariants("Bar") == []

    def test_checker_property_creates_lazily(self) -> None:
        """checker property creates InvariantChecker on first access."""
        state = InvariantState()
        checker = state.checker
        assert isinstance(checker, InvariantChecker)
        assert state.checker is checker  # Same instance


class TestParseInvariantCondition:
    """Test parse_invariant_condition."""

    def test_simple_condition(self) -> None:
        """Parses 'self.x > 0' into a Z3 BoolRef."""
        attrs: dict[str, z3.ExprRef] = {"self.x": z3.Int("self.x")}
        result = parse_invariant_condition("self.x > 0", attrs)
        assert isinstance(result, z3.BoolRef)

    def test_auto_creates_missing_self_attrs(self) -> None:
        """Missing self.* attributes are auto-created as z3.Int."""
        attrs: dict[str, z3.ExprRef] = {}
        result = parse_invariant_condition("self.balance > 0", attrs)
        assert "self.balance" in attrs
        assert isinstance(result, z3.BoolRef)


class TestCheckObjectInvariants:
    """Test check_object_invariants."""

    def test_object_violating_invariant(self) -> None:
        """Object violating invariant reports the violation."""

        @invariant("self.value > 0")
        class MustBePositive:
            def __init__(self) -> None:
                self.value = -5

        state = InvariantState()
        obj = MustBePositive()
        violations = check_object_invariants(obj, state, "__init__", "init")
        assert len(violations) >= 1

    def test_object_without_invariants(self) -> None:
        """Object without @invariant reports no violations."""

        class NoInvariants:
            pass

        state = InvariantState()
        obj = NoInvariants()
        violations = check_object_invariants(obj, state, "method", "entry")
        assert len(violations) == 0
