import pytest
import z3
from unittest.mock import Mock, patch
from pysymex.analysis.specialized.invariants import (
    ClassInvariant,
    InvariantViolation,
    invariant,
    get_invariants,
    InvariantChecker,
    InvariantState,
    parse_invariant_condition,
    check_object_invariants,
)


class TestClassInvariant:
    """Test suite for pysymex.analysis.specialized.invariants.ClassInvariant."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        inv = ClassInvariant("self.x > 0", "msg")
        assert inv.condition == "self.x > 0"
        assert inv.message == "msg"


class TestInvariantViolation:
    """Test suite for pysymex.analysis.specialized.invariants.InvariantViolation."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        inv = ClassInvariant("x>0", "m", class_name="cls")
        v = InvariantViolation(inv, "entry", "meth")
        assert v.invariant.class_name == "cls"
        assert v.method_name == "meth"


def test_invariant() -> None:
    """Test invariant behavior."""

    @invariant("self.x > 0")
    class Dummy:
        pass

    invs = get_invariants(Dummy)
    assert len(invs) == 1
    assert invs[0].condition == "self.x > 0"


def test_get_invariants() -> None:
    """Test get_invariants behavior."""

    class Dummy:
        __invariants__ = [ClassInvariant("self.x > 0", class_name="Dummy")]

    invs = get_invariants(Dummy)
    assert len(invs) == 1


class TestInvariantChecker:
    """Test suite for pysymex.analysis.specialized.invariants.InvariantChecker."""

    def test_violations(self) -> None:
        """Test violations behavior."""
        checker = InvariantChecker()
        assert len(checker.violations) == 0

    def test_clear_violations(self) -> None:
        """Test clear_violations behavior."""
        checker = InvariantChecker()
        checker.violations.append(Mock())
        checker.clear_violations()
        assert len(checker.violations) == 0

    @patch("pysymex.analysis.specialized.invariants.z3.Solver.check", return_value=z3.unsat)
    def test_check_invariant(self, mock_check) -> None:
        """Test check_invariant behavior."""
        checker = InvariantChecker()
        inv = ClassInvariant("self.x > 0", class_name="cls")
        assert checker.check_invariant(inv, z3.BoolVal(True), "entry", "meth", []) is True

    @patch("pysymex.analysis.specialized.invariants.z3.Solver.check", return_value=z3.unsat)
    def test_check_all_invariants(self, mock_check) -> None:
        """Test check_all_invariants behavior."""
        checker = InvariantChecker()
        invs = [ClassInvariant("self.x > 0", class_name="cls")]
        res = checker.check_all_invariants(invs, [z3.BoolVal(True)], "entry", "meth", [])
        assert len(res) == 0

    @patch("pysymex.analysis.specialized.invariants.z3.Solver.check", return_value=z3.unsat)
    def test_check_init_exit(self, mock_check) -> None:
        """Test check_init_exit behavior."""
        checker = InvariantChecker()
        checker.check_init_exit(
            [ClassInvariant("self.x > 0", class_name="cls")], [z3.BoolVal(True)], []
        )
        assert len(checker.violations) == 0

    @patch("pysymex.analysis.specialized.invariants.z3.Solver.check", return_value=z3.unsat)
    def test_check_method_entry(self, mock_check) -> None:
        """Test check_method_entry behavior."""
        checker = InvariantChecker()
        checker.check_method_entry(
            [ClassInvariant("self.x > 0", class_name="cls")], [z3.BoolVal(True)], "m", []
        )
        assert len(checker.violations) == 0

    @patch("pysymex.analysis.specialized.invariants.z3.Solver.check", return_value=z3.unsat)
    def test_check_method_exit(self, mock_check) -> None:
        """Test check_method_exit behavior."""
        checker = InvariantChecker()
        checker.check_method_exit(
            [ClassInvariant("self.x > 0", class_name="cls")], [z3.BoolVal(True)], "m", []
        )
        assert len(checker.violations) == 0


class TestInvariantState:
    """Test suite for pysymex.analysis.specialized.invariants.InvariantState."""

    def test_checker(self) -> None:
        """Test checker behavior."""
        state = InvariantState()
        assert isinstance(state.checker, InvariantChecker)

    def test_register_class(self) -> None:
        """Test register_class behavior."""
        state = InvariantState()
        state.register_class("cls", [ClassInvariant("self.x > 0")])
        assert "cls" in state.class_invariants

    def test_get_invariants(self) -> None:
        """Test get_invariants behavior."""
        state = InvariantState()
        state.register_class("cls", [ClassInvariant("self.x > 0")])
        assert len(state.get_invariants("cls")) == 1
        assert len(state.get_invariants("other")) == 0

    def test_record_violation(self) -> None:
        """Test record_violation behavior."""
        state = InvariantState()
        state.record_violation(Mock())
        assert state.has_violations() is True

    def test_has_violations(self) -> None:
        """Test has_violations behavior."""
        state = InvariantState()
        assert state.has_violations() is False

    def test_get_violations_for_class(self) -> None:
        """Test get_violations_for_class behavior."""
        state = InvariantState()
        v = InvariantViolation(ClassInvariant("x>0", class_name="cls"), "entry", "meth")
        state.record_violation(v)
        assert len(state.get_violations_for_class("cls")) == 1
        assert len(state.get_violations_for_class("other")) == 0

    def test_clone(self) -> None:
        """Test clone behavior."""
        state = InvariantState()
        state.register_class("cls", [ClassInvariant("self.x > 0")])
        c = state.clone()
        assert "cls" in c.class_invariants


def test_parse_invariant_condition() -> None:
    """Test parse_invariant_condition behavior."""
    ast_expr = parse_invariant_condition("self.x > 0", {})
    assert ast_expr is not None

    assert isinstance(parse_invariant_condition("self.x > > 0", {}), z3.ExprRef)


def test_check_object_invariants() -> None:
    """Test check_object_invariants behavior."""

    @invariant("self.x > 0")
    class Dummy:
        def __init__(self, x: int):
            self.x = x

    obj = Dummy(5)
    state = InvariantState()

    with patch("pysymex.analysis.specialized.invariants.z3.Solver.check", return_value=z3.unsat):
        issues = check_object_invariants(obj, state, "init", "entry", [])
        assert len(issues) == 0

    obj2 = Dummy(-5)
    state2 = InvariantState()

    def mock_check(self, inv, cond, cp, m, pc):
        self._violations.append(InvariantViolation(inv, cp, m))
        return False

    with patch.object(InvariantChecker, "check_invariant", side_effect=mock_check, autospec=True):
        issues2 = check_object_invariants(obj2, state2, "init", "entry", [])
        assert len(issues2) == 1
