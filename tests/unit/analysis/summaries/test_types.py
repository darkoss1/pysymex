import pytest
import z3
from pysymex.analysis.summaries.types import (
    ParameterInfo,
    ModifiedVariable,
    ReadVariable,
    CallSite,
    ExceptionInfo,
    FunctionSummary,
)


class TestParameterInfo:
    """Test suite for pysymex.analysis.summaries.types.ParameterInfo."""

    def test_to_z3(self) -> None:
        """Test to_z3 behavior."""
        p1 = ParameterInfo("x", 0, "int")
        z1 = p1.to_z3()
        assert z1 is not None

        p2 = ParameterInfo("b", 1, "bool")
        z2 = p2.to_z3("pref_")
        assert "pref_b" in str(z2)


class TestModifiedVariable:
    """Test suite for pysymex.analysis.summaries.types.ModifiedVariable."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        v = ModifiedVariable("x", "global")
        assert v.name == "x"
        assert v.scope == "global"


class TestReadVariable:
    """Test suite for pysymex.analysis.summaries.types.ReadVariable."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        v = ReadVariable("y", "local")
        assert v.name == "y"
        assert v.scope == "local"


class TestCallSite:
    """Test suite for pysymex.analysis.summaries.types.CallSite."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        c = CallSite("foo", [1], {"b": 2}, 10, True, "self")
        assert c.callee == "foo"
        assert c.args == [1]


class TestExceptionInfo:
    """Test suite for pysymex.analysis.summaries.types.ExceptionInfo."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        e = ExceptionInfo("ValueError", z3.BoolVal(True))
        assert e.exc_type == "ValueError"


class TestFunctionSummary:
    """Test suite for pysymex.analysis.summaries.types.FunctionSummary."""

    def test_get_parameter(self) -> None:
        """Test get_parameter behavior."""
        s = FunctionSummary("f")
        s.parameters.append(ParameterInfo("x", 0))
        assert s.get_parameter("x") is not None
        assert s.get_parameter("y") is None

    def test_get_parameter_z3(self) -> None:
        """Test get_parameter_z3 behavior."""
        s = FunctionSummary("f")
        s.parameters.append(ParameterInfo("x", 0, "int"))
        assert s.get_parameter_z3("x") is not None
        assert s.get_parameter_z3("y") is None

    def test_add_precondition(self) -> None:
        """Test add_precondition behavior."""
        s = FunctionSummary("f")
        s.add_precondition(z3.BoolVal(True))
        assert len(s.preconditions) == 1

    def test_add_postcondition(self) -> None:
        """Test add_postcondition behavior."""
        s = FunctionSummary("f")
        s.add_postcondition(z3.BoolVal(False))
        assert len(s.postconditions) == 1

    def test_add_modified(self) -> None:
        """Test add_modified behavior."""
        s = FunctionSummary("f")
        s.add_modified(ModifiedVariable("x"))
        assert len(s.modified) == 1

    def test_add_reads(self) -> None:
        """Test add_reads behavior."""
        s = FunctionSummary("f")
        s.add_reads(ReadVariable("x"))
        assert len(s.reads) == 1

    def test_add_call(self) -> None:
        """Test add_call behavior."""
        s = FunctionSummary("f")
        s.add_call(CallSite("g"))
        assert len(s.calls) == 1

    def test_add_exception(self) -> None:
        """Test add_exception behavior."""
        s = FunctionSummary("f")
        s.add_exception(ExceptionInfo("ValueError"))
        assert len(s.may_raise) == 1

    def test_modifies_globals(self) -> None:
        """Test modifies_globals behavior."""
        s = FunctionSummary("f")
        assert s.modifies_globals() is False
        s.add_modified(ModifiedVariable("x", "global"))
        assert s.modifies_globals() is True

    def test_reads_globals(self) -> None:
        """Test reads_globals behavior."""
        s = FunctionSummary("f")
        assert s.reads_globals() is False
        s.add_reads(ReadVariable("y", "global"))
        assert s.reads_globals() is True

    def test_get_all_preconditions(self) -> None:
        """Test get_all_preconditions behavior."""
        s = FunctionSummary("f")
        assert s.get_all_preconditions() is not None
        s.add_precondition(z3.BoolVal(True))
        assert z3.is_true(z3.simplify(s.get_all_preconditions()))

    def test_get_all_postconditions(self) -> None:
        """Test get_all_postconditions behavior."""
        s = FunctionSummary("f")
        assert s.get_all_postconditions() is not None
        s.add_postcondition(z3.BoolVal(False))
        assert z3.is_false(z3.simplify(s.get_all_postconditions()))

    def test_clone(self) -> None:
        """Test clone behavior."""
        s = FunctionSummary("f")
        s.add_precondition(z3.BoolVal(True))
        cloned = s.clone()
        assert cloned.name == "f"
        assert len(cloned.preconditions) == 1
