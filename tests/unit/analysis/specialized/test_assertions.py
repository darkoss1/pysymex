import pytest
from pysymex.analysis.specialized.assertions import (
    ContextType,
    AssertionAnalysis,
    analyze_function_name,
    analyze_source_context,
    analyze_assertion,
    is_intentional_assertion,
)


class TestContextType:
    """Test suite for pysymex.analysis.specialized.assertions.ContextType."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ContextType.INPUT_VALIDATION.name == "INPUT_VALIDATION"
        assert ContextType.TYPE_GUARD.name == "TYPE_GUARD"


class TestAssertionAnalysis:
    """Test suite for pysymex.analysis.specialized.assertions.AssertionAnalysis."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        a = AssertionAnalysis(ContextType.INPUT_VALIDATION, True, "func", "cond", 0.9)
        assert a.context_type == ContextType.INPUT_VALIDATION
        assert a.is_intentional is True


def test_analyze_function_name() -> None:
    """Test analyze_function_name behavior."""
    ctx, conf = analyze_function_name("validate_user")
    assert ctx == ContextType.INPUT_VALIDATION
    assert conf == 0.9

    ctx2, conf2 = analyze_function_name("authorize_access")
    assert ctx2 == ContextType.PERMISSION_CHECK

    ctx3, conf3 = analyze_function_name("do_something")
    assert ctx3 == ContextType.UNKNOWN


def test_analyze_source_context() -> None:
    """Test analyze_source_context behavior."""
    source = "if x is None:\n    raise ValueError"
    ctx, conf = analyze_source_context(source)
    assert ctx == ContextType.NULL_GUARD

    source2 = "if not isinstance(x, int):\n    raise TypeError"
    ctx2, conf2 = analyze_source_context(source2)
    assert ctx2 == ContextType.TYPE_GUARD

    source3 = "raise RuntimeError('db error')"
    ctx3, conf3 = analyze_source_context(source3)
    assert ctx3 == ContextType.PRODUCTION_CHECK


def test_analyze_assertion() -> None:
    """Test analyze_assertion behavior."""
    res = analyze_assertion("You must provide an email", "process_form")
    assert res.context_type == ContextType.INPUT_VALIDATION
    assert res.is_intentional is True

    res2 = analyze_assertion("Access denied", "view_admin")
    assert res2.context_type == ContextType.PERMISSION_CHECK

    res3 = analyze_assertion("Unexpected condition", "calculate")
    assert res3.is_intentional is False


def test_is_intentional_assertion() -> None:
    """Test is_intentional_assertion behavior."""
    assert is_intentional_assertion("must provide id", "validate") is True
    assert is_intentional_assertion("failed to load", "my_func") is False
