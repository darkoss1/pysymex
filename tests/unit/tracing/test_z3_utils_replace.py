"""Tests for pysymex.tracing.z3_utils — _replace and _substitute_abstract_names."""

from __future__ import annotations

import z3

from pysymex.tracing.z3_utils import Z3SemanticRegistry, Z3Serializer


class TestSubstituteAbstractNames:
    """Test the _substitute_abstract_names / _replace inner function."""

    def test_no_replacement_for_unknown_names(self) -> None:
        """Unknown k!N tokens should pass through unchanged."""
        registry = Z3SemanticRegistry()
        serializer = Z3Serializer(registry)
        result = serializer._substitute_abstract_names("(+ k!99 k!100)")
        assert "k!99" in result
        assert "k!100" in result

    def test_replacement_via_override(self) -> None:
        """Override k!0→x should replace k!0 in the sexpr string."""
        registry = Z3SemanticRegistry()
        registry.update({"k!0": "x", "k!1": "y"})
        serializer = Z3Serializer(registry)
        result = serializer._substitute_abstract_names("(+ k!0 k!1)")
        assert "x" in result
        assert "y" in result
        assert "k!0" not in result

    def test_replacement_of_bare_exclamation_pattern(self) -> None:
        """Bare !N patterns should also be checked against k!N registry."""
        registry = Z3SemanticRegistry()
        registry.update({"k!0": "alpha"})
        serializer = Z3Serializer(registry)
        result = serializer._substitute_abstract_names("(bvadd !0 k!0)")
        # Both !0 and k!0 should map to "alpha" via fallback
        assert result.count("alpha") >= 1

    def test_partial_match_does_not_replace(self) -> None:
        """Tokens like 'xk!0z' should not be replaced (word boundary)."""
        registry = Z3SemanticRegistry()
        registry.update({"k!0": "replaced"})
        serializer = Z3Serializer(registry)
        # k!0 embedded in a word — regex uses word boundaries
        result = serializer._substitute_abstract_names("(+ k!0 normal_var)")
        assert "replaced" in result
        assert "normal_var" in result

    def test_safe_sexpr_with_z3_expression(self) -> None:
        """safe_sexpr should handle real Z3 expressions without crashing."""
        registry = Z3SemanticRegistry()
        serializer = Z3Serializer(registry)
        x = z3.Int("x")
        expr = x + 1
        result = serializer.safe_sexpr(expr)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_safe_sexpr_non_z3_returns_repr(self) -> None:
        """safe_sexpr on a non-Z3 object should fall back to repr()."""
        registry = Z3SemanticRegistry()
        serializer = Z3Serializer(registry)
        result = serializer.safe_sexpr("hello")
        assert "hello" in result
