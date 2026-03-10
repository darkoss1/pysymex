"""Tests for the Assertion Context Analyzer module.

Tests cover:
- Function name analysis
- Source code context analysis
- Full assertion analysis
- Intentional assertion detection
"""

from pysymex.analysis.assertion_context import (
    AssertionAnalysis,
    ContextType,
    analyze_assertion,
    analyze_function_name,
    analyze_source_context,
    is_intentional_assertion,
)


class TestAnalyzeFunctionName:
    """Test function name analysis."""

    def test_validate_prefix(self):
        """Functions starting with 'validate' should be INPUT_VALIDATION."""
        context, confidence = analyze_function_name("validate_input")
        assert context == ContextType.INPUT_VALIDATION
        assert confidence >= 0.8

    def test_sanitize_prefix(self):
        """Functions starting with 'sanitize' should be INPUT_VALIDATION."""
        context, confidence = analyze_function_name("sanitize_html")
        assert context == ContextType.INPUT_VALIDATION
        assert confidence >= 0.8

    def test_check_prefix(self):
        """Functions starting with 'check' should be INPUT_VALIDATION."""
        context, confidence = analyze_function_name("check_permissions")
        assert context == ContextType.INPUT_VALIDATION
        assert confidence >= 0.8

    def test_verify_prefix(self):
        """Functions starting with 'verify' should be INPUT_VALIDATION."""
        context, confidence = analyze_function_name("verify_signature")
        assert context == ContextType.INPUT_VALIDATION
        assert confidence >= 0.8

    def test_ensure_prefix(self):
        """Functions starting with 'ensure' should be INPUT_VALIDATION."""
        context, confidence = analyze_function_name("ensure_authenticated")
        assert context == ContextType.INPUT_VALIDATION
        assert confidence >= 0.8

    def test_auth_prefix(self):
        """Functions starting with 'auth' should be PERMISSION_CHECK."""
        context, confidence = analyze_function_name("authorize_user")
        assert context == ContextType.PERMISSION_CHECK
        assert confidence >= 0.8

    def test_permission_prefix(self):
        """Functions starting with 'permission' should be PERMISSION_CHECK."""
        context, confidence = analyze_function_name("permission_required")
        assert context == ContextType.PERMISSION_CHECK
        assert confidence >= 0.8

    def test_init_is_invariant(self):
        """Functions with 'init' should be INVARIANT."""
        context, confidence = analyze_function_name("__init__")
        assert context == ContextType.INVARIANT
        assert confidence >= 0.6

    def test_setup_is_invariant(self):
        """Functions with 'setup' should be INVARIANT."""
        context, confidence = analyze_function_name("setup_config")
        assert context == ContextType.INVARIANT
        assert confidence >= 0.6

    def test_parse_is_validation(self):
        """Functions with 'parse' should be INPUT_VALIDATION."""
        context, confidence = analyze_function_name("parse_arguments")
        assert context == ContextType.INPUT_VALIDATION
        assert confidence >= 0.5

    def test_random_name_is_unknown(self):
        """Random function names should be UNKNOWN."""
        context, confidence = analyze_function_name("do_something_else")
        assert context == ContextType.UNKNOWN
        assert confidence <= 0.5

    def test_none_name(self):
        """None function name should be UNKNOWN with low confidence."""
        context, confidence = analyze_function_name(None)
        assert context == ContextType.UNKNOWN
        assert confidence <= 0.4


class TestAnalyzeSourceContext:
    """Test source code context analysis."""

    def test_production_check(self):
        """PRODUCTION in source should be PRODUCTION_CHECK."""
        source = "if PRODUCTION: raise RuntimeError('forbidden')"
        context, confidence = analyze_source_context(source)
        assert context == ContextType.PRODUCTION_CHECK
        assert confidence >= 0.8

    def test_debug_check(self):
        """DEBUG in source should be PRODUCTION_CHECK."""
        source = "if not DEBUG: raise ValueError('not in debug mode')"
        context, confidence = analyze_source_context(source)
        assert context == ContextType.PRODUCTION_CHECK
        assert confidence >= 0.8

    def test_config_pattern(self):
        """config. in source should be CONFIG_GUARD."""
        source = "if config.strict: assert x > 0"
        context, confidence = analyze_source_context(source)
        assert context == ContextType.CONFIG_GUARD
        assert confidence >= 0.7

    def test_settings_pattern(self):
        """settings. in source should be CONFIG_GUARD."""
        source = "if settings.require_auth: raise PermissionError()"
        context, confidence = analyze_source_context(source)
        assert context == ContextType.CONFIG_GUARD
        assert confidence >= 0.7

    def test_raise_valueerror(self):
        """raise ValueError should be INPUT_VALIDATION."""
        source = "if not valid: raise ValueError('invalid input')"
        context, confidence = analyze_source_context(source)
        # ValueError indicates validation, confidence should be reasonable
        assert context in (ContextType.INPUT_VALIDATION, ContextType.NULL_GUARD)
        assert confidence >= 0.6

    def test_raise_typeerror(self):
        """raise TypeError should be TYPE_GUARD."""
        source = "if not isinstance(x, int): raise TypeError()"
        context, confidence = analyze_source_context(source)
        assert context == ContextType.TYPE_GUARD
        assert confidence >= 0.7

    def test_raise_permissionerror(self):
        """raise PermissionError should be PERMISSION_CHECK."""
        source = "if not authorized: raise PermissionError('denied')"
        context, confidence = analyze_source_context(source)
        assert context == ContextType.PERMISSION_CHECK
        assert confidence >= 0.7

    def test_isinstance_check(self):
        """isinstance() should be TYPE_GUARD."""
        source = "if not isinstance(value, str): return False"
        context, confidence = analyze_source_context(source)
        assert context == ContextType.TYPE_GUARD
        assert confidence >= 0.6

    def test_none_check(self):
        """is None check should be NULL_GUARD or INPUT_VALIDATION."""
        source = "if x is None: raise ValueError('x required')"
        context, confidence = analyze_source_context(source)
        # Both None check and ValueError are present - either is acceptable
        assert context in (ContextType.NULL_GUARD, ContextType.INPUT_VALIDATION)
        assert confidence >= 0.6

    def test_is_not_none(self):
        """is not None check should be NULL_GUARD."""
        source = "assert data is not None"
        context, confidence = analyze_source_context(source)
        assert context == ContextType.NULL_GUARD
        assert confidence >= 0.6

    def test_random_code_is_unknown(self):
        """Random code should be UNKNOWN."""
        source = "result = calculate(x, y)"
        context, confidence = analyze_source_context(source)
        assert context == ContextType.UNKNOWN
        assert confidence <= 0.4

    def test_line_number_focus_ignores_unrelated_lines(self):
        """Line-focused analysis should prefer the local assertion context."""
        source = "\n".join(
            [
                "if PRODUCTION:",
                "    raise RuntimeError('guard')",
                "assert data is not None",
            ]
        )
        context, confidence = analyze_source_context(source, line_number=3)
        assert context == ContextType.NULL_GUARD
        assert confidence >= 0.6


class TestAnalyzeAssertion:
    """Test full assertion analysis."""

    def test_validation_function(self):
        """Validation function should be detected."""
        analysis = analyze_assertion(
            message="assertion failed",
            function_name="validate_email",
        )
        assert analysis.context_type == ContextType.INPUT_VALIDATION
        assert analysis.is_intentional is True
        assert analysis.confidence >= 0.8

    def test_security_with_source(self):
        """Security check with source context."""
        analysis = analyze_assertion(
            message="check failed",
            function_name="some_function",
            source_code="if not PRODUCTION: raise RuntimeError()",
        )
        assert analysis.context_type == ContextType.PRODUCTION_CHECK
        assert analysis.is_intentional is True

    def test_unknown_without_context(self):
        """Unknown without any context."""
        analysis = analyze_assertion(
            message="something went wrong",
            function_name="do_stuff",
        )
        assert analysis.context_type == ContextType.UNKNOWN
        assert analysis.is_intentional is False

    def test_required_in_message(self):
        """'required' in message suggests validation."""
        analysis = analyze_assertion(
            message="field is required",
            function_name="process",
        )
        assert analysis.context_type == ContextType.INPUT_VALIDATION

    def test_permission_in_message(self):
        """'permission' in message suggests permission check."""
        analysis = analyze_assertion(
            message="permission denied for user",
            function_name="access",
        )
        assert analysis.context_type == ContextType.PERMISSION_CHECK

    def test_function_purpose_inferred(self):
        """Function purpose should be inferred."""
        analysis = analyze_assertion(
            message="error",
            function_name="validate_config",
        )
        assert analysis.function_purpose == "Input validation"


class TestIsIntentionalAssertion:
    """Test the quick intentional assertion checker."""

    def test_validation_is_intentional(self):
        """Validation functions are intentional."""
        assert is_intentional_assertion("error", function_name="validate_input") is True

    def test_sanitize_is_intentional(self):
        """Sanitize functions are intentional."""
        assert is_intentional_assertion("error", function_name="sanitize_data") is True

    def test_production_check_is_intentional(self):
        """Production checks are intentional."""
        assert (
            is_intentional_assertion(
                "error",
                source_code="if PRODUCTION: raise RuntimeError()",
            )
            is True
        )

    def test_random_is_not_intentional(self):
        """Random functions are not intentional."""
        assert is_intentional_assertion("error", function_name="do_thing") is False

    def test_no_context_is_not_intentional(self):
        """No context means not intentional."""
        assert is_intentional_assertion("error") is False


class TestContextTypeEnum:
    """Test the ContextType enum."""

    def test_all_types_exist(self):
        """Verify all expected context types exist."""
        expected = [
            "PRODUCTION_CHECK",
            "CONFIG_GUARD",
            "INPUT_VALIDATION",
            "TYPE_GUARD",
            "NULL_GUARD",
            "PERMISSION_CHECK",
            "INVARIANT",
            "BOUNDARY_CHECK",
            "UNKNOWN",
        ]
        for name in expected:
            assert hasattr(ContextType, name), f"Missing ContextType: {name}"


class TestAssertionAnalysisDataclass:
    """Test the AssertionAnalysis dataclass."""

    def test_dataclass_creation(self):
        """Test creating AssertionAnalysis."""
        analysis = AssertionAnalysis(
            context_type=ContextType.INPUT_VALIDATION,
            is_intentional=True,
            function_purpose="Validate input",
            confidence=0.9,
        )
        assert analysis.context_type == ContextType.INPUT_VALIDATION
        assert analysis.is_intentional is True
        assert analysis.function_purpose == "Validate input"
        assert analysis.confidence == 0.9

    def test_defaults(self):
        """Test default values."""
        analysis = AssertionAnalysis(
            context_type=ContextType.UNKNOWN,
            is_intentional=False,
        )
        assert analysis.function_purpose is None
        assert analysis.related_condition is None
        assert analysis.confidence == 0.5
