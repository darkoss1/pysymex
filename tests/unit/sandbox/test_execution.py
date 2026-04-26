"""Tests for pysymex.sandbox.execution — safe_exec, hardened_exec, sandbox helpers."""

from __future__ import annotations

import sys

import pytest

from pysymex.sandbox.execution import (
    ExecutionTimeout,
    ResourceLimitError,
    SecurityError,
    _check_attr_name,
    _safe_delattr,
    _safe_getattr,
    _safe_hasattr,
    _safe_setattr,
    create_sandbox_namespace,
    get_hardened_builtins,
    get_safe_builtins,
    make_restricted_import,
    resource_limits,
    safe_exec,
    timeout_context,
)


class TestGetSafeBuiltins:
    """Test get_safe_builtins."""

    def test_safe_builtins_excludes_dangerous(self) -> None:
        """Dangerous builtins are replaced with stubs that raise."""
        from pysymex._constants import DANGEROUS_BUILTINS

        safe = get_safe_builtins()
        for name in DANGEROUS_BUILTINS:
            func = safe.get(name)
            if func is not None:
                with pytest.raises(SecurityError):
                    func()  # type: ignore[misc]

    def test_safe_builtins_includes_safe_ones(self) -> None:
        """Safe builtins like 'len' are present."""
        safe = get_safe_builtins()
        assert "len" in safe
        assert "print" in safe
        assert "int" in safe


class TestCreateSandboxNamespace:
    """Test create_sandbox_namespace."""

    def test_with_builtins(self) -> None:
        """Default namespace includes __builtins__."""
        ns = create_sandbox_namespace()
        assert "__builtins__" in ns
        assert isinstance(ns["__builtins__"], dict)

    def test_without_builtins(self) -> None:
        """allow_builtins=False results in empty __builtins__."""
        ns = create_sandbox_namespace(allow_builtins=False)
        assert ns["__builtins__"] == {}

    def test_extra_globals_merged(self) -> None:
        """Extra globals are merged into namespace."""
        ns = create_sandbox_namespace(extra_globals={"my_var": 42})
        assert ns["my_var"] == 42


class TestMakeRestrictedImport:
    """Test make_restricted_import."""

    def test_allowed_module_succeeds(self) -> None:
        """Importing an allowed module works."""
        restricted = make_restricted_import(frozenset({"math"}))
        result = restricted("math")
        import math

        assert result is math

    def test_disallowed_module_raises(self) -> None:
        """Importing a disallowed module raises SecurityError."""
        restricted = make_restricted_import(frozenset({"math"}))
        with pytest.raises(SecurityError, match="not permitted"):
            restricted("os")

    def test_submodule_check_uses_top_level(self) -> None:
        """'os.path' is rejected when 'os' is not in allowlist."""
        restricted = make_restricted_import(frozenset({"math"}))
        with pytest.raises(SecurityError):
            restricted("os.path")


class TestSafeExec:
    """Test safe_exec."""

    def test_simple_code_execution(self) -> None:
        """Simple assignment executes correctly."""
        ns = safe_exec("x = 42")
        assert ns["x"] == 42

    def test_code_too_large_raises(self) -> None:
        """Code exceeding MAX_CODE_SIZE raises ResourceLimitError."""
        from pysymex._constants import MAX_CODE_SIZE

        huge = "x = 1\n" * (MAX_CODE_SIZE + 1)
        with pytest.raises(ResourceLimitError, match="Code too large"):
            safe_exec(huge)

    def test_syntax_error_propagates(self) -> None:
        """Invalid syntax raises SyntaxError."""
        with pytest.raises(SyntaxError):
            safe_exec("def ")

    def test_import_rejected(self) -> None:
        """Import statements in code are rejected."""
        with pytest.raises(SecurityError, match="Forbidden AST"):
            safe_exec("import os")

    def test_global_rejected(self) -> None:
        """Global statement is rejected."""
        with pytest.raises(SecurityError, match="Forbidden AST"):
            safe_exec("global x")

    def test_provided_namespace_used(self) -> None:
        """Provided namespace is used for execution."""
        ns = safe_exec("y = x + 1", {"x": 10})
        assert ns["y"] == 11


class TestCheckAttrName:
    """Test _check_attr_name."""

    def test_safe_name_passes(self) -> None:
        """Normal attribute names pass without error."""
        _check_attr_name("value")
        _check_attr_name("name")

    def test_dangerous_name_raises(self) -> None:
        """Dangerous attribute names raise SecurityError."""
        with pytest.raises(SecurityError, match="blocked"):
            _check_attr_name("__subclasses__")


class TestSafeGetattr:
    """Test _safe_getattr."""

    def test_safe_attribute_access(self) -> None:
        """Normal attribute access works."""
        result = _safe_getattr("hello", "upper")
        assert callable(result)

    def test_dangerous_attribute_blocked(self) -> None:
        """Dangerous attribute access is blocked."""
        with pytest.raises(SecurityError):
            _safe_getattr("hello", "__subclasses__")

    def test_with_default(self) -> None:
        """Default value returned when attribute missing."""
        result = _safe_getattr("hello", "nonexistent", "fallback")
        assert result == "fallback"


class TestSafeSetattr:
    """Test _safe_setattr."""

    def test_safe_setattr_works(self) -> None:
        """Normal setattr works."""

        class Obj:
            pass

        obj = Obj()
        _safe_setattr(obj, "value", 42)
        assert obj.value == 42  # type: ignore[attr-defined]

    def test_dangerous_setattr_blocked(self) -> None:
        """Dangerous setattr is blocked before reaching the real setattr."""

        class Obj:
            pass

        obj = Obj()
        with pytest.raises(SecurityError):
            _safe_setattr(obj, "__subclasses__", "bad")


class TestSafeDelattr:
    """Test _safe_delattr."""

    def test_safe_delattr_works(self) -> None:
        """Normal delattr works."""

        class Obj:
            pass

        obj = Obj()
        obj.value = 42  # type: ignore[attr-defined]
        _safe_delattr(obj, "value")
        assert not hasattr(obj, "value")

    def test_dangerous_delattr_blocked(self) -> None:
        """Dangerous delattr is blocked before reaching the real delattr."""

        class Obj:
            pass

        obj = Obj()
        with pytest.raises(SecurityError):
            _safe_delattr(obj, "__subclasses__")


class TestSafeHasattr:
    """Test _safe_hasattr."""

    def test_safe_hasattr_works(self) -> None:
        """Normal hasattr works."""
        assert _safe_hasattr("hello", "upper") is True

    def test_dangerous_hasattr_blocked(self) -> None:
        """Dangerous hasattr is blocked."""
        with pytest.raises(SecurityError):
            _safe_hasattr("hello", "__subclasses__")


class TestGetHardenedBuiltins:
    """Test get_hardened_builtins."""

    def test_includes_safe_getattr(self) -> None:
        """Hardened builtins replace getattr with safe version."""
        hardened = get_hardened_builtins()
        assert hardened["getattr"] is _safe_getattr
        assert hardened["setattr"] is _safe_setattr
        assert hardened["delattr"] is _safe_delattr
        assert hardened["hasattr"] is _safe_hasattr

    def test_includes_restricted_import(self) -> None:
        """Hardened builtins include restricted __import__."""
        hardened = get_hardened_builtins()
        assert "__import__" in hardened

    def test_includes_build_class(self) -> None:
        """Hardened builtins include __build_class__ if available."""
        hardened = get_hardened_builtins()
        import builtins

        if hasattr(builtins, "__build_class__"):
            assert "__build_class__" in hardened


class TestTimeoutContext:
    """Test timeout_context."""

    @pytest.mark.timeout(10)
    def test_no_timeout_fast_code(self) -> None:
        """Fast code completes without timeout."""
        with timeout_context(5.0):
            x = 1 + 1
            assert x == 2


class TestResourceLimits:
    """Test resource_limits."""

    @pytest.mark.timeout(10)
    def test_resource_limits_context_manager(self) -> None:
        """resource_limits context manager runs without error."""
        with resource_limits(max_memory_mb=512, max_cpu_seconds=60):
            x = 1 + 1
            assert x == 2
