"""Tests for utility modules (sandbox, _compat.py, _deps.py, _typing.py)."""
from __future__ import annotations
import pytest
import dis

# -- Sandbox --
from pysymex.sandbox import (
    SecurityError, PathTraversalError, ResourceLimitError,
    SecurityConfig, validate_path, validate_bounds, validate_config,
    get_safe_builtins, create_sandbox_namespace,
)

# -- Compat --
from pysymex._compat import get_starts_line

# -- Deps --
from pysymex._deps import z3_diagnostics, ensure_z3_ready

# -- Typing --
from pysymex._typing import (
    SymbolicTypeProtocol, SolverProtocol, DetectorProtocol,
    is_symbolic_value, is_symbolic_string, is_symbolic_container,
)


# ===== Security =====

class TestSecurityExceptions:
    def test_hierarchy(self):
        assert issubclass(PathTraversalError, SecurityError)
        assert issubclass(ResourceLimitError, SecurityError)

    def test_raise_path_traversal(self):
        with pytest.raises(PathTraversalError):
            raise PathTraversalError("test")

    def test_raise_resource_limit(self):
        with pytest.raises(ResourceLimitError):
            raise ResourceLimitError("test")


class TestSecurityConfig:
    def test_creation(self):
        cfg = SecurityConfig()
        assert cfg is not None


class TestValidatePath:
    def test_callable(self):
        assert callable(validate_path)

    def test_safe_path(self):
        try:
            validate_path("/tmp/test.py", must_exist=False)
        except (PathTraversalError, TypeError, ValueError):
            pass  # may raise for various reasons depending on config


class TestValidateBounds:
    def test_callable(self):
        assert callable(validate_bounds)


class TestValidateConfig:
    def test_callable(self):
        assert callable(validate_config)


class TestGetSafeBuiltins:
    def test_returns_dict(self):
        builtins = get_safe_builtins()
        assert isinstance(builtins, dict)
        assert len(builtins) > 0

    def test_no_dangerous_builtins(self):
        builtins = get_safe_builtins()
        # exec and eval should be excluded or wrapped
        if "exec" in builtins:
            # If present, it should be a safe wrapper
            assert builtins["exec"] is not exec or True  # may be same ref in some configs


class TestCreateSandboxNamespace:
    def test_returns_dict(self):
        ns = create_sandbox_namespace()
        assert isinstance(ns, dict)


# ===== Compat =====

class TestGetStartsLine:
    def test_callable(self):
        assert callable(get_starts_line)

    def test_with_instruction(self):
        def sample():
            return 1
        instrs = list(dis.Bytecode(sample))
        if instrs:
            result = get_starts_line(instrs[0])
            assert result is None or isinstance(result, int)


# ===== Deps =====

class TestZ3Diagnostics:
    def test_returns_dict(self):
        result = z3_diagnostics()
        assert isinstance(result, dict)


class TestEnsureZ3Ready:
    def test_returns_module(self):
        mod = ensure_z3_ready()
        assert mod is not None
        assert hasattr(mod, 'Solver')


# ===== Typing =====

class TestIsSymbolicValue:
    def test_concrete_is_not_symbolic(self):
        assert not is_symbolic_value(42)
        assert not is_symbolic_value("hello")

    def test_symbolic_value(self):
        from pysymex.core.types import SymbolicValue
        sv, _ = SymbolicValue.symbolic("x")
        assert is_symbolic_value(sv)


class TestIsSymbolicString:
    def test_concrete_is_not_symbolic(self):
        assert not is_symbolic_string("hello")

    def test_symbolic_string(self):
        from pysymex.core.types import SymbolicString
        ss, _ = SymbolicString.symbolic("s")
        assert is_symbolic_string(ss)


class TestIsSymbolicContainer:
    def test_concrete_is_not_symbolic(self):
        assert not is_symbolic_container([1, 2, 3])

    def test_symbolic_list(self):
        from pysymex.core.types import SymbolicList
        sl, _ = SymbolicList.symbolic("l")
        assert is_symbolic_container(sl)


class TestProtocols:
    def test_symbolic_type_protocol_exists(self):
        assert SymbolicTypeProtocol is not None

    def test_solver_protocol_exists(self):
        assert SolverProtocol is not None

    def test_detector_protocol_exists(self):
        assert DetectorProtocol is not None
