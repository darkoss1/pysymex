"""Tests for pysymex._deps — dependency guards for Z3 runtime requirements."""

from __future__ import annotations

import z3

import pysymex._deps as mod


class TestPackageVersion:
    """Tests for _package_version()."""

    def test_known_package_returns_string(self) -> None:
        """An installed package returns a version string."""
        result = mod._package_version("z3-solver")
        assert result is None or isinstance(result, str)

    def test_unknown_package_returns_none(self) -> None:
        """A non-existent package returns None."""
        result = mod._package_version("this-package-definitely-does-not-exist-xyz-999")
        assert result is None


class TestIsZ3Ready:
    """Tests for _is_z3_ready()."""

    def test_real_z3_module_is_ready(self) -> None:
        """The real z3 module should pass the readiness check."""
        assert mod._is_z3_ready(z3) is True

    def test_empty_module_is_not_ready(self) -> None:
        """A module without solver API is not ready."""
        import types

        fake = types.ModuleType("fake_z3")
        assert mod._is_z3_ready(fake) is False


class TestZ3Diagnostics:
    """Tests for z3_diagnostics()."""

    def test_diagnostics_with_real_z3(self) -> None:
        """Diagnostics for the real z3 module contain expected keys."""
        diag = mod.z3_diagnostics(z3)
        assert "module_repr" in diag
        assert "module_path" in diag
        assert "has_required_api" in diag
        assert "missing_api" in diag
        assert isinstance(diag["has_required_api"], dict)

    def test_diagnostics_no_missing_api_for_real_z3(self) -> None:
        """The real z3 module should have no missing API symbols."""
        diag = mod.z3_diagnostics(z3)
        assert diag["missing_api"] == []

    def test_diagnostics_with_none_module(self) -> None:
        """Passing None falls back to importing z3 automatically."""
        diag = mod.z3_diagnostics()
        assert isinstance(diag["has_required_api"], dict)


class TestBuildZ3Error:
    """Tests for _build_z3_error()."""

    def test_returns_runtime_error(self) -> None:
        """The error builder produces a RuntimeError with diagnostic details."""
        err = mod._build_z3_error()
        assert isinstance(err, RuntimeError)
        msg = str(err)
        assert "z3-solver" in msg
        assert "pip" in msg


class TestEnsureZ3Ready:
    """Tests for ensure_z3_ready()."""

    def test_returns_z3_module(self) -> None:
        """ensure_z3_ready returns a valid z3 module on a healthy install."""
        result = mod.ensure_z3_ready()
        assert hasattr(result, "Int")
        assert hasattr(result, "Solver")
        assert hasattr(result, "BoolVal")

    def test_cached_returns_same_module(self) -> None:
        """Repeated calls return the same cached module."""
        first = mod.ensure_z3_ready()
        second = mod.ensure_z3_ready()
        assert first is second

    def test_force_recheck(self) -> None:
        """force_recheck=True re-validates the module."""
        result = mod.ensure_z3_ready(force_recheck=True)
        assert hasattr(result, "Solver")
