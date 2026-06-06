"""Tests for pysymex.api — public API for symbolic execution."""

from __future__ import annotations

import json
from collections.abc import Mapping
from inspect import iscoroutinefunction
from pathlib import Path
from unittest.mock import patch

import pytest

import pysymex.api as mod
from pysymex import analyze as root_analyze
from pysymex import scan_directory as root_scan_directory
from pysymex import scan_file as root_scan_file
from pysymex.config import AnalysisConfig as ConfigAnalysisConfig
from pysymex.execution.config.settings import ExecutionConfig as CanonicalExecutionConfig
from pysymex.execution.results.result import ExecutionResult as CanonicalExecutionResult
from pysymex.scanner import scan_file as scanner_scan_file
from pysymex.execution.results.result import ExecutionResult
from pysymex.sandbox.bridge.types import create_bytecode_payload, create_function_payload


class TestToInt:
    """Tests for to_int conversion helper."""

    def test_int_passthrough(self) -> None:
        """Int value is returned as-is."""
        assert mod.to_int(42, 0) == 42

    def test_float_truncated(self) -> None:
        """Float is truncated to int."""
        assert mod.to_int(3.7, 0) == 3

    def test_bool_converted(self) -> None:
        """Bool is converted to 0 or 1."""
        assert mod.to_int(True, 0) == 1
        assert mod.to_int(False, 0) == 0

    def test_valid_string(self) -> None:
        """Numeric string is parsed."""
        assert mod.to_int("123", 0) == 123

    def test_invalid_string_returns_default(self) -> None:
        """Non-numeric string returns default."""
        assert mod.to_int("abc", 99) == 99

    def test_none_returns_default(self) -> None:
        """None returns the default."""
        assert mod.to_int(None, 77) == 77

    def test_list_returns_default(self) -> None:
        """Unsupported type returns default."""
        assert mod.to_int([1, 2], 55) == 55


class TestToFloat:
    """Tests for to_float conversion helper."""

    def test_float_passthrough(self) -> None:
        """Float value is returned as-is."""
        assert mod.to_float(3.14, 0.0) == 3.14

    def test_int_converted(self) -> None:
        """Int is converted to float."""
        assert mod.to_float(5, 0.0) == 5.0

    def test_bool_converted(self) -> None:
        """Bool is converted to 0.0 or 1.0."""
        assert mod.to_float(True, 0.0) == 1.0

    def test_valid_string(self) -> None:
        """Numeric string is parsed."""
        assert mod.to_float("2.5", 0.0) == 2.5

    def test_invalid_string_returns_default(self) -> None:
        """Non-numeric string returns default."""
        assert mod.to_float("abc", 9.9) == 9.9

    def test_none_returns_default(self) -> None:
        """None returns default."""
        assert mod.to_float(None, 1.1) == 1.1


class TestToBool:
    """Tests for to_bool conversion helper."""

    def test_bool_passthrough(self) -> None:
        """Bool returns itself."""
        assert mod.to_bool(True, False) is True
        assert mod.to_bool(False, True) is False

    def test_int_truthy(self) -> None:
        """Non-zero int is truthy."""
        assert mod.to_bool(1, False) is True
        assert mod.to_bool(0, True) is False

    def test_string_true_variants(self) -> None:
        """Various truthy strings are recognized."""
        for s in ("true", "True", "TRUE", "1", "yes", "on"):
            assert mod.to_bool(s, False) is True, f"Failed for {s!r}"

    def test_string_false_variants(self) -> None:
        """Various falsy strings are recognized."""
        for s in ("false", "False", "FALSE", "0", "no", "off"):
            assert mod.to_bool(s, True) is False, f"Failed for {s!r}"

    def test_invalid_string_returns_default(self) -> None:
        """Unrecognized string returns default."""
        assert mod.to_bool("maybe", True) is True

    def test_none_returns_default(self) -> None:
        """None returns default."""
        assert mod.to_bool(None, True) is True


class TestIsObjectMapping:
    """Tests for is_object_mapping TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """A dict is a Mapping."""
        assert mod.is_object_mapping({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """A list is not a Mapping."""
        assert mod.is_object_mapping([1, 2]) is False

    def test_none_returns_false(self) -> None:
        """None is not a Mapping."""
        assert mod.is_object_mapping(None) is False

        # The analyze/check/format functions invoke the full execution engine which
        # does not support the RESUME opcode on Python 3.13+. Mark them xfail so
        # the unit test file still provides full structural coverage of the API module.


def test_api_root_public_imports_resolve_to_canonical_owners() -> None:
    """Root public imports resolve to their canonical owners."""
    from pysymex.api.runtime import analyze as api_runtime_analyze
    from pysymex.api.runtime import scan_directory as api_runtime_scan_directory

    assert mod.analyze is api_runtime_analyze
    assert root_analyze is mod.analyze
    assert iscoroutinefunction(mod.analyze)
    assert mod.ExecutionConfig is CanonicalExecutionConfig
    assert mod.ExecutionResult is CanonicalExecutionResult
    assert mod.AnalysisConfig is ConfigAnalysisConfig
    assert root_scan_file is mod.scan_file
    assert root_scan_directory is mod.scan_directory
    assert mod.scan_file is scanner_scan_file
    assert mod.scan_directory is api_runtime_scan_directory
    assert iscoroutinefunction(mod.scan_directory)


def test_public_error_and_protocol_modules_are_api_owned() -> None:
    """Public error and protocol aliases live under pysymex.api."""
    from pysymex.api.errors import SandboxError
    from pysymex.api.protocols import DetectorProtocol, SolverProtocol
    from pysymex.sandbox import SandboxError as CanonicalSandboxError
    from pysymex.typing import DetectorProtocol as CanonicalDetectorProtocol
    from pysymex.typing import SolverProtocol as CanonicalSolverProtocol

    assert SandboxError is CanonicalSandboxError
    assert DetectorProtocol is CanonicalDetectorProtocol
    assert SolverProtocol is CanonicalSolverProtocol


def test_internal_packages_do_not_depend_on_public_api_namespace() -> None:
    """Implementation packages must not import the public API namespace."""
    allowed_prefixes = (
        Path("pysymex") / "api",
        Path("pysymex") / "cli",
    )
    allowed_files = {Path("pysymex") / "__init__.py"}
    offenders: list[str] = []
    for path in Path("pysymex").rglob("*.py"):
        if path in allowed_files or any(path.is_relative_to(prefix) for prefix in allowed_prefixes):
            continue
        text = path.read_text(encoding="utf-8")
        if "pysymex.api" in text:
            offenders.append(str(path))

    assert offenders == []


def test_execution_package_does_not_reexport_user_api_helpers() -> None:
    """User-level helpers belong to pysymex.api and the root package."""
    import pysymex.execution as execution

    for name in ("analyze", "analyze_code", "quick_check"):
        with pytest.raises(AttributeError):
            getattr(execution, name)


def test_executors_package_does_not_export_config_or_results() -> None:
    """Config and result types live outside the executor package."""
    import pysymex.execution.executors as executors

    for name in ("ExecutionConfig", "ExecutionResult"):
        with pytest.raises(AttributeError):
            getattr(executors, name)


def test_format_issues_empty_list() -> None:
    """format_issues handles empty list."""
    text = mod.format_issues([], "text")
    assert text == ""


def test_format_issues_json_empty_list() -> None:
    """format_issues JSON handles empty list."""
    import json

    text = mod.format_issues([], "json")
    parsed = json.loads(text)
    assert parsed == []


def test_analyze_file_defaults_to_sandbox_without_host_module_exec(
    tmp_path: Path,
) -> None:
    """Default file analysis must not execute module initialization on the host."""
    target = tmp_path / "host_exec_guard.py"
    target.write_text(
        "raise RuntimeError('host module initialization executed')\n"
        "def target(x: int) -> int:\n"
        "    return x + 1\n",
        encoding="utf-8",
    )

    namespace: dict[str, object] = {}
    exec(
        compile("def target(x: int) -> int:\n    return x + 1\n", str(target), "exec"),
        namespace,
    )
    func_obj = namespace["target"]
    assert callable(func_obj)
    function_payload = json.loads(create_function_payload(func_obj, target_name="target").decode())
    assert isinstance(function_payload, dict)
    module_code = compile("def target(x: int) -> int:\n    return x + 1\n", str(target), "exec")
    payload = json.loads(create_bytecode_payload(module_code).decode())
    assert isinstance(payload, dict)
    payload["kind"] = "pysymex.module"
    payload["targets"] = {"target": function_payload["target"]}

    def fake_analyze(
        func: object,
        symbolic_args: Mapping[str, str] | None = None,
        **kwargs: object,
    ) -> ExecutionResult:
        _ = symbolic_args
        _ = kwargs
        assert callable(func)
        assert getattr(func, "__name__") == "target"
        return ExecutionResult(function_name="target", source_file=str(target))

    def mock_run_json_worker(
        worker_script: str,
        **kwargs: object,
    ) -> tuple[dict[str, object], str, str]:
        _ = worker_script
        _ = kwargs
        return ({"ok": True, "payload": payload}, "", "")

    from pysymex.api.file import analyze_file_from_path

    with patch("pysymex.sandbox.bridge.module._run_json_worker", side_effect=mock_run_json_worker):
        result = analyze_file_from_path(fake_analyze, target, "target")

    assert result.function_name == "target"


def test_analyze_file_rejects_no_sandbox_mode(tmp_path: Path) -> None:
    """File analysis must not expose a host-process execution fallback."""
    target = tmp_path / "trusted_target.py"
    target.write_text(
        "def target(x: int) -> int:\n    return x + 1\n",
        encoding="utf-8",
    )

    def fake_analyze(
        func: object,
        symbolic_args: Mapping[str, str] | None = None,
        **kwargs: object,
    ) -> ExecutionResult:
        _ = symbolic_args
        _ = kwargs
        assert callable(func)
        return ExecutionResult(function_name="target", source_file=str(target))

    from pysymex.api.file import analyze_file_from_path

    with pytest.raises(ValueError, match="Disabling sandboxed target loading is unsupported"):
        analyze_file_from_path(fake_analyze, target, "target", sandbox=False)
