import argparse
import importlib.util
import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest

import pysymex.cli.commands
from pysymex.execution.executors.verified.types import (
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
)


def test_cmd_analyze() -> None:
    """Test cmd_analyze behavior."""
    args = argparse.Namespace(
        file="fake.py",
        function="f",
        args=[],
        format="text",
        output=None,
        max_paths=10,
        timeout=10,
        verbose=False,
    )
    with patch("pathlib.Path.exists", return_value=False):
        assert pysymex.cli.commands.cmd_analyze(args) == 1


def test_cmd_benchmark() -> None:
    """Test cmd_benchmark behavior."""
    args = argparse.Namespace(output=None, baseline=None, format="text", iterations=1)
    with patch("pysymex.cli.commands.benchmark.cast") as mock_cast:

        def mock_func(**kwargs: object) -> int:
            return 0

        mock_cast.return_value = mock_func
        assert pysymex.cli.commands.cmd_benchmark(args) == 0


def test_generate_completion() -> None:
    """Test generate_completion behavior."""
    assert pysymex.cli.commands.generate_completion("bash") == 0
    assert pysymex.cli.commands.generate_completion("unknown") == 1


def test_generate_completion_lists_no_sandbox(capsys: pytest.CaptureFixture[str]) -> None:
    assert pysymex.cli.commands.generate_completion("bash") == 0

    output = capsys.readouterr().out
    assert "--no-sandbox" in output


def test_cmd_check() -> None:
    """Test cmd_check behavior."""
    args = argparse.Namespace(paths=["."], fail_on="high", sarif=None, verbose=False)
    with patch("pysymex.cli.commands.check.cast") as mock_cast:

        def mock_func(*, files: object, fail_on: object, sarif_output: object) -> int:
            return 0

        mock_cast.return_value = mock_func
        assert pysymex.cli.commands.cmd_check(args) == 0


def test_cmd_verify() -> None:
    """Test cmd_verify behavior."""
    args = argparse.Namespace(file="fake.py")
    with patch("pathlib.Path.exists", return_value=False):
        assert pysymex.cli.commands.cmd_verify(args) == 1


def test_cmd_verify_returns_success_for_verified_contract() -> None:
    """Test cmd_verify returns success when all selected contracts verify."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="safe_positive_identity",
        verbose=False,
        format="text",
        output=None,
    )

    assert _run_cmd_verify_with_contract_loader(args) == 0


def test_cmd_verify_does_not_report_bounded_overflow_for_python_integer_addition() -> None:
    """Ordinary CLI verification follows Python arbitrary-precision integer semantics."""

    def add(left: int, right: int) -> int:
        return left + right

    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="add",
        verbose=False,
        format="text",
        output=None,
    )

    with patch("pysymex.cli.commands.verify.load_function_for_cli", return_value=add):
        assert pysymex.cli.commands.cmd_verify(args) == 0


def test_cmd_verify_sandbox_fails_closed_without_strong_backend() -> None:
    """Sandboxed verify must not silently downgrade when no strong backend exists."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="safe_positive_identity",
        verbose=False,
        format="text",
        output=None,
    )

    with (
        patch(
            "pysymex.sandbox.runner.check_linux_namespace_support",
            return_value=False,
        ),
        patch(
            "pysymex.sandbox.runner.check_windows_appcontainer_support",
            return_value=False,
        ),
        patch("pysymex.sandbox.runner.check_wasm_support", return_value=False),
    ):
        assert pysymex.cli.commands.cmd_verify(args) == 1


def test_cmd_verify_sandbox_requires_specific_function_for_all_contracts() -> None:
    """Sandboxed all-contract verification must fail closed instead of host-executing a module."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function=None,
        verbose=False,
        format="text",
        output=None,
    )

    assert pysymex.cli.commands.cmd_verify(args) == 1


def test_cmd_verify_returns_failure_for_contract_violation() -> None:
    """Test cmd_verify returns failure when selected contracts are violated."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="violates_postcondition",
        verbose=False,
        format="text",
        output=None,
    )

    assert _run_cmd_verify_with_contract_loader(args) == 1


def test_cmd_verify_returns_failure_for_unknown_contract() -> None:
    """Test cmd_verify returns failure when selected contracts cannot be checked."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="unknown_postcondition",
        verbose=False,
        format="text",
        output=None,
    )

    assert _run_cmd_verify_with_contract_loader(args) == 1


def test_cmd_verify_all_functions_requires_sandboxed_function_selection() -> None:
    """Verify no longer host-executes a module to discover all contracts."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function=None,
        verbose=False,
        format="text",
        output=None,
    )

    assert pysymex.cli.commands.cmd_verify(args) == 1


def test_cmd_verify_repeated_file_load_does_not_reuse_stale_contracts() -> None:
    """Test repeated CLI loads do not leak old contracts into fresh functions."""
    path = _contracts_cli_cases_path()

    assert (
        _run_cmd_verify_with_contract_loader(
            argparse.Namespace(
                file=path,
                function="violates_postcondition",
                verbose=False,
                format="text",
                output=None,
            )
        )
        == 1
    )
    assert (
        _run_cmd_verify_with_contract_loader(
            argparse.Namespace(
                file=path,
                function="unknown_postcondition",
                verbose=False,
                format="text",
                output=None,
            )
        )
        == 1
    )
    assert (
        _run_cmd_verify_with_contract_loader(
            argparse.Namespace(
                file=path,
                function="safe_positive_identity",
                verbose=False,
                format="text",
                output=None,
            )
        )
        == 0
    )


def test_cmd_verify_does_not_execute_main_guard(tmp_path: Path) -> None:
    """Loading a verification target should not run script entrypoint code."""
    target = tmp_path / "main_guard_case.py"
    target.write_text(
        "from pysymex.contracts import requires, ensures\n"
        "\n"
        "@requires('x > 0')\n"
        "@ensures('__result__ > 0')\n"
        "def safe_identity(x: int) -> int:\n"
        "    return x\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    raise RuntimeError('main guard executed')\n",
        encoding="utf-8",
    )
    from pysymex.contracts import ensures, requires

    @requires("x > 0")
    @ensures("__result__ > 0")
    def safe_identity(x: int) -> int:
        return x

    args = argparse.Namespace(
        file=target,
        function="safe_identity",
        verbose=False,
        format="text",
        output=None,
    )

    with patch("pysymex.cli.commands.verify.load_function_for_cli", return_value=safe_identity):
        assert pysymex.cli.commands.cmd_verify(args) == 0


def test_cmd_verify_writes_unified_json_report(tmp_path: Path) -> None:
    """Verify should use the shared CLI formatter/output path."""
    output_path = tmp_path / "verify.json"
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="safe_positive_identity",
        verbose=False,
        format="json",
        output=str(output_path),
    )

    assert _run_cmd_verify_with_contract_loader(args) == 0

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["mode"] == "verify"
    assert data["functions_verified"] == 1
    assert data["total_issues"] == 0
    assert data["results"][0]["function_name"] == "safe_positive_identity"


def test_cmd_verify_forwards_symbolic_args(tmp_path: Path) -> None:
    """Verify should forward only well-formed declared symbolic argument types."""
    observed: dict[str, object] = {}

    class _Executor:
        def __init__(self, config: object) -> None:
            observed["config"] = config

        def execute_function(
            self,
            func: Callable[..., object],
            symbolic_args: dict[str, str] | None = None,
        ) -> VerifiedExecutionResult:
            observed["function"] = func
            observed["executed_args"] = symbolic_args
            return VerifiedExecutionResult(
                function_name="target",
                paths_explored=1,
                paths_completed=1,
            )

    def target() -> None:
        pass

    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="target",
        _sandbox_dispatch=True,
        args=[" value : int ", "flag:bool", "invalid"],
        verbose=False,
        format="json",
        output=str(tmp_path / "verify.json"),
    )

    with (
        patch("pysymex.cli.commands.verify.load_function_for_cli", return_value=target),
        patch("pysymex.execution.executors.verified.executor.VerifiedExecutor", new=_Executor),
    ):
        assert pysymex.cli.commands.cmd_verify(args) == 0

    assert observed["function"] is target
    config = observed["config"]
    assert isinstance(config, VerifiedExecutionConfig)
    assert config.symbolic_args == {"value": "int", "flag": "bool"}
    assert observed["executed_args"] == {"value": "int", "flag": "bool"}


def _contracts_cli_cases_path() -> Path:
    return Path(__file__).resolve().parents[2] / "repro" / "contracts_cli_cases.py"


def _contracts_cli_module() -> object:
    path = _contracts_cli_cases_path()
    spec = importlib.util.spec_from_file_location("contracts_cli_cases_for_tests", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _contract_function(name: str) -> object:
    return getattr(_contracts_cli_module(), name)


def _run_cmd_verify_with_contract_loader(args: argparse.Namespace) -> int:
    def load_function(_filepath: Path, function_name: str) -> object:
        return _contract_function(function_name)

    with patch("pysymex.cli.commands.verify.load_function_for_cli", side_effect=load_function):
        return pysymex.cli.commands.cmd_verify(args)
