import argparse
import importlib.util
import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest

from pysymex._internal.benchmarks.suite.runner import BenchmarkRunResult
from pysymex._internal.benchmarks.suite.types import (
    BenchmarkCategory,
    BenchmarkResult,
    RegressionResult,
)
from pysymex._internal.cli.commands.benchmark import cmd_benchmark
from pysymex._internal.cli.commands.completion import generate_completion
from pysymex._internal.cli.commands.scan.command import cmd_scan
from pysymex._internal.cli.commands.verify import cmd_verify
from pysymex._internal.execution.executors.verified.types import (
    VerifiedExecutionResult,
)


def test_cmd_benchmark() -> None:
    """Test cmd_benchmark behavior."""
    args = argparse.Namespace(
        output=None,
        baseline=None,
        format="text",
        iterations=1,
        mode=None,
        category=None,
        warmup=0,
        case=None,
        list=False,
        threshold=10.0,
    )
    with patch(
        "pysymex._internal.benchmarks.suite.runner.run_benchmarks",
        return_value=BenchmarkRunResult(exit_code=0, results=[], inventory=[], regressions=[]),
    ):
        assert cmd_benchmark(args) == 0


def test_cmd_benchmark_lists_cases_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    args = argparse.Namespace(
        output=None,
        baseline=None,
        format="text",
        iterations=1,
        mode=None,
        category=None,
        warmup=0,
        case=None,
        list=True,
        threshold=10.0,
    )

    with patch(
        "pysymex._internal.benchmarks.suite.runner.run_benchmarks",
        return_value=BenchmarkRunResult(
            exit_code=0,
            results=[],
            inventory=["arith_solver", "scanner_scan"],
            regressions=[],
        ),
    ):
        assert cmd_benchmark(args) == 0

    output = capsys.readouterr().out
    assert "Benchmark Cases" in output
    assert "arith_solver" in output
    assert "scanner_scan" in output


@pytest.mark.parametrize(
    ("output_format", "expected"),
    [
        ("text", "pysymex Benchmark Results"),
        ("json", '"name": "formatters"'),
        ("markdown", "| formatters | REPORTING | completed |"),
    ],
)
def test_cmd_benchmark_prints_report_when_no_output_file(
    output_format: str,
    expected: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = argparse.Namespace(
        output=None,
        baseline=None,
        format=output_format,
        iterations=1,
        mode=None,
        category=None,
        warmup=0,
        case="formatters",
        list=False,
        threshold=10.0,
    )
    result = BenchmarkResult(
        name="formatters",
        category=BenchmarkCategory.REPORTING,
        elapsed_seconds=0.1,
        mean_seconds=0.1,
    )

    with patch(
        "pysymex._internal.benchmarks.suite.runner.run_benchmarks",
        return_value=BenchmarkRunResult(
            exit_code=0,
            results=[result],
            inventory=["formatters"],
            regressions=[],
        ),
    ):
        assert cmd_benchmark(args) == 0

    assert expected in capsys.readouterr().out


def test_cmd_benchmark_prints_empty_filter_message(capsys: pytest.CaptureFixture[str]) -> None:
    args = argparse.Namespace(
        output=None,
        baseline=None,
        format="text",
        iterations=1,
        mode=None,
        category=None,
        warmup=0,
        case="not_a_case",
        list=False,
        threshold=10.0,
    )

    with patch(
        "pysymex._internal.benchmarks.suite.runner.run_benchmarks",
        return_value=BenchmarkRunResult(exit_code=0, results=[], inventory=[], regressions=[]),
    ):
        assert cmd_benchmark(args) == 0

    assert "No benchmark cases matched the requested filters." in capsys.readouterr().out


def test_cmd_benchmark_prints_text_baseline_comparison(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = argparse.Namespace(
        output=None,
        baseline="baseline.json",
        format="text",
        iterations=1,
        mode=None,
        category=None,
        warmup=0,
        case="arith_solver",
        list=False,
        threshold=10.0,
    )
    result = BenchmarkResult(
        name="arith_solver",
        category=BenchmarkCategory.SOLVING,
        elapsed_seconds=0.2,
        mean_seconds=0.2,
    )
    regression = RegressionResult(
        benchmark_name="arith_solver",
        baseline_mean=0.1,
        current_mean=0.2,
        change_percent=100.0,
        is_regression=True,
        threshold_percent=10.0,
    )

    with patch(
        "pysymex._internal.benchmarks.suite.runner.run_benchmarks",
        return_value=BenchmarkRunResult(
            exit_code=1,
            results=[result],
            inventory=["arith_solver"],
            regressions=[regression],
        ),
    ):
        assert cmd_benchmark(args) == 1

    output = capsys.readouterr().out
    assert "pysymex Benchmark Results" in output
    assert "Benchmark Comparison Report" in output
    assert "arith_solver" in output


def test_generate_completion() -> None:
    """Test generate_completion behavior."""
    assert generate_completion("bash") == 0
    assert generate_completion("unknown") == 1


def test_generate_completion_lists_no_sandbox(capsys: pytest.CaptureFixture[str]) -> None:
    assert generate_completion("bash") == 0

    output = capsys.readouterr().out
    assert "--no-sandbox" in output
    assert "--max-depth" in output
    assert "--profile" in output
    assert "--profile-mode" in output
    assert "--profile-sample-interval-ms" in output
    assert "--profile-output-dir" in output
    assert "--profile-baseline" in output


def test_cmd_scan_profile_does_not_enable_trace_implicitly() -> None:
    """Profiling should not turn on execution tracing unless explicitly requested."""
    args = argparse.Namespace(
        path="missing.py",
        profile=True,
        profile_baseline=None,
        stats=False,
        trace=False,
        verbose=False,
    )

    with patch("pathlib.Path.exists", return_value=False):
        assert cmd_scan(args) == 1

    assert args.stats is True
    assert args.trace is False


def test_cmd_verify() -> None:
    """Test cmd_verify behavior."""
    args = argparse.Namespace(file="fake.py")
    with patch("pathlib.Path.exists", return_value=False):
        assert cmd_verify(args) == 1


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

    with patch("pysymex._internal.cli.commands.verify.load_function_for_cli", return_value=add):
        assert cmd_verify(args) == 0


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
            "pysymex._internal.sandbox.runner.check_linux_namespace_support",
            return_value=False,
        ),
        patch(
            "pysymex._internal.sandbox.runner.check_windows_appcontainer_support",
            return_value=False,
        ),
    ):
        assert cmd_verify(args) == 1


def test_cmd_verify_sandbox_verifies_all_contracts_when_no_function_specified() -> None:
    """Sandboxed verification runs auto-discovery when no function is selected."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function=None,
        _sandbox_dispatch=True,
        verbose=False,
        format="text",
        output=None,
    )

    from unittest.mock import MagicMock
    from pysymex._internal.sandbox.bridge.blobs import ModuleBlob

    mock_blob = MagicMock(spec=ModuleBlob)
    mock_blob.function_names.return_value = ("safe_positive_identity",)
    mock_blob.get_function.return_value = _contract_function("safe_positive_identity")

    with patch("pysymex._internal.sandbox.bridge.module.extract.extract_module", return_value=mock_blob):
        assert _run_cmd_verify_with_contract_loader(args) == 0


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


def test_cmd_verify_fails_when_no_contract_functions_found() -> None:
    """Test cmd_verify returns failure when no contract-decorated functions exist in the file."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function=None,
        _sandbox_dispatch=True,
        verbose=False,
        format="text",
        output=None,
    )

    from unittest.mock import MagicMock
    from pysymex._internal.sandbox.bridge.blobs import ModuleBlob

    mock_blob = MagicMock(spec=ModuleBlob)
    mock_blob.function_names.return_value = ("no_contracts_function",)
    mock_blob.get_function.return_value = _contract_function("no_contracts_function")

    with patch("pysymex._internal.sandbox.bridge.module.extract.extract_module", return_value=mock_blob):
        assert _run_cmd_verify_with_contract_loader(args) == 1


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

    with patch(
        "pysymex._internal.cli.commands.verify.load_function_for_cli", return_value=safe_identity
    ):
        assert cmd_verify(args) == 0


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
    assert data["mode"] == "contracts"
    assert data["functions_verified"] == 1
    assert data["total_issues"] == 0
    assert data["results"][0]["function_name"] == "safe_positive_identity"


def test_cmd_verify_forwards_symbolic_args(tmp_path: Path) -> None:
    """Verify should forward declared symbolic argument types."""
    observed: dict[str, object] = {}

    def fake_verify(
        func: Callable[..., object],
        **config_overrides: object,
    ) -> VerifiedExecutionResult:
        observed["function"] = func
        observed["config_overrides"] = config_overrides
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
        args=[" value : int ", "flag:bool"],
        verbose=False,
        format="json",
        output=str(tmp_path / "verify.json"),
    )

    with (
        patch("pysymex._internal.cli.commands.verify.load_function_for_cli", return_value=target),
        patch("pysymex._internal.execution.executors.verified.api.verify", new=fake_verify),
    ):
        assert cmd_verify(args) == 0

    assert observed["function"] is target
    assert observed["config_overrides"] == {
        "symbolic_args": {"value": "int", "flag": "bool"},
        "check_preconditions": True,
        "check_postconditions": True,
        "verbose": False,
    }


def test_cmd_verify_rejects_malformed_symbolic_args(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify should not silently ignore malformed symbolic argument specs."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="target",
        _sandbox_dispatch=True,
        args=["value:int", "invalid"],
        verbose=False,
        format="json",
        output=str(tmp_path / "verify.json"),
    )

    assert cmd_verify(args) == 1

    captured = capsys.readouterr()
    assert "symbolic arguments must use NAME:TYPE" in captured.err
    assert not Path(args.output).exists()


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

    with patch(
        "pysymex._internal.cli.commands.verify.load_function_for_cli", side_effect=load_function
    ):
        return cmd_verify(args)


def test_cmd_verify_warns_when_no_contracts_detected(capsys: pytest.CaptureFixture[str]) -> None:
    """Test cmd_verify prints a warning when no contracts are checked on the function."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="no_contracts_function",
        _sandbox_dispatch=True,
        verbose=False,
        format="text",
        output=None,
    )

    assert _run_cmd_verify_with_contract_loader(args) == 0
    captured = capsys.readouterr()
    assert "No contract decorators detected or checked" in captured.err


def test_cmd_verify_directory_support(tmp_path: Path) -> None:
    """Test cmd_verify successfully runs on a directory and verifies all contract functions in all files."""
    dir_path = tmp_path / "pkg"
    dir_path.mkdir()

    from unittest.mock import MagicMock
    from pysymex._internal.sandbox.bridge.blobs import ModuleBlob

    mock_blob = MagicMock(spec=ModuleBlob)
    mock_blob.function_names.return_value = ("safe_positive_identity",)
    mock_blob.get_function.return_value = _contract_function("safe_positive_identity")

    args = argparse.Namespace(
        file=dir_path,
        function=None,
        _sandbox_dispatch=True,
        verbose=False,
        format="text",
        output=None,
    )

    (dir_path / "file1.py").write_text("def safe_positive_identity(x): return x\n", encoding="utf-8")

    with patch("pysymex._internal.sandbox.bridge.module.extract.extract_module", return_value=mock_blob):
        assert _run_cmd_verify_with_contract_loader(args) == 0


def test_cmd_verify_directory_rejects_function_flag(tmp_path: Path) -> None:
    """Test cmd_verify rejects specifying function name when verifying a directory."""
    args = argparse.Namespace(
        file=tmp_path,
        function="some_func",
        _sandbox_dispatch=True,
        verbose=False,
        format="text",
        output=None,
    )
    assert cmd_verify(args) == 1
