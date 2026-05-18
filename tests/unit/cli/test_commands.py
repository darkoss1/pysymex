import argparse
import json
from pathlib import Path
from unittest.mock import patch
import pysymex.cli.commands


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
    with patch("pysymex.cli.commands.Path.exists", return_value=False):
        assert pysymex.cli.commands.cmd_analyze(args) == 1


def test_cmd_benchmark() -> None:
    """Test cmd_benchmark behavior."""
    args = argparse.Namespace(output=None, baseline=None, format="text", iterations=1)
    with patch("pysymex.cli.commands.cast") as mock_cast:

        def mock_func(**kwargs: object) -> int:
            return 0

        mock_cast.return_value = mock_func
        assert pysymex.cli.commands.cmd_benchmark(args) == 0


def test_generate_completion() -> None:
    """Test generate_completion behavior."""
    assert pysymex.cli.commands.generate_completion("bash") == 0
    assert pysymex.cli.commands.generate_completion("unknown") == 1


def test_cmd_check() -> None:
    """Test cmd_check behavior."""
    args = argparse.Namespace(paths=["."], fail_on="high", sarif=None, verbose=False)
    with patch("pysymex.cli.commands.cast") as mock_cast:

        def mock_func(*, files: object, fail_on: object, sarif_output: object) -> int:
            return 0

        mock_cast.return_value = mock_func
        assert pysymex.cli.commands.cmd_check(args) == 0


def test_cmd_verify() -> None:
    """Test cmd_verify behavior."""
    args = argparse.Namespace(file="fake.py")
    with patch("pysymex.cli.commands.Path.exists", return_value=False):
        assert pysymex.cli.commands.cmd_verify(args) == 1


def test_cmd_verify_returns_success_for_verified_contract() -> None:
    """Test cmd_verify returns success when all selected contracts verify."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="safe_positive_identity",
        sandbox=False,
        verbose=False,
        format="text",
        output=None,
    )

    assert pysymex.cli.commands.cmd_verify(args) == 0


def test_cmd_verify_sandbox_allows_future_annotations() -> None:
    """Sandboxed verify can load normal modules using future annotations."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="safe_positive_identity",
        sandbox=True,
        verbose=False,
        format="text",
        output=None,
    )

    assert pysymex.cli.commands.cmd_verify(args) == 0


def test_cmd_verify_returns_failure_for_contract_violation() -> None:
    """Test cmd_verify returns failure when selected contracts are violated."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="violates_postcondition",
        sandbox=False,
        verbose=False,
        format="text",
        output=None,
    )

    assert pysymex.cli.commands.cmd_verify(args) == 1


def test_cmd_verify_returns_failure_for_unknown_contract() -> None:
    """Test cmd_verify returns failure when selected contracts cannot be checked."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="unknown_postcondition",
        sandbox=False,
        verbose=False,
        format="text",
        output=None,
    )

    assert pysymex.cli.commands.cmd_verify(args) == 1


def test_cmd_verify_all_functions_returns_failure_when_any_contract_fails() -> None:
    """Test cmd_verify aggregates findings when verifying all contracted functions."""
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function=None,
        sandbox=False,
        verbose=False,
        format="text",
        output=None,
    )

    assert pysymex.cli.commands.cmd_verify(args) == 1


def test_cmd_verify_repeated_file_load_does_not_reuse_stale_contracts() -> None:
    """Test repeated CLI loads do not leak old contracts into fresh functions."""
    path = _contracts_cli_cases_path()

    assert (
        pysymex.cli.commands.cmd_verify(
            argparse.Namespace(
                file=path,
                function="violates_postcondition",
                sandbox=False,
                verbose=False,
                format="text",
                output=None,
            )
        )
        == 1
    )
    assert (
        pysymex.cli.commands.cmd_verify(
            argparse.Namespace(
                file=path,
                function="unknown_postcondition",
                sandbox=False,
                verbose=False,
                format="text",
                output=None,
            )
        )
        == 1
    )
    assert (
        pysymex.cli.commands.cmd_verify(
            argparse.Namespace(
                file=path,
                function="safe_positive_identity",
                sandbox=False,
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
    args = argparse.Namespace(
        file=target,
        function="safe_identity",
        sandbox=False,
        verbose=False,
        format="text",
        output=None,
    )

    assert pysymex.cli.commands.cmd_verify(args) == 0


def test_cmd_verify_writes_unified_json_report(tmp_path: Path) -> None:
    """Verify should use the shared CLI formatter/output path."""
    output_path = tmp_path / "verify.json"
    args = argparse.Namespace(
        file=_contracts_cli_cases_path(),
        function="safe_positive_identity",
        sandbox=False,
        verbose=False,
        format="json",
        output=str(output_path),
    )

    assert pysymex.cli.commands.cmd_verify(args) == 0

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["mode"] == "verify"
    assert data["functions_verified"] == 1
    assert data["total_issues"] == 0
    assert data["results"][0]["function_name"] == "safe_positive_identity"


def test_cmd_concolic() -> None:
    """Test cmd_concolic behavior."""
    args = argparse.Namespace(file="fake.py")
    with patch("pysymex.cli.commands.Path.exists", return_value=False):
        assert pysymex.cli.commands.cmd_concolic(args) == 1


def _contracts_cli_cases_path() -> Path:
    return Path(__file__).resolve().parents[2] / "repro" / "contracts_cli_cases.py"
