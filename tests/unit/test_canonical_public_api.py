"""Behavioral contract for the canonical user-facing interface."""

from __future__ import annotations

import ast
import json
import types
from pathlib import Path
from typing import cast

import pytest

import pysymex.contracts
import pysymex.diagnostics
import pysymex.issues
import pysymex.reports
import pysymex.results
import pysymex.scan
import pysymex.verify
import pysymex._internal.api.scan


ADAPTER_MODULES = (
    pysymex.issues,
    pysymex.reports,
    pysymex.results,
    pysymex.scan,
)


def test_workflow_families_are_real_module_namespaces() -> None:
    for namespace in (
        pysymex.contracts,
        pysymex.diagnostics,
        pysymex.issues,
        pysymex.reports,
        pysymex.results,
        pysymex.scan,
        pysymex.verify,
    ):
        assert isinstance(namespace, types.ModuleType)


def test_public_results_exposes_expected_types() -> None:
    expected_attrs = (
        "AnalysisOutcome",
        "ExecutionResult",
        "OutcomeEvidence",
        "OutcomeSubreason",
        "ScanResult",
        "TerminationProof",
        "TerminationStatus",
        "VerifiedExecutionResult",
    )
    for attr in expected_attrs:
        assert hasattr(pysymex.results, attr)
        assert getattr(pysymex.results, attr) is not None


def test_public_modules_expose_intentional_exports() -> None:
    expected_exports = {
        pysymex.scan: {"file", "directory", "path"},
        pysymex.verify: {"run", "contracts", "arithmetic", "termination"},
        pysymex.reports: {
            "render",
            "result",
            "scan",
            "verification",
            "issues",
            "save",
            "json",
            "markdown",
            "sarif",
            "text",
        },
        pysymex.results: {"data", "count", "clean", "degraded"},
        pysymex.issues: {"data", "records", "render", "count", "found"},
        pysymex.diagnostics: {"get", "configure", "LogCategory", "LogLevel", "Logger"},
        pysymex.contracts: {"requires", "ensures", "assigns", "pure", "forall"},
    }
    for module, names in expected_exports.items():
        exported = set(module.__all__)
        assert names <= exported


def test_public_exports_do_not_include_underscore_style_helper_names() -> None:
    modules = (
        pysymex.contracts,
        pysymex.diagnostics,
        pysymex.issues,
        pysymex.reports,
        pysymex.results,
        pysymex.scan,
        pysymex.verify,
    )
    for module in modules:
        exported = set(module.__all__)
        assert not any(name.startswith("to_") for name in exported)
        assert not any(name.startswith("is_") for name in exported)
        assert not any(name.startswith("has_") for name in exported)
        assert not any(name.endswith("_") for name in exported)


def test_public_api_adapters_do_not_own_runtime_logic() -> None:
    allowed_statements = (
        ast.Expr,
        ast.ImportFrom,
        ast.Assign,
    )
    for module in ADAPTER_MODULES:
        module_file = module.__file__
        assert module_file is not None
        tree = ast.parse(Path(module_file).read_text(encoding="utf-8"))
        body = [node for node in tree.body if not _is_future_annotations_import(node)]
        assert all(isinstance(node, allowed_statements) for node in body)
        assert not any(isinstance(node, (ast.FunctionDef, ast.ClassDef)) for node in body)
        for node in body:
            if isinstance(node, ast.ImportFrom):
                assert node.module is not None
                assert node.module.startswith("pysymex._internal.api.")


def _is_future_annotations_import(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
    )


def test_scan_path_selects_file_or_directory_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_file = tmp_path / "target.py"
    target_file.write_text("def f():\n    return 1\n", encoding="utf-8")
    target_dir = tmp_path / "pkg"
    target_dir.mkdir()
    calls: list[tuple[str, object, dict[str, object]]] = []

    def fake_file(path: object, **options: object) -> str:
        calls.append(("file", path, options))
        return "file-result"

    def fake_directory(path: object, **options: object) -> list[str]:
        calls.append(("directory", path, options))
        return ["directory-result"]

    monkeypatch.setattr(pysymex._internal.api.scan, "file", fake_file)
    monkeypatch.setattr(pysymex._internal.api.scan, "directory", fake_directory)

    assert pysymex.scan.path(target_file, use_sandbox=False) == "file-result"
    assert pysymex.scan.path(target_dir, pattern="*.py") == ["directory-result"]
    assert calls[0] == ("file", target_file, {"use_sandbox": False})
    assert calls[1] == ("directory", target_dir, {"pattern": "*.py"})

    with pytest.raises(TypeError, match="file scans"):
        pysymex.scan.path(target_file, pattern="*.py")
    with pytest.raises(TypeError, match="directory scans"):
        pysymex.scan.path(target_dir, confirm_issues=True)


def test_public_issue_and_result_helpers_cover_workflow_outputs() -> None:
    arithmetic_issue = pysymex.issues.ArithmeticIssue(
        kind="division_by_zero",
        expression="x // y",
        message="possible division by zero",
        line_number=3,
    )
    verified = pysymex.results.VerifiedExecutionResult(
        function_name="risky",
        source_file="example.py",
        arithmetic_issues=[arithmetic_issue],
    )
    scan_result = pysymex.results.ScanResult(
        file_path="example.py",
        timestamp="2026-06-28T00:00:00",
        issues=[{"kind": "DIVISION_BY_ZERO", "message": "possible zero divisor"}],
        paths_explored=2,
    )

    assert pysymex.issues.found([arithmetic_issue])
    assert pysymex.issues.data(arithmetic_issue)["kind"] == "division_by_zero"
    assert "possible division" in pysymex.issues.render(arithmetic_issue)
    assert pysymex.results.count(verified) == 1
    assert pysymex.results.count(scan_result) == 1
    assert not pysymex.results.clean(verified)
    assert not pysymex.results.clean([scan_result])

    serialized_verified = pysymex.results.data(verified)
    assert serialized_verified["kind"] == "verified_execution"
    assert serialized_verified["arithmetic_issues"]
    serialized_scan = pysymex.results.data([scan_result])
    assert serialized_scan["summary"] == {
        "files": 1,
        "total_issues": 1,
        "files_with_issues": 1,
        "errors": 0,
        "degraded": 0,
    }


def test_public_reports_render_public_workflow_results() -> None:
    scan_result = pysymex.results.ScanResult(
        file_path="example.py",
        timestamp="2026-06-28T00:00:00",
        issues=[{"kind": "DIVISION_BY_ZERO", "message": "possible zero divisor"}],
        paths_explored=2,
    )
    arithmetic_issue = pysymex.issues.ArithmeticIssue(
        kind="division_by_zero",
        expression="x // y",
        message="possible division by zero",
    )
    verified = pysymex.results.VerifiedExecutionResult(
        function_name="risky",
        arithmetic_issues=[arithmetic_issue],
    )

    text_report = pysymex.reports.scan(scan_result)
    assert "example.py" in text_report
    assert "possible zero divisor" in text_report

    json_report = json.loads(pysymex.reports.json(scan_result))
    assert json_report["file"] == "example.py"
    assert json_report["issues"][0]["message"] == "possible zero divisor"

    markdown_report = pysymex.reports.markdown(verified)
    assert "# pysymex verification report" in markdown_report
    assert "possible division by zero" in markdown_report

    html_report = pysymex.reports.render(scan_result, "html")
    assert "<!doctype html>" in html_report
    assert "possible zero divisor" in html_report

    sarif_report = pysymex.reports.sarif(scan_result)
    assert sarif_report["version"] == "2.1.0"
    runs = cast("list[dict[str, object]]", sarif_report["runs"])
    first_run = runs[0]
    assert first_run["results"]


def test_removed_flat_workflows_are_not_root_attributes() -> None:
    for legacy_name in (
        "check",
        "check_arithmetic",
        "check_contracts",
        "configure_logging",
        "format_issues",
        "format_result",
        "get_logger",
        "load_config",
        "prove_termination",
        "scan_directory",
        "scan_file",
    ):
        assert not hasattr(pysymex, legacy_name)


def test_removed_public_implementation_packages_do_not_exist() -> None:
    from pathlib import Path

    package_root = Path(pysymex.__file__).parent
    for removed_name in (
        "analysis",
        "api",
        "benchmarks",
        "cli",
        "core",
        "execution",
        "limits",
        "logger",
        "models",
        "profiling",
        "reporting",
        "sandbox",
        "scanner",
        "stats",
        "tracing",
        "typing",
        "utils",
    ):
        assert not (package_root / removed_name).exists()

    for removed_module in ("deps.py", "guards.py", "lazy.py", "pathing.py"):
        assert not (package_root / removed_module).exists()


def test_removed_public_contracts_implementation_packages_do_not_exist() -> None:
    from pathlib import Path

    contracts_root = Path(pysymex.__file__).parent / "contracts"
    for removed_name in (
        "binding",
        "callable",
        "decorator",
        "effects",
        "formula",
        "frontend",
        "invariants",
        "ir",
        "obligations",
        "quantifiers",
        "reports",
        "runtime",
        "solver",
        "value",
    ):
        assert not (contracts_root / removed_name).exists()

    for removed_module in ("compiler.py", "verifier.py"):
        assert not (contracts_root / removed_module).exists()
