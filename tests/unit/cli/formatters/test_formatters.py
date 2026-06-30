import json
from unittest.mock import MagicMock, patch

import pytest

from pysymex._internal.cli.formatters.base import iter_verify_issue_records
from pysymex._internal.cli.formatters.html import HtmlFormatter
from pysymex._internal.cli.formatters.json import JsonFormatter
from pysymex._internal.cli.formatters.markdown import CliMarkdownFormatter
from pysymex._internal.cli.formatters.registry import get_formatter
from pysymex._internal.cli.formatters.sarif import SarifFormatter
from pysymex._internal.cli.formatters.text.formatter import CliTextFormatter
from pysymex._internal.contracts.decorator.registry import ContractRegistry
from pysymex._internal.contracts.decorators import requires
from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex._internal.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex._internal.contracts.obligations.evidence import build_contract_evidence
from pysymex._internal.contracts.types import Contract
from pysymex._internal.execution.executors.verified.properties.types import (
    ProofStatus,
    PropertyKind,
    PropertyProof,
    PropertySpec,
)
from pysymex._internal.execution.executors.verified.types import InferredProperty
from pysymex._internal.reporting.formatters.json import JSONFormatter as ReportingJsonFormatter
from pysymex._internal.reporting.formatters.markup import (
    MarkdownFormatter as ReportingMarkdownFormatter,
)


@pytest.fixture
def mock_scan_result() -> MagicMock:
    result = MagicMock()
    result.file_path = "test.py"
    result.issues = [
        {
            "kind": "DIVISION_BY_ZERO",
            "line": 10,
            "message": "Div by zero",
            "counterexample": {"x": 0},
        }
    ]
    result.elapsed_time = 1.5
    result.avg_memory_mb = 120.0
    result.paths_explored = 5
    result.max_depth_reached = 3
    result.error = None
    result.to_dict.return_value = {"file": "test.py", "issues": result.issues, "elapsed_time": 1.5}
    return result


@pytest.fixture
def mock_verify_result() -> MagicMock:
    result = MagicMock()
    result.function_name = "checked"
    result.source_file = "verify_target.py"
    result.paths_explored = 3
    result.degraded_passes = []

    runtime_issue = MagicMock()
    runtime_issue.kind = "RUNTIME"
    runtime_issue.line_number = 7
    runtime_issue.format.return_value = "runtime failed"

    contract_issue = MagicMock()
    contract_issue.kind = "CONTRACT"
    contract_issue.line_number = 11
    contract_issue.format.return_value = "contract failed"

    arithmetic_issue = MagicMock()
    arithmetic_issue.kind = "ARITHMETIC"
    arithmetic_issue.line_number = 13
    arithmetic_issue.format.return_value = "arithmetic failed"

    result.issues = [runtime_issue]
    result.contract_issues = [contract_issue]
    result.arithmetic_issues = [arithmetic_issue]
    result.inferred_properties = []
    return result


@requires("x > 0")
def _contract_target_for_report(x: int) -> int:
    return x


def _contract_clause_for_report() -> Contract:
    contract = ContractRegistry.get(_contract_target_for_report)
    assert contract is not None
    return contract.preconditions[0]


def _contract_evidence_for_report() -> object:
    return build_contract_evidence(
        _contract_clause_for_report(),
        _contract_target_for_report,
        hook=ObligationHook.CALL_SITE,
        query_kind=QueryKind.CALL_PRECONDITION,
        pc=11,
        status=VerificationResult.UNSUPPORTED,
        solver_status=SolverStatus.UNSUPPORTED,
        message="predicate could not be lowered",
        unsupported_reasons=(UnsupportedReason.PREDICATE_LOWERING,),
    )


def test_get_formatter() -> None:
    assert isinstance(get_formatter("json"), JsonFormatter)
    assert isinstance(get_formatter("rich"), CliTextFormatter)
    assert isinstance(get_formatter("text"), CliTextFormatter)
    assert isinstance(get_formatter("sarif"), SarifFormatter)
    assert isinstance(get_formatter("html"), HtmlFormatter)
    assert isinstance(get_formatter("markdown"), CliMarkdownFormatter)


def test_get_formatter_rejects_unknown_format() -> None:
    with pytest.raises(ValueError, match="Unsupported formatter: unknown"):
        get_formatter("unknown")


def test_cli_formatters_are_distinct_from_single_result_reporting_formatters() -> None:
    """CLI formatters own command aggregation; reporting formatters own one result."""
    assert JsonFormatter is not ReportingJsonFormatter
    assert CliMarkdownFormatter is not ReportingMarkdownFormatter
    assert hasattr(JsonFormatter(), "format_symbolic")
    assert hasattr(ReportingJsonFormatter(), "format")


def test_iter_verify_issue_records_normalizes_all_verify_issue_buckets(
    mock_verify_result: MagicMock,
) -> None:
    records = list(iter_verify_issue_records(mock_verify_result))

    assert [record.issue_type for record in records] == ["RUNTIME", "CONTRACT", "ARITHMETIC"]
    assert [record.message for record in records] == [
        "runtime failed",
        "contract failed",
        "arithmetic failed",
    ]
    assert [record.line_number for record in records] == [7, 11, 13]
    assert {record.source_file for record in records} == {"verify_target.py"}
    assert {record.function_name for record in records} == {"checked"}


def test_json_formatter(mock_scan_result: MagicMock) -> None:
    fmt = JsonFormatter()
    out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
    assert '"mode": "symbolic"' in out
    assert '"total_issues": 1' in out


def test_json_verify_formatter_includes_contract_evidence_schema(
    mock_verify_result: MagicMock,
) -> None:
    evidence = _contract_evidence_for_report()
    mock_verify_result.contract_evidence = [evidence]

    data = json.loads(JsonFormatter().format_verify([mock_verify_result], 3, 1.0))

    assert data["evidence_schema"] == "pysymex.contracts.evidence.v1"
    assert data["results"][0]["contract_evidence"][0]["solver_status"] == "unsupported"


def test_json_verify_formatter_includes_inferred_properties(
    mock_verify_result: MagicMock,
) -> None:
    spec = PropertySpec(
        PropertyKind.BOUNDED,
        "bounded_execution_completion",
        "bounded execution completed",
    )
    mock_verify_result.inferred_properties = [
        InferredProperty(
            kind=PropertyKind.BOUNDED,
            description=spec.description,
            confidence=1.0,
            proof=PropertyProof(spec, ProofStatus.PROVEN),
        )
    ]

    data = json.loads(JsonFormatter().format_verify([mock_verify_result], 3, 1.0))

    prop = data["results"][0]["inferred_properties"][0]
    assert prop["kind"] == "BOUNDED"
    assert prop["description"] == "bounded execution completed"
    assert prop["confidence"] == 1.0
    assert prop["proof"]["status"] == "PROVEN"
    assert prop["proof"]["name"] == "bounded_execution_completion"


def test_text_verify_formatter_shows_contract_evidence_rows(
    mock_verify_result: MagicMock,
) -> None:
    evidence = _contract_evidence_for_report()
    mock_verify_result.contract_evidence = [evidence]

    output = CliTextFormatter(use_rich=False).format_verify([mock_verify_result], 3, 1.0)

    assert "Contract evidence:" in output
    assert "[UNSUPPORTED] REQUIRES call_site/call_precondition (native): x > 0" in output


def test_text_verify_formatter_shows_inferred_properties(
    mock_verify_result: MagicMock,
) -> None:
    spec = PropertySpec(
        PropertyKind.BOUNDED,
        "bounded_execution_completion",
        "bounded execution completed",
    )
    mock_verify_result.inferred_properties = [
        InferredProperty(
            kind=PropertyKind.BOUNDED,
            description=spec.description,
            confidence=1.0,
            proof=PropertyProof(spec, ProofStatus.PROVEN),
        )
    ]

    output = CliTextFormatter(use_rich=False).format_verify([mock_verify_result], 3, 1.0)

    assert "Inferred properties:" in output
    assert "[PROVEN] BOUNDED: bounded execution completed" in output


def test_text_formatter(mock_scan_result: MagicMock) -> None:
    fmt = CliTextFormatter(use_rich=False)
    out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
    assert "pysymex - formal verification report" in out
    assert "DIVISION_BY_ZERO" in out
    assert "Trigger:" in out


def test_text_formatter_omits_empty_trigger(mock_scan_result: MagicMock) -> None:
    mock_scan_result.issues[0]["counterexample"] = {}

    out = CliTextFormatter(use_rich=False).format_symbolic([mock_scan_result], 1, 1.5)

    assert "Trigger:" not in out


def test_rich_text_formatter_omits_empty_trigger(mock_scan_result: MagicMock) -> None:
    pytest.importorskip("rich")
    mock_scan_result.issues[0]["counterexample"] = {}

    out = CliTextFormatter(use_rich=True).format_symbolic([mock_scan_result], 1, 1.5)

    assert "Trigger:" not in out


def test_markdown_formatter(mock_scan_result: MagicMock) -> None:
    fmt = CliMarkdownFormatter()
    out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
    assert "# pysymex symbolic execution report" in out
    assert "DIVISION_BY_ZERO" in out
    assert "Triggering Input" in out


def test_markdown_formatter_omits_empty_triggering_input(mock_scan_result: MagicMock) -> None:
    mock_scan_result.issues[0]["counterexample"] = {}

    out = CliMarkdownFormatter().format_symbolic([mock_scan_result], 1, 1.5)

    assert "Triggering Input" not in out


def test_html_formatter(mock_scan_result: MagicMock) -> None:
    fmt = HtmlFormatter()

    with patch("pysymex._internal.cli.formatters.html.generate_html_report") as mock_gen:
        mock_gen.return_value = "<html></html>"
        out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
        assert out == "<html></html>"


def test_html_formatter_normalizes_empty_triggering_input(mock_scan_result: MagicMock) -> None:
    mock_scan_result.issues[0]["counterexample"] = {}
    fmt = HtmlFormatter()

    with patch("pysymex._internal.cli.formatters.html.generate_html_report") as mock_gen:
        mock_gen.return_value = "<html></html>"

        out = fmt.format_symbolic([mock_scan_result], 1, 1.5)

    assert out == "<html></html>"
    report = mock_gen.call_args.args[0]
    assert report.issues[0].triggering_input is None


def test_html_verify_formatter_uses_normalized_verify_records(
    mock_verify_result: MagicMock,
) -> None:
    fmt = HtmlFormatter()

    with patch("pysymex._internal.cli.formatters.html.generate_html_report") as mock_gen:
        mock_gen.return_value = "<html></html>"

        out = fmt.format_verify([mock_verify_result], 3, 1.0)

    assert out == "<html></html>"
    report = mock_gen.call_args.args[0]
    assert [issue.issue_type for issue in report.issues] == ["RUNTIME", "CONTRACT", "ARITHMETIC"]
    assert [issue.message for issue in report.issues] == [
        "runtime failed",
        "contract failed",
        "arithmetic failed",
    ]
    assert [issue.line_number for issue in report.issues] == [7, 11, 13]


def test_sarif_formatter(mock_scan_result: MagicMock) -> None:
    fmt = SarifFormatter()

    with patch("pysymex._internal.reporting.sarif.generator.SARIFGenerator") as mock_gen_sym:
        mock_sarif = MagicMock()
        mock_sarif.to_json.return_value = "{}"
        mock_gen_sym.return_value.generate.return_value = mock_sarif

        out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
        assert out == "{}"
        symbolic_call = mock_gen_sym.return_value.generate.call_args.kwargs
        assert symbolic_call["execution_successful"] is True
        assert symbolic_call["analysis_errors"] is None


def test_sarif_symbolic_formatter_records_scan_failures(mock_scan_result: MagicMock) -> None:
    mock_scan_result.error = "Syntax Error: invalid syntax"

    payload = json.loads(SarifFormatter().format_symbolic([mock_scan_result], 1, 1.0))
    invocation = payload["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["analysisErrors"] == ["test.py: Syntax Error: invalid syntax"]


def test_sarif_verify_formatter_uses_normalized_verify_records(
    mock_verify_result: MagicMock,
) -> None:
    fmt = SarifFormatter()
    evidence = _contract_evidence_for_report()
    mock_verify_result.contract_issues[0].evidence = evidence

    with patch("pysymex._internal.reporting.sarif.generator.SARIFGenerator") as mock_generator:
        mock_sarif = MagicMock()
        mock_sarif.to_json.return_value = "{}"
        mock_generator.return_value.generate.return_value = mock_sarif

        out = fmt.format_verify([mock_verify_result], 3, 1.0)

    assert out == "{}"
    issues = mock_generator.return_value.generate.call_args.kwargs["issues"]
    assert [issue["type"] for issue in issues] == ["RUNTIME", "CONTRACT", "ARITHMETIC"]
    assert issues[1]["properties"]["contractEvidence"]["solver_status"] == "unsupported"


def test_sarif_verify_formatter_projects_contract_evidence_properties(
    mock_verify_result: MagicMock,
) -> None:
    evidence = _contract_evidence_for_report()
    mock_verify_result.contract_issues[0].evidence = evidence

    payload = json.loads(SarifFormatter().format_verify([mock_verify_result], 3, 1.0))

    contract_result = payload["runs"][0]["results"][1]
    assert contract_result["properties"]["contractEvidence"]["status"] == "UNSUPPORTED"
