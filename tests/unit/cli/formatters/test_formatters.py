import pytest
from unittest.mock import MagicMock, patch
from pysymex.cli.formatters import get_formatter
from pysymex.cli.formatters.json_fmt import JsonFormatter
from pysymex.cli.formatters.text_fmt import TextFormatter
from pysymex.cli.formatters.sarif_fmt import SarifFormatter
from pysymex.cli.formatters.html_fmt import HtmlFormatter
from pysymex.cli.formatters.markdown_fmt import MarkdownFormatter


@pytest.fixture
def mock_issue() -> MagicMock:
    issue = MagicMock()
    issue.kind = "DIVISION_BY_ZERO"
    issue.line = 10
    issue.message = "Div by zero"
    issue.severity = "critical"
    issue.file = "test.py"
    issue.to_dict.return_value = {
        "kind": "DIVISION_BY_ZERO",
        "line": 10,
        "message": "Div by zero",
        "severity": "critical",
        "file": "test.py",
    }
    return issue


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
    result.to_dict.return_value = {"file": "test.py", "issues": result.issues, "elapsed_time": 1.5}
    return result


def test_get_formatter() -> None:
    assert isinstance(get_formatter("json"), JsonFormatter)
    assert isinstance(get_formatter("rich"), TextFormatter)
    assert isinstance(get_formatter("text"), TextFormatter)
    assert isinstance(get_formatter("sarif"), SarifFormatter)
    assert isinstance(get_formatter("html"), HtmlFormatter)
    assert isinstance(get_formatter("markdown"), MarkdownFormatter)
    assert isinstance(get_formatter("unknown"), TextFormatter)


def test_json_formatter(mock_issue: MagicMock, mock_scan_result: MagicMock) -> None:
    fmt = JsonFormatter()

    # Static
    out = fmt.format_static([mock_issue], 1, 0, 1.0)
    assert '"mode": "static"' in out
    assert '"total_issues": 1' in out

    # Pipeline
    mock_pipeline_result = MagicMock()
    mock_pipeline_result.issues = [mock_issue]
    out = fmt.format_pipeline({"test.py": mock_pipeline_result}, [("test.py", mock_issue)], 1, 1.0)
    assert '"mode": "pipeline"' in out
    assert '"files_scanned": 1' in out

    # Symbolic
    out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
    assert '"mode": "symbolic"' in out
    assert '"total_issues": 1' in out


def test_text_formatter(mock_issue: MagicMock, mock_scan_result: MagicMock) -> None:
    fmt = TextFormatter(use_rich=False)

    # Static
    out = fmt.format_static([mock_issue], 1, 0, 1.0)
    assert "pysymex static scan" in out
    assert "DIVISION_BY_ZERO" in out

    # Pipeline
    out = fmt.format_pipeline({}, [("test.py", mock_issue)], 1, 1.0)
    assert "pysymex pipeline scan" in out
    assert "test.py:10" in out

    # Symbolic
    out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
    assert "pysymex - formal verification report" in out
    assert "DIVISION_BY_ZERO" in out


def test_markdown_formatter(mock_issue: MagicMock, mock_scan_result: MagicMock) -> None:
    fmt = MarkdownFormatter()

    # Static
    out = fmt.format_static([mock_issue], 1, 0, 1.0)
    assert "# pysymex static analysis report" in out
    assert "DIVISION_BY_ZERO" in out

    # Pipeline
    out = fmt.format_pipeline({}, [("test.py", mock_issue)], 1, 1.0)
    assert "# pysymex pipeline scan report" in out
    assert "test.py:10" in out

    # Symbolic
    out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
    assert "# pysymex symbolic execution report" in out
    assert "DIVISION_BY_ZERO" in out


def test_html_formatter(mock_issue: MagicMock, mock_scan_result: MagicMock) -> None:
    fmt = HtmlFormatter()

    with patch("pysymex.cli.formatters.html_fmt.generate_html_report") as mock_gen:
        mock_gen.return_value = "<html></html>"

        # Static
        out = fmt.format_static([mock_issue], 1, 0, 1.0)
        assert out == "<html></html>"

        # Pipeline
        out = fmt.format_pipeline({}, [("test.py", mock_issue)], 1, 1.0)
        assert out == "<html></html>"

        # Symbolic
        out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
        assert out == "<html></html>"


def test_sarif_formatter(mock_issue: MagicMock, mock_scan_result: MagicMock) -> None:
    fmt = SarifFormatter()

    with patch("pysymex.reporting.sarif.SARIFGenerator") as mock_gen_sym:
        with patch("pysymex.reporting.sarif.generate_sarif") as mock_gen_static:
            mock_sarif = MagicMock()
            mock_sarif.to_json.return_value = "{}"
            mock_gen_sym.return_value.generate.return_value = mock_sarif
            mock_gen_static.return_value.to_json.return_value = "{}"

            # Static
            out = fmt.format_static([mock_issue], 1, 0, 1.0)
            assert out == "{}"

            # Symbolic
            out = fmt.format_symbolic([mock_scan_result], 1, 1.5)
            assert out == "{}"
