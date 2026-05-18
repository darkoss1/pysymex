import pytest
import argparse
from unittest.mock import patch, MagicMock
from pathlib import Path
import pysymex.cli.scan
from pysymex.scanner.types import ScanResult


def test_cmd_scan() -> None:
    """Test cmd_scan behavior."""
    args = argparse.Namespace(path="fake.py", mode="symbolic", verbose=False, recursive=False)
    with patch("pysymex.cli.scan.Path.exists", return_value=False):
        assert pysymex.cli.scan.cmd_scan(args) == 1


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_cmd_scan_async() -> None:
    """Test cmd_scan_async behavior."""
    args = argparse.Namespace(path="fake.py", mode="symbolic", verbose=False, recursive=False)
    with patch("pysymex.cli.scan.Path.exists", return_value=False):
        assert await pysymex.cli.scan.cmd_scan_async(args) == 1


def test_format_static_text_report() -> None:
    """Test format_static_text_report behavior."""
    from pysymex.cli.formatters.text_fmt import TextFormatter

    fmt = TextFormatter(use_rich=False)
    text = fmt.format_static([], 0, 0, 0.0)
    assert "pysymex static scan" in text


def test_format_symbolic_text_report() -> None:
    """Test format_symbolic_text_report behavior."""
    from pysymex.cli.formatters.text_fmt import TextFormatter

    fmt = TextFormatter(use_rich=False)
    text = fmt.format_symbolic([], 0, 0.0, False)
    assert "pysymex - formal verification report" in text


def test_get_symbolic_sarif() -> None:
    """Test get_symbolic_sarif behavior."""
    from pysymex.cli.formatters.sarif_fmt import SarifFormatter

    with patch("pysymex.reporting.sarif.SARIFGenerator") as mock_gen:
        mock_sarif = MagicMock()
        mock_sarif.to_json.return_value = "{}"
        mock_gen.return_value.generate.return_value = mock_sarif
        fmt = SarifFormatter()
        assert fmt.format_symbolic([], 0, 0.0) == "{}"


def test_handle_static_sarif_scan_uses_shared_output_writer(tmp_path: Path) -> None:
    """Static SARIF scans should honor the same output path flow as other scan formats."""
    target = tmp_path / "sample.py"
    target.write_text("def f():\n    return 1\n", encoding="utf-8")
    output = tmp_path / "scan.sarif"
    args = argparse.Namespace(
        path=str(target),
        format="sarif",
        output=str(output),
        verbose=False,
        recursive=False,
        stats=False,
        show_suppressed=False,
    )

    with patch("pysymex.api.scan_static", return_value=[]):
        with patch("pysymex.cli.scan.emit_cli_output") as emit:
            rc = pysymex.cli.scan._handle_static_scan(args, 0.0)  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal output routing

    assert rc == 0
    emit.assert_called_once()
    assert emit.call_args.kwargs["output_path"] == str(output)


def test_handle_symbolic_scan_forces_deterministic_mode_for_single_file(tmp_path: Path) -> None:
    """Single-file symbolic scans force deterministic mode for stable path coverage."""
    file_path = tmp_path / "sample.py"
    file_path.write_text("def f(x):\n    return x\n", encoding="utf-8")
    args = argparse.Namespace(
        path=str(file_path),
        mode="symbolic",
        format="json",
        output=None,
        verbose=False,
        recursive=False,
        visualize=False,
        stats=False,
        reproduce=False,
        max_paths=200,
        timeout=30,
        workers=0,
        auto=False,
        sandbox=True,
        use_chtd=True,
        use_h_acceleration=True,
        deterministic=False,
        seed=42,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
    )
    observed: dict[str, object] = {}

    def _fake_call(
        func: object,
        *call_args: object,
        **call_kwargs: object,
    ) -> object:
        _ = func
        _ = call_args
        observed.update(call_kwargs)
        return ScanResult(
            file_path=str(file_path),
            timestamp="2026-04-30T00:00:00",
            issues=[],
        )

    with patch("pysymex.cli.scan._call_with_supported_kwargs", side_effect=_fake_call):
        with patch("pysymex.cli.scan.emit_cli_output"):
            rc = pysymex.cli.scan._handle_symbolic_scan(args, file_path, 0.0)  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    assert rc == 0
    assert observed["deterministic_mode"] is True


def test_handle_symbolic_scan_keeps_directory_deterministic_flag(tmp_path: Path) -> None:
    """Directory symbolic scans preserve explicit deterministic flag value."""
    dir_path = tmp_path / "src"
    dir_path.mkdir()
    args = argparse.Namespace(
        path=str(dir_path),
        mode="symbolic",
        format="json",
        output=None,
        verbose=False,
        recursive=False,
        visualize=False,
        stats=False,
        reproduce=False,
        max_paths=200,
        timeout=30,
        workers=0,
        auto=False,
        sandbox=True,
        use_chtd=True,
        use_h_acceleration=True,
        deterministic=False,
        seed=42,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
    )
    observed: dict[str, object] = {}

    def _fake_call(
        func: object,
        *call_args: object,
        **call_kwargs: object,
    ) -> object:
        _ = func
        _ = call_args
        observed.update(call_kwargs)
        return []

    with patch("pysymex.cli.scan._call_with_supported_kwargs", side_effect=_fake_call):
        with patch("pysymex.cli.scan.emit_cli_output"):
            rc = pysymex.cli.scan._handle_symbolic_scan(args, dir_path, 0.0)  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    assert rc == 0
    assert observed["deterministic_mode"] is False
