import pytest
import argparse
from unittest.mock import patch, MagicMock
import pysymex.cli.scan

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
    text = pysymex.cli.scan.format_static_text_report([], 0)
    assert "PySyMex Static Scan" in text

def test_format_symbolic_text_report() -> None:
    """Test format_symbolic_text_report behavior."""
    text = pysymex.cli.scan.format_symbolic_text_report([], 0, False)
    assert "PySyMex Symbolic Scan" in text

def test_get_symbolic_sarif() -> None:
    """Test get_symbolic_sarif behavior."""
    with patch("pysymex.reporting.sarif.SARIFGenerator") as mock_gen:
        mock_sarif = MagicMock()
        mock_sarif.to_json.return_value = "{}"
        mock_gen.return_value.generate.return_value = mock_sarif
        assert pysymex.cli.scan.get_symbolic_sarif([]) == "{}"
