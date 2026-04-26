import argparse
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


def test_cmd_concolic() -> None:
    """Test cmd_concolic behavior."""
    args = argparse.Namespace(file="fake.py")
    with patch("pysymex.cli.commands.Path.exists", return_value=False):
        assert pysymex.cli.commands.cmd_concolic(args) == 1
