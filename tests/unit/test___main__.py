import subprocess
import sys


def test_main_execution() -> None:
    """Test that __main__.py correctly invokes the cli main function."""
    result = subprocess.run(
        [sys.executable, "-m", "pysymex", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Usage" in result.stdout or "pysymex" in result.stdout
