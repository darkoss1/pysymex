from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _run_python(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_importing_scan_file_does_not_import_scan_tracing_adapter() -> None:
    code = textwrap.dedent(
        """
        import sys

        import pysymex._internal.scanner.file

        raise SystemExit(1 if "pysymex._internal.tracing.scan" in sys.modules else 0)
        """
    )

    result = _run_python(code)

    assert result.returncode == 0, result.stderr


def test_scan_file_with_trace_disabled_does_not_import_scan_tracing_adapter(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.py"
    target.write_text("def target(value: int) -> int:\n    return value + 1\n", encoding="utf-8")
    code = textwrap.dedent(
        f"""
        import sys
        from pathlib import Path

        from pysymex._internal.scanner.file import scan_file

        result = scan_file(
            Path({str(target)!r}),
            use_sandbox=False,
            trace_enabled=False,
            max_paths=4,
            timeout=10,
        )
        if result.error is not None:
            print(result.error)
            raise SystemExit(2)
        raise SystemExit(1 if "pysymex._internal.tracing.scan" in sys.modules else 0)
        """
    )

    result = _run_python(code)

    assert result.returncode == 0, result.stdout + result.stderr
