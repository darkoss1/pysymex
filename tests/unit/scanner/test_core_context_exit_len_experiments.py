from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_reports_context_exit_len_assertion_division_case(
    tmp_path: Path,
) -> None:
    target = tmp_path / "context_exit_len_assertion_division.py"
    target.write_text(
        "from __future__ import annotations\n\n"
        "class ExitResult:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "class Manager:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n"
        "    def __enter__(self) -> int:\n"
        "        return self.size\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> ExitResult:\n"
        "        return ExitResult(self.size)\n\n"
        "def target(size: int, salt: int) -> int:\n"
        "    holder = {'size': size}\n"
        "    alias = holder\n"
        "    def choose_exit_size() -> int:\n"
        "        if ((size ^ salt) & 1) == 0:\n"
        "            alias['size'] = size\n"
        "        else:\n"
        "            alias['size'] = size - 2\n"
        "        return alias['size']\n"
        "    marker = 0\n"
        "    try:\n"
        "        with Manager(choose_exit_size()):\n"
        "            return 100 // 0\n"
        "    except ValueError:\n"
        "        marker = 1\n"
        "    assert marker == 0\n"
        "    return marker\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, trace_enabled=False, timeout=30)
    issue_kinds = {issue.get("kind") for issue in result.issues}

    assert "DIVISION_BY_ZERO" in issue_kinds
    assert "ASSERTION_ERROR" in issue_kinds
    assert "unsupported_truth_protocol" not in result.degraded_passes
