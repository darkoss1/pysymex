from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_exec_sink_assignment_does_not_emit_follow_on_key_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "exec_sink_assignment.py"
    target.write_text(
        "def target(seed: int) -> int:\n"
        "    namespace = {'seed': seed}\n"
        "    exec('result = seed + 2', namespace)\n"
        "    return namespace['result']\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(issue.get("kind") == "RUNTIME_ERROR" for issue in result.issues)
    assert not any(
        issue.get("kind") == "KEY_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )
