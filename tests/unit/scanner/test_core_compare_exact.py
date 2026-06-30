from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_nested_tuple_same_symbolic_values_has_no_assertion_false_positive(
    tmp_path: Path,
) -> None:
    target = tmp_path / "tuple_same_symbolic_values.py"
    target.write_text(
        "def target(left: int, right: int) -> int:\n"
        "    token = ('pause', left, right)\n"
        "    observed = (token, ('mirror', left, right), (right, left, token))\n"
        "    expected = (('pause', left, right), ('mirror', left, right), (right, left, token))\n"
        "    if observed != expected:\n"
        "        raise AssertionError('tuple comparison drift')\n"
        "    return left + right\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=40,
        max_iterations=4000,
        timeout=6,
    )

    assert result.error is None
    assert not any(issue.get("kind") == "ASSERTION_ERROR" for issue in result.issues)
