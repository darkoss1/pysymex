"""Scanner regressions for loop cleanup inside context managers."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_nested_with_loop_cleanup_does_not_call_stale_iterator(tmp_path: Path) -> None:
    target = tmp_path / "nested_with_loop_cleanup.py"
    target.write_text(
        "class Gate:\n"
        "    def __init__(self) -> None:\n"
        "        self.events = []\n"
        "\n"
        "    def __enter__(self) -> object:\n"
        "        self.events.append('enter')\n"
        "        return self\n"
        "\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:\n"
        "        self.events.append(('exit', exc_type is not None))\n"
        "        return False\n"
        "\n"
        "\n"
        "def target(x: int) -> int:\n"
        "    total = 0\n"
        "    gate = Gate()\n"
        "    with gate as outer:\n"
        "        with outer as inner:\n"
        "            for value in [(x, 1), (x + 1, 2)]:\n"
        "                a, b = value\n"
        "                total += a + b\n"
        "    return total + len(gate.events)\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        max_iterations=5000,
        timeout=8,
    )

    assert result.error is None
    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert not result.issues
