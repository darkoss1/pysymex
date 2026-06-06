from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_property_setter_mutation_updates_closed_instance_before_getter(
    tmp_path: Path,
) -> None:
    target = tmp_path / "property_setter_closure.py"
    target.write_text(
        "from __future__ import annotations\n"
        "\n"
        "class Box:\n"
        "    def __init__(self) -> None:\n"
        "        self.value = 1\n"
        "\n"
        "    @property\n"
        "    def pivot(self) -> int:\n"
        "        return self.value\n"
        "\n"
        "    @pivot.setter\n"
        "    def pivot(self, value: int) -> None:\n"
        "        self.value = value\n"
        "\n"
        "def target(x: int) -> int:\n"
        "    box = Box()\n"
        "\n"
        "    def write() -> int:\n"
        "        box.pivot = x\n"
        "        return box.pivot\n"
        "\n"
        "    denominator = write()\n"
        "    if x == 0:\n"
        "        return 10 // denominator\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, max_paths=40, timeout=8)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
