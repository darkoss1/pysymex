"""Scanner regressions for bounded standard-library dataclass declarations."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_preserves_dataclass_constructor_field_value(tmp_path: Path) -> None:
    target = tmp_path / "dataclass_field_zero.py"
    target.write_text(
        "from dataclasses import dataclass\n"
        "\n"
        "@dataclass\n"
        "class Point:\n"
        "    x: float\n"
        "    y: float\n"
        "\n"
        "    def magnitude_squared(self) -> float:\n"
        "        return self.x * self.x + self.y * self.y\n"
        "\n"
        "def target(x: float, y: float) -> float:\n"
        "    return 1.0 / Point(x, y).magnitude_squared()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert "solver_unknown_detector_query" not in result.degraded_passes
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_propagates_integer_dataclass_field_into_detection(tmp_path: Path) -> None:
    target = tmp_path / "int_dataclass_field.py"
    target.write_text(
        "from dataclasses import dataclass\n"
        "\n"
        "@dataclass\n"
        "class Denominator:\n"
        "    value: int\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    return 10 // Denominator(value).value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_uses_empty_dataclass_list_default_factory(tmp_path: Path) -> None:
    target = tmp_path / "dataclass_default_factory_empty.py"
    target.write_text(
        "from dataclasses import dataclass, field\n"
        "\n"
        "@dataclass\n"
        "class Queue:\n"
        "    items: list = field(default_factory=list)\n"
        "\n"
        "    def pop_first(self):\n"
        "        return self.items.pop(0)\n"
        "\n"
        "def target():\n"
        "    return Queue().pop_first()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)
    assert any(issue.get("kind") == "INDEX_ERROR" for issue in result.issues)


def test_scan_file_rejects_frozen_dataclass_field_mutation(tmp_path: Path) -> None:
    target = tmp_path / "frozen_dataclass_mutation.py"
    target.write_text(
        "from dataclasses import dataclass\n"
        "\n"
        "@dataclass(frozen=True)\n"
        "class Record:\n"
        "    value: int\n"
        "\n"
        "def target(value: int) -> None:\n"
        "    record = Record(value)\n"
        "    record.value = 2\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and "cannot assign to field 'value'" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_propagates_dataclass_list_mutation_through_method_loop(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dataclass_method_loop_full.py"
    target.write_text(
        "from dataclasses import dataclass, field\n"
        "\n"
        "@dataclass\n"
        "class Queue:\n"
        "    capacity: int\n"
        "    items: list = field(default_factory=list)\n"
        "\n"
        "    def add(self, item):\n"
        "        if len(self.items) >= self.capacity:\n"
        "            raise ValueError('full')\n"
        "        self.items.append(item)\n"
        "\n"
        "def target() -> int:\n"
        "    queue = Queue(1)\n"
        "    for item in range(1):\n"
        "        queue.add(item)\n"
        "    return 10 // (queue.capacity - len(queue.items))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_does_not_overcount_dataclass_method_list_mutation(tmp_path: Path) -> None:
    target = tmp_path / "dataclass_method_loop_not_full.py"
    target.write_text(
        "from dataclasses import dataclass, field\n"
        "\n"
        "@dataclass\n"
        "class Queue:\n"
        "    capacity: int\n"
        "    items: list = field(default_factory=list)\n"
        "\n"
        "    def add(self, item):\n"
        "        self.items.append(item)\n"
        "\n"
        "def target() -> int:\n"
        "    queue = Queue(3)\n"
        "    for item in range(2):\n"
        "        queue.add(item)\n"
        "    return 10 // (queue.capacity - len(queue.items))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
