from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_executes_zero_arg_super_diamond_chain(tmp_path: Path) -> None:
    target = tmp_path / "super_diamond_bug.py"
    target.write_text(
        "class A:\n"
        "    def value(self) -> int:\n"
        "        return 10 // self.denominator\n\n"
        "class B(A):\n"
        "    def value(self) -> int:\n"
        "        return super().value()\n\n"
        "class C(A):\n"
        "    def value(self) -> int:\n"
        "        return super().value()\n\n"
        "class D(B, C):\n"
        "    def value(self, x: int) -> int:\n"
        "        self.denominator = x - 3\n"
        "        return super().value()\n\n"
        "def target(x: int) -> int:\n"
        "    return D().value(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_super_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_keeps_guard_through_zero_arg_super_diamond_chain(tmp_path: Path) -> None:
    target = tmp_path / "super_diamond_safe.py"
    target.write_text(
        "class A:\n"
        "    def value(self) -> int:\n"
        "        return 10 // self.denominator\n\n"
        "class B(A):\n"
        "    def value(self) -> int:\n"
        "        return super().value()\n\n"
        "class C(A):\n"
        "    def value(self) -> int:\n"
        "        return super().value()\n\n"
        "class D(B, C):\n"
        "    def value(self, x: int) -> int:\n"
        "        self.denominator = 1 if x == 3 else x - 3\n"
        "        return super().value()\n\n"
        "def target(x: int) -> int:\n"
        "    return D().value(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_super_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
