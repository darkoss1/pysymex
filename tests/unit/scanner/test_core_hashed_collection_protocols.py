"""Scanner regressions for unsupported user-instance hashing in native containers."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_degrades_dict_lookup_that_requires_user_hashing(tmp_path: Path) -> None:
    target = tmp_path / "dict_hashed_key.py"
    target.write_text(
        "class EqualKey:\n"
        "    def __hash__(self) -> int:\n"
        "        return 7\n"
        "    def __eq__(self, other: object) -> bool:\n"
        "        return True\n"
        "\n"
        "def target() -> int:\n"
        "    payload = {EqualKey(): 0}\n"
        "    return 10 // payload[EqualKey()]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_hashed_collection_protocol" in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_does_not_report_unequal_hash_collision_as_reachable(tmp_path: Path) -> None:
    target = tmp_path / "unequal_hash_collision.py"
    target.write_text(
        "class UnequalCollisionKey:\n"
        "    def __hash__(self) -> int:\n"
        "        return 7\n"
        "    def __eq__(self, other: object) -> bool:\n"
        "        return False\n"
        "\n"
        "def target() -> int:\n"
        "    payload = {UnequalCollisionKey(): 0}\n"
        "    if UnequalCollisionKey() in payload:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_hashed_collection_protocol" in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_degrades_unhashable_modeled_dict_key(tmp_path: Path) -> None:
    target = tmp_path / "unhashable_key.py"
    target.write_text(
        "class EqualityOnlyKey:\n"
        "    def __eq__(self, other: object) -> bool:\n"
        "        return True\n"
        "\n"
        "def target() -> dict[object, int]:\n"
        "    return {EqualityOnlyKey(): 0}\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_hashed_collection_protocol" in result.degraded_passes
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
