from __future__ import annotations

from pathlib import Path

import z3

from pysymex._internal.analysis.detectors.runtime.indexing.bounds.proofs import (
    path_constraints_prove_in_bounds,
)
from pysymex._internal.scanner.file import scan_file
from pysymex._internal.scanner.types import ScanResult


def _issue_kinds(result: ScanResult) -> set[str]:
    return {str(issue.get("kind", "")) for issue in result.issues}


def test_scan_file_function_filter_avoids_unselected_helper_assertions(tmp_path: Path) -> None:
    target = tmp_path / "helpers.py"
    target.write_text(
        "def helper():\n"
        "    raise AssertionError('helper noise')\n"
        "\n"
        "def target(x: int) -> int:\n"
        "    return x + 1\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        function_filter="target",
        max_paths=20,
        timeout=2,
    )

    assert result.error is None
    assert result.code_objects == 1
    assert not result.issues


def test_len_guarded_list_reads_survive_irrelevant_path_pollution(tmp_path: Path) -> None:
    target = tmp_path / "len_guarded.py"
    target.write_text(
        "def target(input_bytes: list[int]) -> int:\n"
        "    if len(input_bytes) != 32:\n"
        "        return -1\n"
        "    state_hash = 0x1337\n"
        "    for i in range(9, 12):\n"
        "        val = input_bytes[i]\n"
        "        if val % 3 == 0:\n"
        "            state_hash = ((state_hash << 1) ^ val) & 0xFFFFFFFF\n"
        "        elif val % 3 == 1:\n"
        "            state_hash = ((state_hash >> 1) + (val * 2)) & 0xFFFFFFFF\n"
        "        else:\n"
        "            state_hash ^= 0xCAFE\n"
        "    return state_hash + input_bytes[20] + input_bytes[21]\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        function_filter="target",
        max_paths=80,
        timeout=4,
    )

    assert result.error is None
    assert "INDEX_ERROR" not in _issue_kinds(result)


def test_path_bounds_proof_follows_transitive_len_aliases() -> None:
    container_len = z3.Int("input_bytes_len")
    len_result = z3.Int("len_input_bytes_int")
    path_constraints = [
        container_len >= 0,
        len_result == container_len,
        len_result >= 0,
        z3.IntVal(32) == len_result,
    ]

    assert path_constraints_prove_in_bounds(
        z3.IntVal(21),
        -container_len,
        container_len,
        path_constraints,
    )
