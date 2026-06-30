"""Scanner regressions for precise stdlib collection mutation behavior."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_empty_deque_popleft_after_path_local_removal(tmp_path: Path) -> None:
    target = tmp_path / "deque_empty_popleft.py"
    target.write_text(
        "from collections import deque\n"
        "\n"
        "def target(flag: int) -> int:\n"
        "    queue: deque[int] = deque([flag])\n"
        "    if flag == 0:\n"
        "        queue.popleft()\n"
        "    return queue.popleft()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "INDEX_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") in {6, 7}
        for issue in result.issues
    )


def test_scan_file_allows_guarded_nonempty_deque_popleft(tmp_path: Path) -> None:
    target = tmp_path / "deque_nonempty_popleft.py"
    target.write_text(
        "from collections import deque\n"
        "\n"
        "def target(flag: int) -> int:\n"
        "    queue: deque[int] = deque([flag])\n"
        "    if flag != 0:\n"
        "        return queue.popleft()\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "INDEX_ERROR"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_empty_heapq_pop_without_a_path_local_push(tmp_path: Path) -> None:
    target = tmp_path / "heapq_empty_pop.py"
    target.write_text(
        "from heapq import heappop, heappush\n"
        "\n"
        "def target(flag: int) -> int:\n"
        "    heap: list[int] = []\n"
        "    if flag != 0:\n"
        "        heappush(heap, flag)\n"
        "    return heappop(heap)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "INDEX_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_allows_heapq_pop_after_path_local_push(tmp_path: Path) -> None:
    target = tmp_path / "heapq_nonempty_pop.py"
    target.write_text(
        "from heapq import heappop, heappush\n"
        "\n"
        "def target(flag: int) -> int:\n"
        "    heap: list[int] = []\n"
        "    if flag != 0:\n"
        "        heappush(heap, flag)\n"
        "        return heappop(heap)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "INDEX_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_defaultdict_int_missing_zero_division(tmp_path: Path) -> None:
    target = tmp_path / "defaultdict_missing_zero.py"
    target.write_text(
        "from collections import defaultdict\n"
        "\n"
        "def target(flag: int) -> int:\n"
        "    values: defaultdict[str, int] = defaultdict(int)\n"
        "    if flag == 0:\n"
        "        return 10 // values['missing']\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 6
        for issue in result.issues
    )


def test_scan_file_allows_explicit_nonzero_defaultdict_value(tmp_path: Path) -> None:
    target = tmp_path / "defaultdict_nonzero_value.py"
    target.write_text(
        "from collections import defaultdict\n"
        "\n"
        "def target(flag: int) -> int:\n"
        "    values: defaultdict[str, int] = defaultdict(int)\n"
        "    values['missing'] = 1\n"
        "    if flag == 0:\n"
        "        return 10 // values['missing']\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_bisect_end_insertion_index(tmp_path: Path) -> None:
    target = tmp_path / "bisect_index.py"
    target.write_text(
        "from bisect import bisect_left\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    values = [10, 20, 30]\n"
        "    index = bisect_left(values, value)\n"
        "    return values[index]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "INDEX_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 6
        for issue in result.issues
    )


def test_scan_file_allows_guarded_bisect_index(tmp_path: Path) -> None:
    target = tmp_path / "bisect_guarded_index.py"
    target.write_text(
        "from bisect import bisect_left\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    values = [10, 20, 30]\n"
        "    index = bisect_left(values, value)\n"
        "    if index >= len(values):\n"
        "        return 0\n"
        "    return values[index]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "INDEX_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_allows_division_suppressed_by_matching_contextlib_type(
    tmp_path: Path,
) -> None:
    target = tmp_path / "suppress_division.py"
    target.write_text(
        "from contextlib import suppress\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with suppress(ZeroDivisionError):\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_division_with_unrelated_contextlib_suppress_type(
    tmp_path: Path,
) -> None:
    target = tmp_path / "suppress_other_exception.py"
    target.write_text(
        "from contextlib import suppress\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with suppress(ValueError):\n"
        "        result = 10 // denominator\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 5
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "UNBOUND_VARIABLE" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_does_not_trust_user_defined_suppress_lookalike(tmp_path: Path) -> None:
    target = tmp_path / "custom_suppress.py"
    target.write_text(
        "class suppress:\n"
        "    def __init__(self, *_types: object) -> None:\n"
        "        pass\n"
        "    def __enter__(self) -> None:\n"
        "        return None\n"
        "    def __exit__(self, *_args: object) -> bool:\n"
        "        return False\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with suppress(ZeroDivisionError):\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_reports_accumulate_zero_sum_without_index_error(tmp_path: Path) -> None:
    target = tmp_path / "accumulate_zero_sum.py"
    target.write_text(
        "from itertools import accumulate\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    totals = list(accumulate([value, -value]))\n"
        "    return 10 // totals[-1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 5
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "INDEX_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_allows_guarded_accumulate_last_item(tmp_path: Path) -> None:
    target = tmp_path / "accumulate_guarded.py"
    target.write_text(
        "from itertools import accumulate\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    totals = list(accumulate([value, 1]))\n"
        "    denominator = totals[-1]\n"
        "    if denominator == 0:\n"
        "        return 0\n"
        "    return 10 // denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "INDEX_ERROR"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )
