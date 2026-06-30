"""Adversarial scanner regressions spanning modeled issue-kind families."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import cast

from pysymex._internal.scanner.file import scan_file

EXPECTED_RUNTIME_ISSUE_KINDS = {
    "ASSERTION_ERROR",
    "ATTRIBUTE_ERROR",
    "DIVISION_BY_ZERO",
    "INDEX_ERROR",
    "KEY_ERROR",
    "MODULO_BY_ZERO",
    "NAME_ERROR",
    "NULL_DEREFERENCE",
    "TYPE_ERROR",
    "UNBOUND_VARIABLE",
    "UNHANDLED_EXCEPTION",
    "VALUE_ERROR",
}


def _issue_kind(issue: object) -> str:
    if isinstance(issue, dict):
        raw_kind = cast("Mapping[str, object]", issue).get("kind")
    else:
        raw_kind = getattr(issue, "kind", None)
    if hasattr(raw_kind, "name"):
        return str(getattr(raw_kind, "name"))
    return str(raw_kind)


def _issue_kinds(issues: Sequence[object]) -> set[str]:
    return {_issue_kind(issue) for issue in issues}


def _scan_source(tmp_path: Path, filename: str, source: str):
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")
    return scan_file(
        target,
        max_paths=420,
        timeout=12,
        use_sandbox=False,
        no_cache=True,
        max_iterations=12000,
    )


def _load_target(source: str) -> Callable[[int, int, int], int]:
    namespace: dict[str, object] = {}
    exec(compile(source, "<adversarial-issue-kind-matrix>", "exec"), namespace)
    return cast("Callable[[int, int, int], int]", namespace["target"])


HARD_MULTI_KIND_TARGET = """
def target(mode: int, index: int, key_flag: int) -> int:
    class Slot:
        def __get__(self, instance, owner) -> int:
            if owner is not None:
                instance.events.append(owner.seed)
            return instance.base

    class Box:
        seed = 1
        value = Slot()

        def __init__(self, base: int):
            self.base = base
            self.events = []

    class Scope:
        def __init__(self, value: int):
            self.value = value
            self.events = []

        def __enter__(self):
            self.events.append("enter")
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            self.events.append("exit")
            return False

    box = Box(mode - key_flag)
    values = [1, 2, 3]
    mapping = {"present": box.value}

    with Scope(box.value) as active:
        pivot = active.value + len(active.events)

    if mode == 0:
        return 100 // (mode + pivot - pivot)
    if mode == 1:
        return 100 % (mode - 1)
    if mode == 2:
        if index >= 0:
            return values[index + 3]
        return values[0]
    if mode == 3:
        return mapping["missing"]
    if mode == 4:
        value = None
        return value.missing
    if mode == 5:
        return "prefix" - index
    if mode == 6:
        raise AssertionError("branch assertion")
    if mode == 7:
        return int("not-an-int")
    if mode == 8:
        raise RuntimeError("branch runtime")
    if mode == 9:
        return missing_name
    if mode == 10:
        if index > 0:
            local_value = index
        return local_value
    if mode == 11:
        class Empty:
            pass

        return Empty().missing
    if mode == 12:
        return values[99]
    if mode == 13:
        return mapping["missing-literal"]
    return 1
"""


HARD_MULTI_KIND_SAFE_CONTROL = """
def target(mode: int, index: int, key_flag: int) -> int:
    class Slot:
        def __get__(self, instance, owner) -> int:
            if owner is not None:
                instance.events.append(owner.seed)
            return instance.base

    class Box:
        seed = 1
        value = Slot()

        def __init__(self, base: int):
            self.base = base
            self.events = []

    class Scope:
        def __init__(self, value: int):
            self.value = value
            self.events = []

        def __enter__(self):
            self.events.append("enter")
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            self.events.append("exit")
            return False

    box = Box(mode - key_flag)
    values = [1, 2, 3]
    mapping = {"present": box.value}

    with Scope(box.value) as active:
        pivot = active.value + len(active.events)

    safe_index = index
    if safe_index < 0:
        safe_index = -safe_index
    safe_index = safe_index % 3

    if mode == 0:
        denom = mode + pivot - pivot
        if denom == 0:
            denom = 1
        return 100 // denom
    if mode == 1:
        denom = mode
        if denom == 0:
            denom = 1
        return 100 % denom
    if mode == 2:
        return values[safe_index]
    if mode == 3:
        return mapping["present"]
    if mode == 4:
        value = Box(1)
        return value.value
    if mode == 5:
        return len("prefix") + safe_index
    if mode == 6:
        assert True
        return safe_index
    if mode == 7:
        return int("123")
    if mode == 8:
        return 1
    if mode == 9:
        existing_name = 1
        return existing_name
    if mode == 10:
        local_value = 0
        if index > 0:
            local_value = index
        return local_value
    if mode == 11:
        class Empty:
            pass

        item = Empty()
        item.missing = 1
        return item.missing
    if mode == 12:
        return values[2]
    if mode == 13:
        return mapping["present"]
    return 1
"""


def test_scan_file_hard_issue_kind_matrix_reports_default_runtime_kinds(
    tmp_path: Path,
) -> None:
    result = _scan_source(tmp_path, "hard_issue_kind_matrix.py", HARD_MULTI_KIND_TARGET)

    issue_kinds = _issue_kinds(result.issues)

    assert result.error is None
    assert not result.degraded_passes
    assert EXPECTED_RUNTIME_ISSUE_KINDS <= issue_kinds
    assert "UNKNOWN" not in issue_kinds
    assert result.paths_explored <= 80


def test_cpython_hard_issue_kind_matrix_oracle() -> None:
    target = _load_target(HARD_MULTI_KIND_TARGET)
    expected_exceptions: dict[int, type[BaseException]] = {
        0: ZeroDivisionError,
        1: ZeroDivisionError,
        2: IndexError,
        3: KeyError,
        4: AttributeError,
        5: TypeError,
        6: AssertionError,
        7: ValueError,
        8: RuntimeError,
        9: NameError,
        10: UnboundLocalError,
        11: AttributeError,
        12: IndexError,
        13: KeyError,
    }

    for mode, exception_type in expected_exceptions.items():
        try:
            target(mode, 0, 0)
        except exception_type:
            pass
        else:
            raise AssertionError(f"mode {mode} did not raise {exception_type.__name__}")


def test_scan_file_hard_issue_kind_matrix_safe_control_stays_clean(
    tmp_path: Path,
) -> None:
    result = _scan_source(
        tmp_path,
        "hard_issue_kind_matrix_safe_control.py",
        HARD_MULTI_KIND_SAFE_CONTROL,
    )

    assert result.error is None
    assert not result.degraded_passes
    assert _issue_kinds(result.issues).isdisjoint(EXPECTED_RUNTIME_ISSUE_KINDS)
    assert result.paths_explored <= 80


def test_cpython_hard_issue_kind_matrix_safe_control_oracle() -> None:
    target = _load_target(HARD_MULTI_KIND_SAFE_CONTROL)

    for mode in range(14):
        assert isinstance(target(mode, -4, 2), int)
