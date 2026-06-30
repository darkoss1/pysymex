from __future__ import annotations

from collections.abc import Callable

from pysymex._internal.contracts.enums import VerificationResult
from pysymex.contracts import ContractKind, assigns, pure

_GLOBAL_LIST: list[int] = []
_GLOBAL_LIST_ALIAS = _GLOBAL_LIST
_GLOBAL_OTHER_LIST: list[int] = []
_GLOBAL_DICT: dict[str, int] = {}
_GLOBAL_DICT_ALIAS = _GLOBAL_DICT
_GLOBAL_SET: set[int] = set()
_GLOBAL_SET_ALIAS = _GLOBAL_SET


def _assert_single_violation(
    target: Callable[..., int],
    expected_kind: ContractKind,
    expected_location: str,
) -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    result = verify(target, {"x": "int"})
    issues = [issue for issue in result.contract_issues if issue.kind is expected_kind]

    assert len(issues) == 1
    assert issues[0].result is VerificationResult.VIOLATED
    assert expected_location in issues[0].message
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 1


def _assert_verified(target: Callable[..., int]) -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    result = verify(target, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
    assert result.contracts_violated == 0


def test_pure_obligation_tracks_global_list_append_without_mutating_host_global() -> None:
    _GLOBAL_LIST.clear()

    @pure
    def target(x: int) -> int:
        _GLOBAL_LIST.append(x)
        return len(_GLOBAL_LIST)

    _assert_single_violation(target, ContractKind.PURE, "global._GLOBAL_LIST[*]")
    assert _GLOBAL_LIST == []


def test_assigns_obligation_tracks_global_list_append_without_mutating_host_global() -> None:
    _GLOBAL_LIST.clear()

    @assigns()
    def target(x: int) -> int:
        _GLOBAL_LIST.append(x)
        return len(_GLOBAL_LIST)

    _assert_single_violation(target, ContractKind.ASSIGNS, "global._GLOBAL_LIST[*]")
    assert _GLOBAL_LIST == []


def test_assigns_allows_global_list_write_through_definite_entry_alias() -> None:
    _GLOBAL_LIST.clear()

    @assigns("global._GLOBAL_LIST[*]")
    def target(x: int) -> int:
        _GLOBAL_LIST_ALIAS.append(x)
        return len(_GLOBAL_LIST_ALIAS)

    _assert_verified(target)
    assert _GLOBAL_LIST == []


def test_assigns_rejects_global_list_write_through_distinct_global() -> None:
    _GLOBAL_LIST.clear()
    _GLOBAL_OTHER_LIST.clear()

    @assigns("global._GLOBAL_LIST[*]")
    def target(x: int) -> int:
        _GLOBAL_OTHER_LIST.append(x)
        return len(_GLOBAL_OTHER_LIST)

    _assert_single_violation(target, ContractKind.ASSIGNS, "global._GLOBAL_OTHER_LIST[*]")
    assert _GLOBAL_LIST == []
    assert _GLOBAL_OTHER_LIST == []


def test_pure_obligation_tracks_global_dict_store_without_mutating_host_global() -> None:
    _GLOBAL_DICT.clear()

    @pure
    def target(x: int) -> int:
        _GLOBAL_DICT["x"] = x
        return len(_GLOBAL_DICT)

    _assert_single_violation(target, ContractKind.PURE, "global._GLOBAL_DICT[*]")
    assert _GLOBAL_DICT == {}


def test_assigns_obligation_tracks_global_dict_store_without_mutating_host_global() -> None:
    _GLOBAL_DICT.clear()

    @assigns()
    def target(x: int) -> int:
        _GLOBAL_DICT["x"] = x
        return len(_GLOBAL_DICT)

    _assert_single_violation(target, ContractKind.ASSIGNS, "global._GLOBAL_DICT[*]")
    assert _GLOBAL_DICT == {}


def test_assigns_allows_global_dict_write_through_definite_entry_alias() -> None:
    _GLOBAL_DICT.clear()

    @assigns("global._GLOBAL_DICT[*]")
    def target(x: int) -> int:
        _GLOBAL_DICT_ALIAS["x"] = x
        return len(_GLOBAL_DICT_ALIAS)

    _assert_verified(target)
    assert _GLOBAL_DICT == {}


def test_pure_obligation_tracks_global_set_add_without_mutating_host_global() -> None:
    _GLOBAL_SET.clear()

    @pure
    def target(x: int) -> int:
        _GLOBAL_SET.add(x)
        return len(_GLOBAL_SET)

    _assert_single_violation(target, ContractKind.PURE, "global._GLOBAL_SET[*]")
    assert _GLOBAL_SET == set()


def test_assigns_obligation_tracks_global_set_add_without_mutating_host_global() -> None:
    _GLOBAL_SET.clear()

    @assigns()
    def target(x: int) -> int:
        _GLOBAL_SET.add(x)
        return len(_GLOBAL_SET)

    _assert_single_violation(target, ContractKind.ASSIGNS, "global._GLOBAL_SET[*]")
    assert _GLOBAL_SET == set()


def test_assigns_allows_global_set_write_through_definite_entry_alias() -> None:
    _GLOBAL_SET.clear()

    @assigns("global._GLOBAL_SET[*]")
    def target(x: int) -> int:
        _GLOBAL_SET_ALIAS.add(x)
        return len(_GLOBAL_SET_ALIAS)

    _assert_verified(target)
    assert _GLOBAL_SET == set()
