from __future__ import annotations

from pysymex._internal.contracts.enums import VerificationResult
from pysymex.contracts import ContractKind, assigns, pure


def test_effect_obligations_ignore_non_escaping_nested_local_container_writes() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    @pure
    def pure_child_local_only(x: int) -> int:
        def child() -> int:
            ys: list[int] = []
            ys.append(1)
            return len(ys)

        return child() + x

    pure_result = verify(pure_child_local_only, {"x": "int"})

    assert pure_result.contract_issues == []
    assert pure_result.contracts_checked == 1
    assert pure_result.contracts_verified == 1

    @assigns()
    def assigns_empty_child_local_only(x: int) -> int:
        def child() -> int:
            ys: list[int] = []
            ys.append(1)
            return len(ys)

        return child() + x

    assigns_result = verify(assigns_empty_child_local_only, {"x": "int"})

    assert assigns_result.contract_issues == []
    assert assigns_result.contracts_checked == 1
    assert assigns_result.contracts_verified == 1


def test_effect_obligations_ignore_same_frame_fresh_local_container_writes() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    @pure
    def pure_local_list(x: int) -> int:
        xs: list[int] = []
        xs.append(x)
        return len(xs)

    pure_list_result = verify(pure_local_list, {"x": "int"})

    assert pure_list_result.contract_issues == []
    assert pure_list_result.contracts_checked == 1
    assert pure_list_result.contracts_verified == 1

    @assigns()
    def assigns_empty_local_dict(x: int) -> int:
        local: dict[str, int] = {}
        local["x"] = x
        return len(local)

    assigns_dict_result = verify(assigns_empty_local_dict, {"x": "int"})

    assert assigns_dict_result.contract_issues == []
    assert assigns_dict_result.contracts_checked == 1
    assert assigns_dict_result.contracts_verified == 1

    @pure
    def pure_local_set(x: int) -> int:
        local: set[int] = set()
        local.add(x)
        return len(local)

    pure_set_result = verify(pure_local_set, {"x": "int"})

    assert pure_set_result.contract_issues == []
    assert pure_set_result.contracts_checked == 1
    assert pure_set_result.contracts_verified == 1

    @pure
    def pure_local_bytearray(x: int) -> int:
        local = bytearray()
        local.append(1)
        return len(local) + x

    pure_bytearray_result = verify(pure_local_bytearray, {"x": "int"})

    assert pure_bytearray_result.contract_issues == []
    assert pure_bytearray_result.contracts_checked == 1
    assert pure_bytearray_result.contracts_verified == 1


def test_effect_obligations_still_track_argument_alias_after_local_rename() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    @pure
    def pure_alias_deleted(xs: list[int], x: int) -> int:
        ys = xs
        del xs
        ys.append(x)
        return len(ys)

    result = verify(pure_alias_deleted, {"xs": "list", "x": "int"})
    pure_issues = [issue for issue in result.contract_issues if issue.kind is ContractKind.PURE]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_issues[0].message


def test_effect_obligations_track_omitted_mutable_default_writes() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    @pure
    def pure_default_list(xs: list[int] = []) -> int:
        xs.append(1)
        return len(xs)

    pure_default_list.__defaults__ = ([],)
    pure_result = verify(pure_default_list, {})
    pure_issues = [
        issue for issue in pure_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_issues[0].message

    @assigns()
    def assigns_default_list(xs: list[int] = []) -> int:
        xs.append(1)
        return len(xs)

    assigns_default_list.__defaults__ = ([],)
    assigns_result = verify(assigns_default_list, {})
    assigns_issues = [
        issue for issue in assigns_result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in assigns_issues[0].message

    @pure
    def pure_default_set(xs: set[int] = set()) -> int:
        xs.add(1)
        return len(xs)

    pure_default_set.__defaults__ = (set(),)
    pure_set_result = verify(pure_default_set, {})
    pure_set_issues = [
        issue for issue in pure_set_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(pure_set_issues) == 1
    assert pure_set_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_set_issues[0].message
    assert "model.add" in pure_set_issues[0].message

    @assigns()
    def assigns_default_set(xs: set[int] = set()) -> int:
        xs.add(1)
        return len(xs)

    assigns_default_set.__defaults__ = (set(),)
    assigns_set_result = verify(assigns_default_set, {})
    assigns_set_issues = [
        issue for issue in assigns_set_result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_set_issues) == 1
    assert assigns_set_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in assigns_set_issues[0].message
    assert "model.add" in assigns_set_issues[0].message


def test_effect_obligations_track_nested_omitted_mutable_default_writes() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    @pure
    def child(xs: list[int] = []) -> int:
        xs.append(1)
        return len(xs)

    child.__defaults__ = ([],)

    def caller() -> int:
        return child()

    result = verify(caller, {})
    pure_issues = [issue for issue in result.contract_issues if issue.kind is ContractKind.PURE]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_issues[0].message

    @pure
    def set_child(xs: set[int] = set()) -> int:
        xs.add(1)
        return len(xs)

    set_child.__defaults__ = (set(),)

    def set_caller() -> int:
        return set_child()

    set_result = verify(set_caller, {})
    pure_set_issues = [
        issue for issue in set_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(pure_set_issues) == 1
    assert pure_set_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_set_issues[0].message
    assert "model.add" in pure_set_issues[0].message


def test_pure_obligation_under_unmodeled_call_side_effect_is_unknown() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    class Mutator:
        def __call__(self, xs: list[int]) -> int:
            xs.append(1)
            return 0

    mutator = Mutator()

    @pure
    def target(xs: list[int], callback: Mutator = mutator) -> int:
        callback(xs)
        return 0

    concrete_xs: list[int] = []
    target(concrete_xs)
    assert len(concrete_xs) == 1

    res = verify(target, {"xs": "list"})

    assert res.degraded_passes == ["unmodeled_call_abstraction"]
    assert res.contracts_checked == 1
    assert res.contracts_verified == 0
    assert res.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in res.contract_issues] == [
        (ContractKind.PURE, VerificationResult.UNKNOWN)
    ]


def test_nested_argument_writes_are_checked_against_caller_assigns_roots() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    @assigns("xs[*]")
    def assigns_xs_nested_child(xs: list[int]) -> int:
        def child(ys: list[int]) -> None:
            ys.append(1)

        child(xs)
        return len(xs)

    assigns_result = verify(assigns_xs_nested_child, {"xs": "list"})

    assert assigns_result.contract_issues == []
    assert assigns_result.contracts_checked == 1
    assert assigns_result.contracts_verified == 1

    @pure
    def pure_nested_child(xs: list[int]) -> int:
        def child(ys: list[int]) -> None:
            ys.append(1)

        child(xs)
        return len(xs)

    pure_result = verify(pure_nested_child, {"xs": "list"})
    pure_issues = [
        issue for issue in pure_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_issues[0].message
