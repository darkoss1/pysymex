from __future__ import annotations

from collections.abc import Callable

from pysymex._internal.contracts.enums import VerificationResult
from pysymex.contracts import ContractKind, assigns, pure


def test_effect_obligations_ignore_fresh_closure_container_and_object_writes() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    @pure
    def pure_fresh_list(x: int) -> int:
        xs: list[int] = []

        def child() -> None:
            xs.append(x)

        child()
        return len(xs)

    pure_list_result = verify(pure_fresh_list, {"x": "int"})

    assert pure_list_result.contract_issues == []
    assert pure_list_result.contracts_checked == 1
    assert pure_list_result.contracts_verified == 1

    @assigns()
    def assigns_fresh_object(x: int) -> int:
        class Box:
            value: int

        box = Box()

        def child() -> None:
            box.value = x

        child()
        return box.value

    assigns_object_result = verify(assigns_fresh_object, {"x": "int"})

    assert assigns_object_result.contract_issues == []
    assert assigns_object_result.contracts_checked == 1
    assert assigns_object_result.contracts_verified == 1


def test_pure_reports_factory_captured_nonlocal_write() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def factory() -> Callable[[int], int]:
        value = 0

        @pure
        def target(x: int) -> int:
            nonlocal value
            value = x
            return value

        return target

    result = verify(factory(), {"x": "int"})
    pure_issues = [issue for issue in result.contract_issues if issue.kind is ContractKind.PURE]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "closure.value" in pure_issues[0].message


def test_assigns_reports_factory_captured_object_attribute_write() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def factory() -> Callable[[int], int]:
        class Box:
            value: int

        box = Box()

        @assigns()
        def target(x: int) -> int:
            box.value = x
            return x

        return target

    result = verify(factory(), {"x": "int"})
    assigns_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "box.value" in assigns_issues[0].message


def test_pure_reports_factory_captured_list_append() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def factory() -> tuple[Callable[[int], int], list[int]]:
        xs: list[int] = []

        @pure
        def target(x: int) -> int:
            xs.append(x)
            return len(xs)

        return target, xs

    target, host_xs = factory()
    result = verify(target, {"x": "int"})
    pure_issues = [issue for issue in result.contract_issues if issue.kind is ContractKind.PURE]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_issues[0].message
    assert host_xs == []


def test_effect_obligations_track_factory_captured_dict_and_set_writes() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def dict_factory() -> tuple[Callable[[int], int], dict[str, int]]:
        values: dict[str, int] = {}

        @pure
        def target(x: int) -> int:
            values["x"] = x
            return len(values)

        return target, values

    dict_target, host_dict = dict_factory()
    dict_result = verify(dict_target, {"x": "int"})
    dict_issues = [
        issue for issue in dict_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(dict_issues) == 1
    assert dict_issues[0].result is VerificationResult.VIOLATED
    assert "values[*]" in dict_issues[0].message
    assert host_dict == {}

    def set_factory() -> tuple[Callable[[int], int], set[int]]:
        values: set[int] = set()

        @assigns()
        def target(x: int) -> int:
            values.add(x)
            return len(values)

        return target, values

    set_target, host_set = set_factory()
    set_result = verify(set_target, {"x": "int"})
    set_issues = [
        issue for issue in set_result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(set_issues) == 1
    assert set_issues[0].result is VerificationResult.VIOLATED
    assert "values[*]" in set_issues[0].message
    assert host_set == set()


def test_assigns_allows_factory_captured_list_write_through_definite_alias() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def factory() -> tuple[Callable[[int], int], list[int], list[int]]:
        xs: list[int] = []
        ys = xs

        @assigns("xs[*]")
        def target(x: int) -> int:
            ys.append(x)
            return len(xs) + len(ys)

        return target, xs, ys

    target, host_xs, host_ys = factory()
    result = verify(target, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
    assert host_xs == []
    assert host_ys == []


def test_assigns_rejects_factory_captured_distinct_list_write() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def factory() -> tuple[Callable[[int], int], list[int], list[int]]:
        xs: list[int] = []
        ys: list[int] = []

        @assigns("xs[*]")
        def target(x: int) -> int:
            ys.append(x)
            return len(xs) + len(ys)

        return target, xs, ys

    target, host_xs, host_ys = factory()
    result = verify(target, {"x": "int"})
    assigns_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "ys[*]" in assigns_issues[0].message
    assert host_xs == []
    assert host_ys == []


def test_pure_reports_nested_child_captured_list_append() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def factory() -> tuple[Callable[[int], int], list[int]]:
        xs: list[int] = []

        @pure
        def target(x: int) -> int:
            def child() -> None:
                xs.append(x)

            child()
            return len(xs)

        return target, xs

    target, host_xs = factory()
    result = verify(target, {"x": "int"})
    pure_issues = [issue for issue in result.contract_issues if issue.kind is ContractKind.PURE]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_issues[0].message
    assert host_xs == []


def test_assigns_allows_nested_child_captured_list_write_through_definite_alias() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def factory() -> tuple[Callable[[int], int], list[int], list[int]]:
        xs: list[int] = []
        ys = xs

        @assigns("xs[*]")
        def target(x: int) -> int:
            def child() -> None:
                ys.append(x)

            child()
            return len(xs) + len(ys)

        return target, xs, ys

    target, host_xs, host_ys = factory()
    result = verify(target, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
    assert host_xs == []
    assert host_ys == []


def test_assigns_rejects_nested_child_captured_distinct_list_write() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def factory() -> tuple[Callable[[int], int], list[int], list[int]]:
        xs: list[int] = []
        ys: list[int] = []

        @assigns("xs[*]")
        def target(x: int) -> int:
            def child() -> None:
                ys.append(x)

            child()
            return len(xs) + len(ys)

        return target, xs, ys

    target, host_xs, host_ys = factory()
    result = verify(target, {"x": "int"})
    assigns_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "ys[*]" in assigns_issues[0].message
    assert host_xs == []
    assert host_ys == []
