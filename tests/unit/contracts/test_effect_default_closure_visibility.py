from __future__ import annotations

from pysymex._internal.contracts.enums import VerificationResult
from pysymex.contracts import ContractKind, assigns, pure


def test_pure_reports_nested_child_default_list_append() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    shared: list[int] = []

    @pure
    def target(x: int, xs: list[int] = shared) -> int:
        def child() -> None:
            xs.append(x)

        child()
        return len(xs)

    result = verify(target, {"x": "int"})
    pure_issues = [issue for issue in result.contract_issues if issue.kind is ContractKind.PURE]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_issues[0].message
    assert shared == []


def test_assigns_allows_nested_child_default_list_write_through_definite_alias() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    shared: list[int] = []

    @assigns("xs[*]")
    def target(x: int, xs: list[int] = shared, ys: list[int] = shared) -> int:
        def child() -> None:
            ys.append(x)

        child()
        return len(xs) + len(ys)

    result = verify(target, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
    assert shared == []


def test_assigns_rejects_nested_child_default_distinct_list_write() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    allowed: list[int] = []
    other: list[int] = []

    @assigns("xs[*]")
    def target(x: int, xs: list[int] = allowed, ys: list[int] = other) -> int:
        def child() -> None:
            ys.append(x)

        child()
        return len(xs) + len(ys)

    result = verify(target, {"x": "int"})
    assigns_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "ys[*]" in assigns_issues[0].message
    assert allowed == []
    assert other == []


def test_assigns_tracks_nested_child_keyword_only_default_list_aliases() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    shared: list[int] = []
    other: list[int] = []

    @assigns("xs[*]")
    def alias_target(x: int, *, xs: list[int] = shared, ys: list[int] = shared) -> int:
        def child() -> None:
            ys.append(x)

        child()
        return len(xs) + len(ys)

    alias_result = verify(alias_target, {"x": "int"})

    assert alias_result.contract_issues == []
    assert alias_result.contracts_checked == 1
    assert alias_result.contracts_verified == 1

    @assigns("xs[*]")
    def distinct_target(x: int, *, xs: list[int] = shared, ys: list[int] = other) -> int:
        def child() -> None:
            ys.append(x)

        child()
        return len(xs) + len(ys)

    distinct_result = verify(distinct_target, {"x": "int"})
    assigns_issues = [
        issue for issue in distinct_result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "ys[*]" in assigns_issues[0].message
    assert shared == []
    assert other == []


def test_nested_child_default_dict_writes_track_alias_and_distinct_roots() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    shared: dict[str, int] = {}
    other: dict[str, int] = {}

    @pure
    def pure_target(x: int, values: dict[str, int] = shared) -> int:
        def child() -> None:
            values["x"] = x

        child()
        return len(values)

    pure_result = verify(pure_target, {"x": "int"})
    pure_issues = [
        issue for issue in pure_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "values[*]" in pure_issues[0].message

    @assigns("values[*]")
    def alias_target(
        x: int,
        values: dict[str, int] = shared,
        alias: dict[str, int] = shared,
    ) -> int:
        def child() -> None:
            alias["x"] = x

        child()
        return len(values) + len(alias)

    assert verify(alias_target, {"x": "int"}).contract_issues == []

    @assigns("values[*]")
    def distinct_target(
        x: int,
        values: dict[str, int] = shared,
        alias: dict[str, int] = other,
    ) -> int:
        def child() -> None:
            alias["x"] = x

        child()
        return len(values) + len(alias)

    distinct_result = verify(distinct_target, {"x": "int"})
    assigns_issues = [
        issue for issue in distinct_result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "alias[*]" in assigns_issues[0].message
    assert shared == {}
    assert other == {}


def test_nested_child_default_set_writes_track_alias_and_distinct_roots() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    shared: set[int] = set()
    other: set[int] = set()

    @pure
    def pure_target(x: int, values: set[int] = shared) -> int:
        def child() -> None:
            values.add(x)

        child()
        return len(values)

    pure_result = verify(pure_target, {"x": "int"})
    pure_issues = [
        issue for issue in pure_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "values[*]" in pure_issues[0].message
    assert "model.add" in pure_issues[0].message

    @assigns("values[*]")
    def alias_target(
        x: int,
        values: set[int] = shared,
        alias: set[int] = shared,
    ) -> int:
        def child() -> None:
            alias.add(x)

        child()
        return len(values) + len(alias)

    assert verify(alias_target, {"x": "int"}).contract_issues == []

    @assigns("values[*]")
    def distinct_target(
        x: int,
        values: set[int] = shared,
        alias: set[int] = other,
    ) -> int:
        def child() -> None:
            alias.add(x)

        child()
        return len(values) + len(alias)

    distinct_result = verify(distinct_target, {"x": "int"})
    assigns_issues = [
        issue for issue in distinct_result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "alias[*]" in assigns_issues[0].message
    assert shared == set()
    assert other == set()


def test_nested_child_default_dict_list_value_writes_track_deep_aliases() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    shared: dict[str, list[int]] = {"items": []}
    other: dict[str, list[int]] = {"items": []}

    @pure
    def pure_target(x: int, data: dict[str, list[int]] = shared) -> int:
        def child() -> None:
            data["items"].append(x)

        child()
        return len(data["items"])

    pure_result = verify(pure_target, {"x": "int"})
    pure_issues = [
        issue for issue in pure_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "data[*][*]" in pure_issues[0].message

    @assigns("data[*][*]")
    def alias_target(
        x: int,
        data: dict[str, list[int]] = shared,
        alias: dict[str, list[int]] = shared,
    ) -> int:
        def child() -> None:
            alias["items"].append(x)

        child()
        return len(data["items"]) + len(alias["items"])

    assert verify(alias_target, {"x": "int"}).contract_issues == []

    @assigns("data[*][*]")
    def distinct_target(
        x: int,
        data: dict[str, list[int]] = shared,
        alias: dict[str, list[int]] = other,
    ) -> int:
        def child() -> None:
            alias["items"].append(x)

        child()
        return len(data["items"]) + len(alias["items"])

    distinct_result = verify(distinct_target, {"x": "int"})
    assigns_issues = [
        issue for issue in distinct_result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "alias[*][*]" in assigns_issues[0].message
    assert shared == {"items": []}
    assert other == {"items": []}
