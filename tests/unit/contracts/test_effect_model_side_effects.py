from __future__ import annotations

import bisect
import heapq
import random
from collections.abc import Callable

from pysymex._internal.contracts.enums import VerificationResult
from pysymex.contracts import ContractKind, assigns, pure


def test_effect_obligations_track_generic_mutates_arg_side_effects() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    @pure
    def pure_heapify(xs: list[int], heapify: Callable[[list[int]], None] = heapq.heapify) -> int:
        heapify(xs)
        return len(xs)

    pure_result = verify(pure_heapify, {"xs": "list"})
    pure_issues = [
        issue for issue in pure_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_issues[0].message
    assert "model.mutates_arg" in pure_issues[0].message

    @assigns()
    def assigns_insort(
        xs: list[int],
        x: int,
        insort: Callable[[list[int], int], None] = bisect.insort,
    ) -> int:
        insort(xs, x)
        return len(xs)

    assigns_result = verify(assigns_insort, {"xs": "list", "x": "int"})
    assigns_issues = [
        issue for issue in assigns_result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in assigns_issues[0].message
    assert "model.mutates_arg" in assigns_issues[0].message

    @pure
    def pure_shuffle(xs: list[int], shuffle: Callable[[list[int]], None] = random.shuffle) -> int:
        shuffle(xs)
        return len(xs)

    shuffle_result = verify(pure_shuffle, {"xs": "list"})
    shuffle_issues = [
        issue for issue in shuffle_result.contract_issues if issue.kind is ContractKind.PURE
    ]

    assert len(shuffle_issues) == 1
    assert shuffle_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in shuffle_issues[0].message
    assert "model.mutates_arg" in shuffle_issues[0].message


def test_effect_obligations_ignore_generic_mutates_arg_on_fresh_locals() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    @pure
    def pure_local_heapify(
        x: int,
        heapify: Callable[[list[int]], None] = heapq.heapify,
    ) -> int:
        xs: list[int] = []
        heapify(xs)
        return len(xs) + x

    result = verify(pure_local_heapify, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
