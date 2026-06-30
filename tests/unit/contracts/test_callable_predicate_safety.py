from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import cast

import pytest
import z3

from pysymex._internal.contracts.combinators import And_, Implies_, Not_, Or_
from pysymex._internal.contracts.compiler import ContractCompiler
from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.execution.executors.verified.api import verify
from pysymex.contracts import ContractKind, ensures

_global_mutation_marker = 0


def test_trace_callable_rejects_global_assignment_before_execution() -> None:
    global _global_mutation_marker
    _global_mutation_marker = 0

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        global _global_mutation_marker
        _global_mutation_marker = 1
        return value > 0

    with pytest.raises(ValueError, match="STORE_GLOBAL"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert _global_mutation_marker == 0


def test_trace_callable_rejects_nonlocal_assignment_before_execution() -> None:
    def make_predicate() -> tuple[Callable[[z3.ArithRef], z3.BoolRef], Callable[[], int]]:
        threshold = 0

        def predicate(value: z3.ArithRef) -> z3.BoolRef:
            nonlocal threshold
            threshold = 1
            return value > 0

        return predicate, lambda: threshold

    predicate, read_threshold = make_predicate()

    with pytest.raises(ValueError, match="STORE_DEREF"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert read_threshold() == 0


def test_trace_callable_rejects_subscript_assignment_before_execution() -> None:
    box = [0]

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        box[0] = 1
        return value > 0

    with pytest.raises(ValueError, match="STORE_SUBSCR"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert box == [0]


def test_trace_callable_rejects_global_property_access_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[str] = []

        @property
        def value(self) -> int:
            self.events.append("property-called")
            return 1

    box = Box()

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        return value > box.value

    with pytest.raises(ValueError, match="LOAD_ATTR"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert box.events == []


def test_trace_callable_rejects_default_parameter_property_access_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[str] = []

        @property
        def value(self) -> int:
            self.events.append("property-called")
            return 1

    box = Box()

    def predicate(value: z3.ArithRef, default_box: Box = box) -> z3.BoolRef:
        return value > default_box.value

    with pytest.raises(ValueError, match="LOAD_ATTR"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert box.events == []


def test_trace_callable_rejects_closure_property_access_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[str] = []

        @property
        def value(self) -> int:
            self.events.append("property-called")
            return 1

    box = Box()

    def make_predicate() -> Callable[[z3.ArithRef], z3.BoolRef]:
        def predicate(value: z3.ArithRef) -> z3.BoolRef:
            return value > box.value

        return predicate

    with pytest.raises(ValueError, match="LOAD_ATTR"):
        ContractCompiler.trace_callable(make_predicate(), {"value": z3.Int("value")})

    assert box.events == []


def test_trace_callable_rejects_subscript_read_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[object] = []

        def __getitem__(self, index: object) -> int:
            self.events.append(index)
            return 1

    box = Box()

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        return value > box[0]

    with pytest.raises(ValueError, match="BINARY_SUBSCR"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert box.events == []


def test_trace_callable_rejects_slice_read_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[object] = []

        def __getitem__(self, index: object) -> int:
            self.events.append(index)
            return 1

    box = Box()

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        return value > box[0:1]

    with pytest.raises(ValueError, match="BINARY_SLICE|BINARY_SUBSCR"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert box.events == []


def test_trace_callable_rejects_membership_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[object] = []

        def __contains__(self, item: object) -> bool:
            self.events.append(item)
            return True

    box = Box()

    def predicate(value: z3.ArithRef) -> bool:
        return value in box

    with pytest.raises(ValueError, match="CONTAINS_OP"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert box.events == []


def test_trace_callable_rejects_iteration_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[str] = []

        def __iter__(self) -> Iterator[int]:
            self.events.append("iter")
            return iter([1])

    box = Box()

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        for item in box:
            return value > item
        return value > 0

    with pytest.raises(ValueError, match="GET_ITER"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert box.events == []


def test_trace_callable_rejects_host_comparison_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[object] = []

        def __lt__(self, other: object) -> bool:
            self.events.append(other)
            return True

    box = Box()

    def predicate(value: z3.ArithRef) -> bool:
        return box < value

    with pytest.raises(ValueError, match="COMPARE_OP"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert box.events == []


def test_trace_callable_rejects_host_bool_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[str] = []

        def __bool__(self) -> bool:
            self.events.append("bool")
            return True

    box = Box()

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        if box:
            return value > 0
        return value < 0

    with pytest.raises(
        ValueError,
        match="TO_BOOL|POP_JUMP_IF_FALSE|POP_JUMP_FORWARD_IF_FALSE|POP_JUMP_BACKWARD_IF_FALSE|JUMP_IF_FALSE_OR_POP",
    ):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert box.events == []


def test_trace_callable_rejects_host_len_truthiness_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[str] = []

        def __len__(self) -> int:
            self.events.append("len")
            return 1

    box = Box()

    def predicate(value: z3.ArithRef) -> object:
        return box and value > 0

    with pytest.raises(
        ValueError,
        match="TO_BOOL|POP_JUMP_IF_FALSE|POP_JUMP_FORWARD_IF_FALSE|POP_JUMP_BACKWARD_IF_FALSE|JUMP_IF_FALSE_OR_POP",
    ):
        ContractCompiler.trace_callable(
            cast("Callable[..., z3.BoolRef | bool]", predicate),
            {"value": z3.Int("value")},
        )

    assert box.events == []


def test_trace_callable_rejects_format_simple_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[tuple[str, str]] = []

        def __format__(self, spec: str) -> str:
            self.events.append(("format", spec))
            return "x"

    box = Box()

    def predicate(value: z3.ArithRef) -> object:
        _ = value
        return f"{box}"

    with pytest.raises(ValueError, match="FORMAT_SIMPLE|FORMAT_VALUE"):
        ContractCompiler.trace_callable(
            cast("Callable[..., z3.BoolRef | bool]", predicate),
            {"value": z3.Int("value")},
        )

    assert box.events == []


def test_trace_callable_rejects_format_with_spec_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[tuple[str, str]] = []

        def __format__(self, spec: str) -> str:
            self.events.append(("format", spec))
            return "x"

    box = Box()

    def predicate(value: z3.ArithRef) -> object:
        _ = value
        return f"{box:>3}"

    with pytest.raises(ValueError, match="FORMAT_WITH_SPEC|FORMAT_VALUE"):
        ContractCompiler.trace_callable(
            cast("Callable[..., z3.BoolRef | bool]", predicate),
            {"value": z3.Int("value")},
        )

    assert box.events == []


def test_trace_callable_rejects_format_conversion_before_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[str] = []

        def __repr__(self) -> str:
            self.events.append("repr")
            return "x"

    box = Box()

    def predicate(value: z3.ArithRef) -> object:
        _ = value
        return f"{box!r}"

    with pytest.raises(ValueError, match="CONVERT_VALUE|FORMAT_VALUE"):
        ContractCompiler.trace_callable(
            cast("Callable[..., z3.BoolRef | bool]", predicate),
            {"value": z3.Int("value")},
        )

    assert box.events == []


def test_trace_callable_allows_local_temporaries_and_closure_reads() -> None:
    minimum = 3

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        offset = 1
        return value > minimum + offset

    formula = ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert z3.eq(formula, z3.Int("value") > 4)


def test_trace_callable_rejects_method_call_side_effect_before_execution() -> None:
    events: list[str] = []

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        events.append("called")
        return value > 0

    with pytest.raises(ValueError, match="LOAD_ATTR|LOAD_METHOD"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert events == []


def test_trace_callable_rejects_helper_call_before_execution() -> None:
    helper_calls: list[str] = []

    def helper(value: z3.ArithRef) -> z3.BoolRef:
        helper_calls.append("called")
        return value > 0

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        return helper(value)

    with pytest.raises(ValueError, match="CALL"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert helper_calls == []


def test_trace_callable_rejects_keyword_helper_call_before_execution() -> None:
    helper_calls: list[str] = []

    def helper(*, value: z3.ArithRef) -> z3.BoolRef:
        helper_calls.append("called")
        return value > 0

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        return helper(value=value)

    with pytest.raises(ValueError, match="CALL_KW|CALL"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert helper_calls == []


def test_trace_callable_rejects_keyword_method_call_before_execution() -> None:
    calls: list[z3.ArithRef] = []

    class Recorder:
        def record(self, *, value: z3.ArithRef) -> None:
            calls.append(value)

    recorder = Recorder()

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        recorder.record(value=value)
        return value > 0

    with pytest.raises(ValueError, match="LOAD_ATTR|LOAD_METHOD|CALL"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert calls == []


def test_trace_callable_allows_contract_combinator_calls() -> None:
    symbols = {"x": z3.Int("x"), "y": z3.Int("y")}

    def predicate(x: z3.ArithRef, y: z3.ArithRef) -> z3.BoolRef:
        return And_(Or_(x > 0, y > 0), Not_(x == y), Implies_(x > 10, y > 0))

    formula = ContractCompiler.trace_callable(predicate, symbols)

    assert z3.eq(
        formula,
        z3.And(
            z3.Or(symbols["x"] > 0, symbols["y"] > 0),
            z3.Not(symbols["x"] == symbols["y"]),
            z3.Implies(symbols["x"] > 10, symbols["y"] > 0),
        ),
    )


def test_trace_callable_rejects_shadowed_combinator_call_before_execution() -> None:
    calls: list[str] = []

    def And_(*conditions: z3.BoolRef) -> z3.BoolRef:  # noqa: N802
        calls.append("called")
        return z3.And(*conditions)

    def predicate(value: z3.ArithRef) -> z3.BoolRef:
        return And_(value > 0)

    with pytest.raises(ValueError, match="CALL"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert calls == []


def test_trace_callable_rejects_callable_object_side_effect_before_execution() -> None:
    class Predicate:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, value: z3.ArithRef) -> z3.BoolRef:
            self.calls = self.calls + 1
            return value > 0

    predicate = Predicate()

    with pytest.raises(ValueError, match="STORE_ATTR"):
        ContractCompiler.trace_callable(predicate, {"value": z3.Int("value")})

    assert predicate.calls == 0


def test_runtime_callable_predicate_host_mutation_is_unsupported_without_execution() -> None:
    box = [0]

    def predicate(result: z3.ArithRef) -> z3.BoolRef:
        box[0] = 1
        return result > 0

    @ensures(predicate)
    def target(value: int) -> int:
        return value

    result = verify(target, {"value": "int"})

    assert box == [0]
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]
    assert "host-state mutation opcode STORE_SUBSCR" in result.contract_issues[0].message


def test_runtime_callable_predicate_call_side_effect_is_unsupported_without_execution() -> None:
    calls: list[str] = []

    def predicate(result: z3.ArithRef) -> z3.BoolRef:
        calls.append("called")
        return result > 0

    @ensures(predicate)
    def target(value: int) -> int:
        return value

    result = verify(target, {"value": "int"})

    assert calls == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]
    assert any(
        x in result.contract_issues[0].message
        for x in ("host-runtime effect opcode LOAD_ATTR", "host-runtime effect opcode LOAD_METHOD")
    )


def test_runtime_callable_predicate_keyword_call_side_effect_is_unsupported() -> None:
    calls: list[str] = []

    def helper(*, value: z3.ArithRef) -> z3.BoolRef:
        calls.append("called")
        return value > 0

    def predicate(result: z3.ArithRef) -> z3.BoolRef:
        return helper(value=result)

    @ensures(predicate)
    def target(value: int) -> int:
        return value

    result = verify(target, {"value": "int"})

    assert calls == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]
    assert "host-runtime effect opcode CALL" in result.contract_issues[0].message


def test_runtime_callable_predicate_property_access_is_unsupported_without_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[str] = []

        @property
        def value(self) -> int:
            self.events.append("property-called")
            return 1

    box = Box()

    def predicate(result: z3.ArithRef) -> z3.BoolRef:
        return result > box.value

    @ensures(predicate)
    def target(value: int) -> int:
        return value

    result = verify(target, {"value": "int"})

    assert box.events == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]
    assert "host-runtime effect opcode LOAD_ATTR" in result.contract_issues[0].message


def test_runtime_callable_predicate_subscript_read_is_unsupported_without_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[object] = []

        def __getitem__(self, index: object) -> int:
            self.events.append(index)
            return 1

    box = Box()

    def predicate(result: z3.ArithRef) -> z3.BoolRef:
        return result > box[0]

    @ensures(predicate)
    def target(value: int) -> int:
        return value

    result = verify(target, {"value": "int"})

    assert box.events == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]
    assert "host-runtime effect opcode BINARY_SUBSCR" in result.contract_issues[0].message


def test_runtime_callable_predicate_membership_is_unsupported_without_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[object] = []

        def __contains__(self, item: object) -> bool:
            self.events.append(item)
            return True

    box = Box()

    def predicate(result: z3.ArithRef) -> bool:
        return result in box

    @ensures(predicate)
    def target(value: int) -> int:
        return value

    result = verify(target, {"value": "int"})

    assert box.events == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]
    assert "host-runtime effect opcode CONTAINS_OP" in result.contract_issues[0].message


def test_runtime_callable_predicate_truthiness_is_unsupported_without_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[str] = []

        def __bool__(self) -> bool:
            self.events.append("bool")
            return True

    box = Box()

    def predicate(result: z3.ArithRef) -> z3.BoolRef:
        if box:
            return result > 0
        return result < 0

    @ensures(predicate)
    def target(value: int) -> int:
        return value

    result = verify(target, {"value": "int"})

    assert box.events == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]
    assert any(
        x in result.contract_issues[0].message
        for x in (
            "TO_BOOL",
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_FORWARD_IF_FALSE",
            "POP_JUMP_BACKWARD_IF_FALSE",
            "JUMP_IF_FALSE_OR_POP",
        )
    )


def test_runtime_callable_predicate_formatting_is_unsupported_without_execution() -> None:
    class Box:
        def __init__(self) -> None:
            self.events: list[tuple[str, str]] = []

        def __format__(self, spec: str) -> str:
            self.events.append(("format", spec))
            return "x"

    box = Box()

    def predicate(result: z3.ArithRef) -> object:
        _ = result
        return f"{box}"

    @ensures(cast("Callable[..., z3.BoolRef | bool]", predicate))
    def target(value: int) -> int:
        return value

    result = verify(target, {"value": "int"})

    assert box.events == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]
    assert any(x in result.contract_issues[0].message for x in ("FORMAT_SIMPLE", "FORMAT_VALUE"))
