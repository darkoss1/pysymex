from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.mapping_protocol.extraction import (
    UNSUPPORTED_MAPPING_PROTOCOL,
)
from pysymex._internal.core.classes.registry import class_registry
from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.fallback.types import FallbackKind, RiskLevel, SoundnessTag
from pysymex._internal.execution.opcodes.common.collections.mutation.dicts import (
    handle_common_dict_merge_update,
)
from pysymex._internal.execution.opcodes.common.functions.classes.instances.values import (
    modeled_instance_value,
)
from pysymex._internal.typing.protocols import StackValue
from tests.unit.execution.opcodes.common.collections_helpers import instr


@dataclass(frozen=True)
class Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


class KeysOnly:
    def __init__(self, data: dict[object, object]) -> None:
        self.data = data

    def keys(self) -> object:
        return self.data.keys()

    def __getitem__(self, key: object) -> object:
        return self.data[key]


class BadKeys:
    def keys(self) -> object:
        return 1

    def __getitem__(self, key: object) -> object:
        return 2


class MissingKey:
    def keys(self) -> object:
        return ["missing"]

    def __getitem__(self, key: object) -> object:
        raise KeyError(key)


class ItemsOnly:
    def items(self) -> list[tuple[str, int]]:
        return [("a", 1)]


def _kwargs_target(**kwargs: object) -> dict[str, object]:
    return kwargs


def _modeled_keys_only_value(data: SymbolicDict | dict[object, object]) -> StackValue:
    modeled_cls = SymbolicClass("ModeledKeysOnlyMappingProtocol")
    modeled_cls.add_method("keys", KeysOnly.keys.__code__, parameters=["self"])
    modeled_cls.add_method(
        "__getitem__",
        KeysOnly.__getitem__.__code__,
        parameters=["self", "key"],
    )
    instance = class_registry.create_instance(modeled_cls, {"data": data})
    return modeled_instance_value(modeled_cls.name, instance, 50)


def _modeled_plain_value(class_name: str) -> StackValue:
    modeled_cls = SymbolicClass(class_name)
    instance = class_registry.create_instance(modeled_cls)
    return modeled_instance_value(modeled_cls.name, instance, 53)


def _modeled_dynamic_attr_value() -> StackValue:
    modeled_cls = SymbolicClass("ModeledDynamicAttributeMaybeMapping")
    modeled_cls.add_method("__getattr__", parameters=["self", "name"])
    instance = class_registry.create_instance(modeled_cls)
    return modeled_instance_value(modeled_cls.name, instance, 54)


def test_handle_common_dict_update_accepts_keys_getitem_mapping_protocol() -> None:
    state = VMState(
        stack=cast(
            "list[StackValue]",
            [SymbolicDict.from_const({}), KeysOnly({1: 2, "a": 3})],
        ),
        pc=44,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key(1) == (True, 2)
    assert updated.concrete_value_for_key("a") == (True, 3)


def test_handle_common_dict_update_accepts_modeled_keys_getitem_wrapper() -> None:
    stack: list[StackValue] = [
        SymbolicDict.from_const({}),
        _modeled_keys_only_value(SymbolicDict.from_const({1: 2})),
    ]
    state = VMState(stack=stack, pc=50)

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key(1) == (True, 2)


def test_handle_common_dict_merge_accepts_keys_getitem_keyword_mapping() -> None:
    stack = cast(
        "list[StackValue]",
        [_kwargs_target, None, (), SymbolicDict.from_const({}), KeysOnly({"a": 3})],
    )
    state = VMState(stack=stack, pc=45)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key("a") == (True, 3)


def test_handle_common_dict_merge_accepts_modeled_keys_getitem_keyword_wrapper() -> None:
    stack = cast(
        "list[StackValue]",
        [
            _kwargs_target,
            None,
            (),
            SymbolicDict.from_const({}),
            _modeled_keys_only_value(SymbolicDict.from_const({"a": 3})),
        ],
    )
    state = VMState(stack=stack, pc=51)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key("a") == (True, 3)


def test_handle_common_dict_merge_rejects_keys_mapping_non_string_keyword_key() -> None:
    stack = cast(
        "list[StackValue]",
        [_kwargs_target, None, (), SymbolicDict.empty("kwargs"), KeysOnly({1: 2})],
    )
    state = VMState(stack=stack, pc=46)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "keywords must be strings" in result.issues[0].message


def test_handle_common_dict_merge_rejects_modeled_mapping_non_string_keyword_key() -> None:
    stack = cast(
        "list[StackValue]",
        [
            _kwargs_target,
            None,
            (),
            SymbolicDict.from_const({}),
            _modeled_keys_only_value(SymbolicDict.from_const({1: 2})),
        ],
    )
    state = VMState(stack=stack, pc=52)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "keywords must be strings" in result.issues[0].message


def test_handle_common_dict_update_rejects_modeled_instance_without_keys() -> None:
    state = VMState(
        stack=[SymbolicDict.empty("dict_update"), _modeled_plain_value("ModeledPlain")],
        pc=53,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "'ModeledPlain' object is not a mapping" in result.issues[0].message


def test_handle_common_dict_merge_rejects_modeled_instance_without_keys() -> None:
    stack = cast(
        "list[StackValue]",
        [
            _kwargs_target,
            None,
            (),
            SymbolicDict.from_const({}),
            _modeled_plain_value("ModeledPlainKwargs"),
        ],
    )
    state = VMState(stack=stack, pc=54)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "argument after ** must be a mapping, not ModeledPlainKwargs" in result.issues[0].message


def test_handle_common_dict_update_degrades_dynamic_modeled_instance() -> None:
    state = VMState(
        stack=[SymbolicDict.empty("dict_update"), _modeled_dynamic_attr_value()],
        pc=55,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert result.issues == []
    assert result.degraded_passes == [UNSUPPORTED_MAPPING_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_MAPPING_PROTOCOL
    assert event.owner == "execution.opcodes.collections"
    assert event.reason == "modeled mapping protocol was inconclusive for DICT_UPDATE"
    assert event.pc == 55
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_dict_update_reports_bad_keys_result() -> None:
    state = VMState(
        stack=cast("list[StackValue]", [SymbolicDict.empty("dict_update"), BadKeys()]),
        pc=47,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "BadKeys.keys() returned a non-iterable (type int)" in result.issues[0].message


def test_handle_common_dict_update_routes_getitem_key_error_to_handler() -> None:
    dispatcher = OpcodeDispatcher()
    update = instr("DICT_UPDATE", 1, arg=1, offset=4)
    dispatcher.set_instructions([update, instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    state = VMState(
        stack=cast("list[StackValue]", [SymbolicDict.empty("dict_update"), MissingKey()]),
        pc=48,
    )

    result = handle_common_dict_merge_update(update, state, dispatcher)

    assert not result.terminal
    assert result.issues == []
    routed = result.new_states[0].stack[-1]
    assert isinstance(routed, SymbolicException)
    assert routed.type_name == "KeyError"


def test_handle_common_dict_update_rejects_items_only_protocol() -> None:
    state = VMState(
        stack=cast("list[StackValue]", [SymbolicDict.empty("dict_update"), ItemsOnly()]),
        pc=49,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "'ItemsOnly' object is not a mapping" in result.issues[0].message
