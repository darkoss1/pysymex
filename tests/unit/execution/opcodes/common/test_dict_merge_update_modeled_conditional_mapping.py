from __future__ import annotations

from typing import cast

from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.mapping_protocol.extraction import (
    UNSUPPORTED_MAPPING_PROTOCOL,
)
from pysymex._internal.core.classes.registry import class_registry
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.collections.mutation.dicts import (
    handle_common_dict_merge_update,
)
from pysymex._internal.execution.opcodes.common.functions.classes.instances.values import (
    modeled_instance_value,
)
from pysymex._internal.typing.protocols import StackValue
from tests.unit.execution.opcodes.common.collections_helpers import instr


class ConditionalMap:
    def keys(self) -> object:
        return ["a", "b"]

    def __getitem__(self, key: object) -> object:
        if key == "a":
            return 3
        if key == "b":
            return 5
        raise KeyError(key)


class ConditionalNonStringMap:
    def keys(self) -> object:
        return [1]

    def __getitem__(self, key: object) -> object:
        if key == 1:
            return 2
        raise KeyError(key)


class ConditionalConstLeftMap:
    def keys(self) -> object:
        return ["a"]

    def __getitem__(self, key: object) -> object:
        if "a" == key:
            return 7
        raise KeyError(key)


class ConditionalMissingMap:
    def keys(self) -> object:
        return ["missing"]

    def __getitem__(self, key: object) -> object:
        if key == "a":
            return 3
        raise KeyError(key)


ConditionalSource = (
    type[ConditionalMap]
    | type[ConditionalNonStringMap]
    | type[ConditionalConstLeftMap]
    | type[ConditionalMissingMap]
)


def _kwargs_target(**kwargs: object) -> dict[str, object]:
    return kwargs


def _modeled_conditional_value(
    class_name: str,
    source_cls: ConditionalSource,
) -> StackValue:
    modeled_cls = SymbolicClass(class_name)
    modeled_cls.add_method("keys", source_cls.keys.__code__, parameters=["self"])
    modeled_cls.add_method(
        "__getitem__",
        source_cls.__getitem__.__code__,
        parameters=["self", "key"],
    )
    instance = class_registry.create_instance(modeled_cls)
    return modeled_instance_value(modeled_cls.name, instance, 67)


def test_handle_common_dict_update_accepts_modeled_conditional_getitem() -> None:
    state = VMState(
        stack=[
            SymbolicDict.from_const({}),
            _modeled_conditional_value("ModeledConditionalMap", ConditionalMap),
        ],
        pc=67,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key("a") == (True, 3)
    assert updated.concrete_value_for_key("b") == (True, 5)


def test_handle_common_dict_merge_rejects_modeled_conditional_non_string_key() -> None:
    stack = cast(
        "list[StackValue]",
        [
            _kwargs_target,
            None,
            (),
            SymbolicDict.from_const({}),
            _modeled_conditional_value(
                "ModeledConditionalNonStringMap",
                ConditionalNonStringMap,
            ),
        ],
    )
    state = VMState(stack=stack, pc=68)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "keywords must be strings" in result.issues[0].message


def test_handle_common_dict_update_accepts_modeled_conditional_const_left_getitem() -> None:
    state = VMState(
        stack=[
            SymbolicDict.from_const({}),
            _modeled_conditional_value("ModeledConditionalConstLeftMap", ConditionalConstLeftMap),
        ],
        pc=70,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key("a") == (True, 7)


def test_handle_common_dict_update_degrades_missing_conditional_key() -> None:
    state = VMState(
        stack=[
            SymbolicDict.empty("dict_update"),
            _modeled_conditional_value("ModeledConditionalMissingMap", ConditionalMissingMap),
        ],
        pc=69,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert result.issues == []
    assert result.degraded_passes == [UNSUPPORTED_MAPPING_PROTOCOL]
    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key("missing") == (False, None)
