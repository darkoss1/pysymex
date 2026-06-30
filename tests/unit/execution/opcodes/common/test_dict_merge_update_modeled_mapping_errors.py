from __future__ import annotations

from typing import cast

from pysymex._internal.core.classes.classes import SymbolicClass
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


class BadKeys:
    def keys(self) -> object:
        return 1

    def __getitem__(self, key: object) -> object:
        return 2


class ConstMap:
    def keys(self) -> object:
        return ("a",)

    def __getitem__(self, key: object) -> object:
        return 3


class ConstNonStringMap:
    def keys(self) -> object:
        return (1,)

    def __getitem__(self, key: object) -> object:
        return 2


class ListKeysMap:
    def keys(self) -> object:
        return ["a"]

    def __getitem__(self, key: object) -> object:
        return 3


class ListKeysNonStringMap:
    def keys(self) -> object:
        return [1]

    def __getitem__(self, key: object) -> object:
        return 2


class KeySensitiveMap:
    def keys(self) -> object:
        return ["a", "b"]

    def __getitem__(self, key: str) -> object:
        return {"a": 3, "b": 5}[key]


class KeySensitiveNonStringMap:
    def keys(self) -> object:
        return [1]

    def __getitem__(self, key: int) -> object:
        return {1: 2}[key]


def _kwargs_target(**kwargs: object) -> dict[str, object]:
    return kwargs


def _modeled_bad_keys_value(class_name: str, *, dynamic_lookup: bool = False) -> StackValue:
    modeled_cls = SymbolicClass(class_name)
    modeled_cls.add_method("keys", BadKeys.keys.__code__, parameters=["self"])
    modeled_cls.add_method(
        "__getitem__",
        BadKeys.__getitem__.__code__,
        parameters=["self", "key"],
    )
    if dynamic_lookup:
        modeled_cls.add_method("__getattribute__", parameters=["self", "name"])
    instance = class_registry.create_instance(modeled_cls)
    return modeled_instance_value(modeled_cls.name, instance, 56)


def _modeled_const_map_value(
    class_name: str,
    *,
    non_string: bool = False,
    dynamic_lookup: bool = False,
) -> StackValue:
    source_cls = ConstNonStringMap if non_string else ConstMap
    modeled_cls = SymbolicClass(class_name)
    modeled_cls.add_method("keys", source_cls.keys.__code__, parameters=["self"])
    modeled_cls.add_method(
        "__getitem__",
        source_cls.__getitem__.__code__,
        parameters=["self", "key"],
    )
    if dynamic_lookup:
        modeled_cls.add_method("__getattribute__", parameters=["self", "name"])
    instance = class_registry.create_instance(modeled_cls)
    return modeled_instance_value(modeled_cls.name, instance, 59)


def _modeled_list_keys_map_value(class_name: str, *, non_string: bool = False) -> StackValue:
    source_cls = ListKeysNonStringMap if non_string else ListKeysMap
    modeled_cls = SymbolicClass(class_name)
    modeled_cls.add_method("keys", source_cls.keys.__code__, parameters=["self"])
    modeled_cls.add_method(
        "__getitem__",
        source_cls.__getitem__.__code__,
        parameters=["self", "key"],
    )
    instance = class_registry.create_instance(modeled_cls)
    return modeled_instance_value(modeled_cls.name, instance, 63)


def _modeled_key_sensitive_map_value(class_name: str, *, non_string: bool = False) -> StackValue:
    source_cls = KeySensitiveNonStringMap if non_string else KeySensitiveMap
    modeled_cls = SymbolicClass(class_name)
    modeled_cls.add_method("keys", source_cls.keys.__code__, parameters=["self"])
    modeled_cls.add_method(
        "__getitem__",
        source_cls.__getitem__.__code__,
        parameters=["self", "key"],
    )
    instance = class_registry.create_instance(modeled_cls)
    return modeled_instance_value(modeled_cls.name, instance, 65)


def test_handle_common_dict_update_accepts_modeled_constant_mapping_protocol() -> None:
    state = VMState(
        stack=[
            SymbolicDict.from_const({}),
            _modeled_const_map_value("ModeledConstMap"),
        ],
        pc=59,
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


def test_handle_common_dict_merge_accepts_modeled_constant_keyword_mapping() -> None:
    stack = cast(
        "list[StackValue]",
        [
            _kwargs_target,
            None,
            (),
            SymbolicDict.from_const({}),
            _modeled_const_map_value("ModeledConstMapKwargs"),
        ],
    )
    state = VMState(stack=stack, pc=60)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key("a") == (True, 3)


def test_handle_common_dict_merge_rejects_modeled_constant_non_string_keyword() -> None:
    stack = cast(
        "list[StackValue]",
        [
            _kwargs_target,
            None,
            (),
            SymbolicDict.from_const({}),
            _modeled_const_map_value("ModeledConstNonStringMap", non_string=True),
        ],
    )
    state = VMState(stack=stack, pc=61)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "keywords must be strings" in result.issues[0].message


def test_handle_common_dict_update_accepts_modeled_literal_list_keys() -> None:
    state = VMState(
        stack=[
            SymbolicDict.from_const({}),
            _modeled_list_keys_map_value("ModeledListKeysMap"),
        ],
        pc=63,
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


def test_handle_common_dict_merge_rejects_modeled_literal_list_non_string_key() -> None:
    stack = cast(
        "list[StackValue]",
        [
            _kwargs_target,
            None,
            (),
            SymbolicDict.from_const({}),
            _modeled_list_keys_map_value("ModeledListKeysNonStringMap", non_string=True),
        ],
    )
    state = VMState(stack=stack, pc=64)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "keywords must be strings" in result.issues[0].message


def test_handle_common_dict_update_accepts_modeled_key_sensitive_literal_dict_getitem() -> None:
    state = VMState(
        stack=[
            SymbolicDict.from_const({}),
            _modeled_key_sensitive_map_value("ModeledKeySensitiveMap"),
        ],
        pc=65,
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


def test_handle_common_dict_merge_rejects_modeled_key_sensitive_non_string_key() -> None:
    stack = cast(
        "list[StackValue]",
        [
            _kwargs_target,
            None,
            (),
            SymbolicDict.from_const({}),
            _modeled_key_sensitive_map_value("ModeledKeySensitiveNonStringMap", non_string=True),
        ],
    )
    state = VMState(stack=stack, pc=66)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "keywords must be strings" in result.issues[0].message


def test_handle_common_dict_update_reports_modeled_non_iterable_keys_result() -> None:
    state = VMState(
        stack=[
            SymbolicDict.empty("dict_update"),
            _modeled_bad_keys_value("ModeledBadKeys"),
        ],
        pc=56,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "ModeledBadKeys.keys() returned a non-iterable (type int)" in result.issues[0].message


def test_handle_common_dict_merge_reports_modeled_non_iterable_keys_result() -> None:
    stack = cast(
        "list[StackValue]",
        [
            _kwargs_target,
            None,
            (),
            SymbolicDict.from_const({}),
            _modeled_bad_keys_value("ModeledBadKeysKwargs"),
        ],
    )
    state = VMState(stack=stack, pc=57)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert (
        "ModeledBadKeysKwargs.keys() returned a non-iterable (type int)" in result.issues[0].message
    )
