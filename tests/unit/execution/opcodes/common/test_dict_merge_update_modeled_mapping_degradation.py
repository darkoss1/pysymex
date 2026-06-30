from __future__ import annotations

from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.mapping_protocol.extraction import (
    UNSUPPORTED_MAPPING_PROTOCOL,
)
from pysymex._internal.core.classes.registry import class_registry
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


def _modeled_bad_keys_value(class_name: str) -> StackValue:
    modeled_cls = SymbolicClass(class_name)
    modeled_cls.add_method("keys", BadKeys.keys.__code__, parameters=["self"])
    modeled_cls.add_method(
        "__getitem__",
        BadKeys.__getitem__.__code__,
        parameters=["self", "key"],
    )
    modeled_cls.add_method("__getattribute__", parameters=["self", "name"])
    instance = class_registry.create_instance(modeled_cls)
    return modeled_instance_value(modeled_cls.name, instance, 71)


def _modeled_const_map_value(class_name: str) -> StackValue:
    modeled_cls = SymbolicClass(class_name)
    modeled_cls.add_method("keys", ConstMap.keys.__code__, parameters=["self"])
    modeled_cls.add_method(
        "__getitem__",
        ConstMap.__getitem__.__code__,
        parameters=["self", "key"],
    )
    modeled_cls.add_method("__getattribute__", parameters=["self", "name"])
    instance = class_registry.create_instance(modeled_cls)
    return modeled_instance_value(modeled_cls.name, instance, 72)


def test_handle_common_dict_update_degrades_dynamic_constant_mapping_protocol() -> None:
    state = VMState(
        stack=[
            SymbolicDict.empty("dict_update"),
            _modeled_const_map_value("ModeledDynamicConstMap"),
        ],
        pc=72,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert result.issues == []
    assert result.degraded_passes == [UNSUPPORTED_MAPPING_PROTOCOL]


def test_handle_common_dict_update_degrades_dynamic_keys_lookup() -> None:
    state = VMState(
        stack=[
            SymbolicDict.empty("dict_update"),
            _modeled_bad_keys_value("ModeledDynamicBadKeys"),
        ],
        pc=71,
    )

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert not result.terminal
    assert result.issues == []
    assert result.degraded_passes == [UNSUPPORTED_MAPPING_PROTOCOL]
