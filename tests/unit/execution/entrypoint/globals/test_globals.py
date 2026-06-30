from __future__ import annotations

from pysymex._internal.execution.entrypoint.globals.callables import CallableGlobals
from pysymex._internal.execution.entrypoint.globals.containers import EntrypointContainerGlobals
from pysymex._internal.execution.entrypoint.globals.contracts import ContractGlobals
from pysymex._internal.execution.entrypoint.globals.instances import InstanceGlobals


class PlainGlobalReceiver:
    def method(self) -> int:
        return 1


class DynamicGlobalReceiver:
    def __getattr__(self, name: str) -> object:
        raise AttributeError(name)

    def method(self) -> int:
        return 1


plain_global_receiver = PlainGlobalReceiver()
dynamic_global_receiver = DynamicGlobalReceiver()
global_mutable_list: list[int] = []
global_mutable_dict: dict[str, int] = {}
global_mutable_set: set[int] = set()
global_immutable_tuple = ()


def _uses_plain_receiver() -> int:
    return plain_global_receiver.method()


def _uses_dynamic_receiver() -> int:
    return dynamic_global_receiver.method()


def _uses_mutable_containers() -> int:
    global_mutable_list.append(1)
    global_mutable_dict["x"] = 1
    global_mutable_set.add(1)
    return len(global_mutable_list) + len(global_mutable_dict) + len(global_mutable_set)


def _uses_nested_mutable_container() -> int:
    def child() -> int:
        global_mutable_list.append(1)
        return len(global_mutable_list)

    return child()


def _uses_immutable_tuple() -> int:
    return len(global_immutable_tuple)


def test_entrypoint_globals_exports_use_domain_owners() -> None:
    assert CallableGlobals.select is not None
    assert InstanceGlobals.select is not None
    assert EntrypointContainerGlobals.select is not None
    assert ContractGlobals.select is not None


def test_instance_select_includes_plain_instances() -> None:
    selected = InstanceGlobals.select(
        _uses_plain_receiver,
        _uses_plain_receiver.__code__,
    )

    assert selected == {"plain_global_receiver": plain_global_receiver}


def test_instance_select_skips_dynamic_attribute_hooks() -> None:
    selected = InstanceGlobals.select(
        _uses_dynamic_receiver,
        _uses_dynamic_receiver.__code__,
    )

    assert selected == {}


def test_container_select_includes_referenced_containers() -> None:
    selected = EntrypointContainerGlobals.select(
        _uses_mutable_containers,
        _uses_mutable_containers.__code__,
    )

    assert selected == {
        "global_mutable_dict": global_mutable_dict,
        "global_mutable_list": global_mutable_list,
        "global_mutable_set": global_mutable_set,
    }


def test_container_select_includes_nested_references() -> None:
    selected = EntrypointContainerGlobals.select(
        _uses_nested_mutable_container,
        _uses_nested_mutable_container.__code__,
    )

    assert selected == {"global_mutable_list": global_mutable_list}


def test_container_select_skips_immutable_values() -> None:
    selected = EntrypointContainerGlobals.select(
        _uses_immutable_tuple,
        _uses_immutable_tuple.__code__,
    )

    assert selected == {}
