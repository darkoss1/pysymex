from __future__ import annotations

from pysymex.execution.entrypoint_globals import referenced_same_module_instance_globals


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


def _uses_plain_receiver() -> int:
    return plain_global_receiver.method()


def _uses_dynamic_receiver() -> int:
    return dynamic_global_receiver.method()


def test_referenced_same_module_instance_globals_include_plain_instances() -> None:
    selected = referenced_same_module_instance_globals(
        _uses_plain_receiver,
        _uses_plain_receiver.__code__,
    )

    assert selected == {"plain_global_receiver": plain_global_receiver}


def test_referenced_same_module_instance_globals_skip_dynamic_attribute_hooks() -> None:
    selected = referenced_same_module_instance_globals(
        _uses_dynamic_receiver,
        _uses_dynamic_receiver.__code__,
    )

    assert selected == {}
