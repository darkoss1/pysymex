from __future__ import annotations

import dis
from collections.abc import Iterator
from dataclasses import dataclass
from typing import cast

import pytest
import z3

from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.registry import class_registry
from pysymex._internal.core.classes.types import SymbolicMethod
from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.construction_fallbacks import (
    CONSTRUCTOR_ENTRY_UNAVAILABLE_REASON,
    UNSUPPORTED_CONSTRUCTION_PROTOCOL,
)
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.fallback.types import FallbackKind, RiskLevel, SoundnessTag
from pysymex._internal.execution.opcodes.common.functions.attribute.load.handler import (
    handle_common_load_method,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.store import (
    handle_common_delete_attr,
    handle_common_store_attr,
)
from pysymex._internal.execution.opcodes.common.functions.call import handle_common_call
from pysymex._internal.execution.opcodes.common.functions.call_ex import (
    handle_common_call_function_ex,
)
from pysymex._internal.execution.opcodes.common.functions.protocol.fallbacks import (
    PROTOCOL_BUILTIN_UNAVAILABLE_REASON,
    UNSUPPORTED_CONVERSION_PROTOCOL,
    UNSUPPORTED_LENGTH_PROTOCOL,
)
from pysymex._internal.execution.opcodes.common.functions.super import (
    UNSUPPORTED_SUPER_PROTOCOL,
    handle_common_load_super_variants,
)
from pysymex._internal.execution.opcodes.common.lowering.calls import CallLowerer
from pysymex._internal.sandbox.errors import SecurityViolationError
from pysymex._internal.typing.protocols import StackValue


class ConcreteReceiver:
    safe_attr = 7

    def __call__(self) -> int:
        return self.safe_attr


class MutableReceiver:
    x: int


def _readonly_property_getter(_obj: object) -> int:
    return 1


@dataclass(frozen=True)
class Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


def _yield_values(values: object) -> Iterator[object]:
    yield values


def _receiver_method(self: object, value: int) -> int:
    return value if self is not None else 0


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def _instr_with_arg(opname: str, arg: int) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, arg=arg, argval=arg)


def test_load_attr_reads_direct_exception_group_exceptions() -> None:
    member = SymbolicException.concrete(RuntimeError, "boom")
    group = SymbolicException.concrete(ExceptionGroup, "group", [member])
    state = VMState(stack=[group], pc=0)

    result = handle_common_load_method(
        _instr("LOAD_ATTR", "exceptions"),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal is False
    assert result.new_states[0].stack[-1] == (member,)


def test_load_attr_reads_direct_stopiteration_value() -> None:
    stopped = SymbolicException.concrete(StopIteration, 13)
    state = VMState(stack=[stopped], pc=0)

    result = handle_common_load_method(
        _instr("LOAD_ATTR", "value"),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal is False
    assert result.new_states[0].stack[-1] == 13


def _class_body_code(name: str) -> object:
    module_code = compile(f"class {name}:\n    pass\n", "<call-class-test>", "exec")
    for const in module_code.co_consts:
        if getattr(const, "co_name", None) == name:
            return const
    raise AssertionError(f"missing class body code for {name}")


def _symbolic_type_value(name: str, code_obj: object) -> SymbolicValue:
    class_value = SymbolicValue(
        _name=name,
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
        affinity_type="type",
    )
    class_value.attach_modeled_object(code_obj)
    return class_value


def _symbolic_instance_value(name: str, modeled_cls: SymbolicClass) -> SymbolicValue:
    modeled_obj = class_registry.instantiate(modeled_cls)
    value = SymbolicValue(
        _name=f"instance_{name}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
    )
    value.attach_modeled_object(modeled_obj)
    return value


def test_handle_common_call_rejects_argument_stack_underflow() -> None:
    def identity(value: object) -> object:
        return value

    state = VMState(stack=[identity], pc=3)

    with pytest.raises(VMStateError, match="cannot satisfy 2 item"):
        handle_common_call(_instr("CALL", 1), state, OpcodeDispatcher())


def test_handle_common_call_rejects_null_callable_with_populated_receiver() -> None:
    state = VMState(stack=[None, 42], pc=4)

    with pytest.raises(VMStateError, match="callable slot is NULL"):
        handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())


def test_handle_common_call_reports_uncaught_none_callable() -> None:
    state = VMState(stack=[None], pc=5)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "'NoneType' object is not callable" in result.issues[0].message


def test_handle_common_call_reports_symbolic_callable_forced_none() -> None:
    func, type_constraint = SymbolicValue.symbolic("maybe_func")
    state = VMState(stack=[func], pc=5).add_constraint(type_constraint).add_constraint(func.is_none)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]


def test_handle_common_call_reports_definite_non_callable_symbolic_int() -> None:
    func, type_constraint = SymbolicValue.symbolic_int("x")
    state = VMState(stack=[func], pc=5).add_constraint(type_constraint)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal
    assert len(result.issues) == 1
    assert result.issues[0].kind == IssueKind.TYPE_ERROR


def test_handle_common_call_consumes_direct_call_null_marker() -> None:
    state = VMState(stack=[SymbolicNone(), range, 3], pc=7)

    result = handle_common_call(_instr("CALL", 1), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert result.terminal is False
    assert len(next_state.stack) == 1
    assert not isinstance(next_state.stack[0], SymbolicNone)


def test_call_lowerer_treats_symbolic_method_as_callable() -> None:
    method = SymbolicMethod("method", func=_receiver_method).bind_to_instance(object())

    assert CallLowerer(7).is_likely_callable(method)


def test_handle_common_call_returns_generator_without_entering_frame() -> None:
    iterator, iterator_constraint = SymbolicValue.symbolic("iterator")
    state = VMState(stack=[SymbolicNone(), all, _yield_values, iterator], pc=8)
    state = state.add_constraint(iterator_constraint)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert result.terminal is False
    assert next_state.pc == 9
    assert len(next_state.stack) == 3
    assert isinstance(next_state.stack[0], SymbolicNone)
    assert next_state.stack[1] is all
    assert next_state.call_stack == []
    assert not isinstance(next_state.stack[2], SymbolicNone)


def test_handle_common_call_function_ex_consumes_null_sentinel_and_expands_args() -> None:
    state = VMState(stack=[pow, SymbolicNone("PUSH_NULL_None"), (2, 3)], pc=11)

    result = handle_common_call_function_ex(
        _instr_with_arg("CALL_FUNCTION_EX", 0), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    top = next_state.stack[-1]
    assert dis.stack_effect(dis.opmap["CALL_FUNCTION_EX"], 0) == -2
    assert len(next_state.stack) == 1
    assert isinstance(top, SymbolicValue)
    assert top.value == 8
    assert next_state.pc == 12


def test_unmodeled_call_reports_abstraction() -> None:
    state = VMState(stack=[SymbolicNone(), object.__str__], pc=12)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.degraded_passes == ["unmodeled_call_abstraction"]


def test_unmodeled_call_function_ex_reports_abstraction() -> None:
    state = VMState(stack=[object.__str__, SymbolicNone("PUSH_NULL_None"), ()], pc=13)

    result = handle_common_call_function_ex(
        _instr_with_arg("CALL_FUNCTION_EX", 0), state, OpcodeDispatcher()
    )

    assert result.degraded_passes == ["unmodeled_call_abstraction"]


def test_symbolic_call_protocol_failure_records_unsupported_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedCallableProtocol"))
    modeled_cls.add_method("__call__")
    modeled_obj = class_registry.instantiate(modeled_cls)
    func = SymbolicValue(
        _name="instance_UnsupportedCallableProtocol",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
    )
    func.attach_modeled_object(modeled_obj)
    state = VMState(stack=[SymbolicNone(), func], pc=14)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == ["unsupported_call_protocol"]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == "unsupported_call_protocol"
    assert event.owner == "execution.calls"
    assert (
        event.reason == "symbolic __call__ target could not be modeled or entered interprocedurally"
    )
    assert event.pc == 14
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.LOW
    assert event.false_negative_risk is RiskLevel.HIGH


def test_modeled_len_builtin_failure_records_protocol_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedLenBuiltin"))
    modeled_cls.add_method("__len__")
    receiver = _symbolic_instance_value("_UnsupportedLenBuiltin", modeled_cls)
    state = VMState(stack=[SymbolicNone(), len, receiver], pc=16)

    result = handle_common_call(_instr("CALL", 1), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_LENGTH_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_LENGTH_PROTOCOL
    assert event.owner == "execution.opcodes.protocol_builtins"
    assert event.reason == PROTOCOL_BUILTIN_UNAVAILABLE_REASON
    assert event.pc == 16
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_modeled_conversion_builtin_failure_records_protocol_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedIntBuiltin"))
    modeled_cls.add_method("__int__")
    receiver = _symbolic_instance_value("_UnsupportedIntBuiltin", modeled_cls)
    state = VMState(stack=[SymbolicNone(), int, receiver], pc=17)

    result = handle_common_call(_instr("CALL", 1), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_CONVERSION_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_CONVERSION_PROTOCOL
    assert event.owner == "execution.opcodes.protocol_builtins"
    assert event.reason == PROTOCOL_BUILTIN_UNAVAILABLE_REASON
    assert event.pc == 17
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_modeled_class_new_failure_records_construction_event() -> None:
    class_name = "_UnsupportedNewConstruction"
    code_obj = _class_body_code(class_name)
    modeled_cls = class_registry.register_class(SymbolicClass(class_name))
    modeled_cls.add_method("__new__")
    class_registry.register_code_object(code_obj, modeled_cls)
    class_value = _symbolic_type_value(class_name, code_obj)
    state = VMState(stack=[SymbolicNone(), class_value], pc=15)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_CONSTRUCTION_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_CONSTRUCTION_PROTOCOL
    assert event.owner == "execution.calls.construction"
    assert event.reason == CONSTRUCTOR_ENTRY_UNAVAILABLE_REASON
    assert event.pc == 15
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_unsupported_super_variant_preserves_caller_stack_prefix() -> None:
    state = VMState(stack=cast("list[StackValue]", [17, "class", "self"]), pc=14)

    result = handle_common_load_super_variants(
        _instr("LOAD_SUPER_METHOD", "value"), state, OpcodeDispatcher()
    )

    assert result.degraded_passes == [UNSUPPORTED_SUPER_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_SUPER_PROTOCOL
    assert event.owner == "execution.opcodes.super"
    assert event.reason == "super opcode variant for 'value' is unsupported"
    assert event.pc == 14
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH
    assert result.new_states[0].stack[0] == 17


def test_handle_common_load_method_allows_safe_concrete_attribute() -> None:
    state = VMState(stack=[ConcreteReceiver()], pc=5)

    result = handle_common_load_method(
        _instr("LOAD_METHOD", "safe_attr"), state, OpcodeDispatcher()
    )

    assert result.terminal is False
    assert result.new_states[0].stack[-1] == 7


def test_handle_common_load_method_blocks_dangerous_concrete_attribute() -> None:
    state = VMState(stack=[ConcreteReceiver()], pc=6)

    with pytest.raises(SecurityViolationError, match="__subclasses__"):
        handle_common_load_method(
            _instr("LOAD_METHOD", "__subclasses__"), state, OpcodeDispatcher()
        )


def test_handle_common_load_method_binds_heap_modeled_method_to_receiver() -> None:
    receiver = SymbolicObject("self_obj", 101, z3.IntVal(101), {101})
    method = SymbolicMethod(func=_receiver_method, name="m")
    heap_object: dict[str, StackValue] = {"m": cast("StackValue", method)}
    state = VMState(stack=[receiver], pc=10).store_heap(receiver.address, heap_object)

    result = handle_common_load_method(_instr("LOAD_METHOD", "m"), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    loaded_method = next_state.stack[-2]
    explicit_receiver = next_state.stack[-1]
    assert isinstance(loaded_method, SymbolicMethod)
    assert loaded_method.bound_to is receiver
    assert explicit_receiver is receiver

    call_args, _ = loaded_method.get_call_args((explicit_receiver, 1), {})
    assert call_args == (receiver, 1)


def test_handle_common_load_method_terminates_missing_modeled_attribute() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_MissingAttrReceiver"))
    modeled_obj = class_registry.instantiate(modeled_cls)
    receiver = SymbolicValue(
        _name="instance_MissingAttrReceiver",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
    )
    receiver.attach_modeled_object(modeled_obj)
    state = VMState(stack=[receiver], pc=11)

    result = handle_common_load_method(_instr("LOAD_ATTR", "missing"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.ATTRIBUTE_ERROR]


def test_symbolic_getattribute_failure_records_unsupported_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedGetattributeReceiver"))
    modeled_cls.add_method("__getattribute__")
    modeled_obj = class_registry.instantiate(modeled_cls)
    receiver = SymbolicValue(
        _name="instance_UnsupportedGetattributeReceiver",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
    )
    receiver.attach_modeled_object(modeled_obj)
    state = VMState(stack=[receiver], pc=12)

    result = handle_common_load_method(_instr("LOAD_ATTR", "value"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == ["unsupported_attribute_protocol"]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == "unsupported_attribute_protocol"
    assert event.owner == "execution.opcodes.attribute"
    assert event.reason == "modeled __getattribute__ for 'value' could not be entered"
    assert event.pc == 12
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_symbolic_property_getter_failure_records_descriptor_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedPropertyReceiver"))
    modeled_cls.add_property("value", fget=_readonly_property_getter)
    modeled_obj = class_registry.instantiate(modeled_cls)
    receiver = SymbolicValue(
        _name="instance_UnsupportedPropertyReceiver",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
    )
    receiver.attach_modeled_object(modeled_obj)
    state = VMState(stack=[receiver], pc=13)

    result = handle_common_load_method(_instr("LOAD_ATTR", "value"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == ["unsupported_descriptor_protocol"]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == "unsupported_descriptor_protocol"
    assert event.owner == "execution.opcodes.attribute"
    assert event.reason == "property 'value' has no retained getter code"
    assert event.pc == 13
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_store_attr_mutates_concrete_receiver() -> None:
    receiver = MutableReceiver()
    state = VMState(stack=cast("list[StackValue]", [9, receiver]), pc=12)

    result = handle_common_store_attr(_instr("STORE_ATTR", "x"), state, OpcodeDispatcher())

    assert result.terminal is False
    assert result.new_states[0].stack == []
    assert receiver.x == 9


def test_handle_common_store_attr_reports_readonly_modeled_property() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_ReadonlyReceiver"))
    modeled_cls.add_property("value", fget=_readonly_property_getter)
    modeled_obj = class_registry.instantiate(modeled_cls)
    receiver = SymbolicValue(
        _name="instance_ReadonlyReceiver",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
    )
    receiver.attach_modeled_object(modeled_obj)
    state = VMState(stack=[2, receiver], pc=13)

    result = handle_common_store_attr(_instr("STORE_ATTR", "value"), state, OpcodeDispatcher())

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.ATTRIBUTE_ERROR]
    assert "property 'value' of '_ReadonlyReceiver' object has no setter" in (
        result.issues[0].message
    )


def test_handle_common_delete_attr_mutates_concrete_receiver() -> None:
    receiver = MutableReceiver()
    receiver.x = 9
    state = VMState(stack=cast("list[StackValue]", [receiver]), pc=13)

    result = handle_common_delete_attr(_instr("DELETE_ATTR", "x"), state, OpcodeDispatcher())

    assert result.terminal is False
    assert result.new_states[0].stack == []
    assert not hasattr(receiver, "x")


def test_handle_common_delete_attr_reports_missing_concrete_attribute() -> None:
    receiver = MutableReceiver()
    state = VMState(stack=cast("list[StackValue]", [receiver]), pc=14)

    result = handle_common_delete_attr(_instr("DELETE_ATTR", "x"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.ATTRIBUTE_ERROR]
    assert "'MutableReceiver' object has no attribute 'x'" in result.issues[0].message


def test_handle_common_store_attr_reports_definite_attribute_error() -> None:
    state = VMState(stack=cast("list[StackValue]", [9, None]), pc=15)

    result = handle_common_store_attr(_instr("STORE_ATTR", "x"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.ATTRIBUTE_ERROR]
    assert "'NoneType' object has no attribute 'x'" in result.issues[0].message


def test_handle_common_store_attr_routes_attribute_error_to_handler() -> None:
    dispatcher = OpcodeDispatcher()
    store_attr = _instr("STORE_ATTR", "x")._replace(offset=4)
    dispatcher.set_instructions([store_attr, _instr("NOP")._replace(offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    state = VMState(stack=cast("list[StackValue]", [9, None]), pc=16)

    result = handle_common_store_attr(store_attr, state, dispatcher)

    assert result.terminal is False
    assert result.issues == []
    next_state = result.new_states[0]
    assert next_state.pc == 1
    assert len(next_state.stack) == 1
    exception = next_state.stack[0]
    assert isinstance(exception, SymbolicException)
    assert exception.type_name == "AttributeError"


def test_handle_common_store_attr_rejects_missing_object() -> None:
    state = VMState(stack=[9], pc=17)

    with pytest.raises(VMStateError, match="STORE_ATTR"):
        handle_common_store_attr(_instr("STORE_ATTR", "x"), state, OpcodeDispatcher())


def test_handle_common_delete_attr_removes_heap_symbolic_object_attribute() -> None:
    receiver = SymbolicObject("obj", 101, z3.IntVal(101), {101})
    state = VMState(stack=[receiver], pc=18).store_heap(
        receiver.address,
        cast("StackValue", {"x": 9, "y": 10}),
    )

    result = handle_common_delete_attr(_instr("DELETE_ATTR", "x"), state, OpcodeDispatcher())

    assert result.terminal is False
    assert result.new_states[0].memory[101] == {"y": 10}


def test_handle_common_load_method_marks_unknown_none_receiver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pysymex._internal.execution.opcodes.common.functions.attribute.load.handler as load_ops
    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.execution.opcodes.common.functions.attribute.load.handler import (
        ATTRIBUTE_LOAD_NONE_FEASIBILITY_UNKNOWN,
    )

    receiver, constraint = SymbolicValue.symbolic("load_attr_unknown_none")
    state = VMState(stack=[receiver], path_constraints=[constraint], pc=13)

    def unknown_check(*args: object, **kwargs: object) -> SolverResult:
        _ = args, kwargs
        return SolverResult.unknown()

    monkeypatch.setattr(load_ops, "_path_satisfiability_result", unknown_check)

    result = handle_common_load_method(_instr("LOAD_ATTR", "dynamic"), state, OpcodeDispatcher())

    assert result.terminal is False
    assert ATTRIBUTE_LOAD_NONE_FEASIBILITY_UNKNOWN in result.degraded_passes


def test_handle_common_store_attr_marks_unknown_none_receiver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pysymex._internal.execution.opcodes.common.functions.attribute.store as store_ops
    from pysymex._internal.core.solver.engine.results import SolverResult

    receiver, constraint = SymbolicValue.symbolic("store_attr_unknown_none")
    state = VMState(stack=[1, receiver], path_constraints=[constraint], pc=14)

    def unknown_check(*args: object, **kwargs: object) -> SolverResult:
        _ = args, kwargs
        return SolverResult.unknown()

    monkeypatch.setattr(store_ops, "_path_satisfiability_result", unknown_check)

    result = handle_common_store_attr(_instr("STORE_ATTR", "dynamic"), state, OpcodeDispatcher())

    assert result.terminal is False
    assert store_ops.ATTRIBUTE_NONE_FEASIBILITY_UNKNOWN in result.degraded_passes
