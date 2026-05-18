from __future__ import annotations

import dis
from typing import cast

import z3

from pysymex._typing import StackValue
from pysymex.core.objects import ObjectState
from pysymex.core.objects.oop import (
    EnhancedClass,
    create_enhanced_instance,
    enhanced_class_registry,
)
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.control import handle_common_match_class


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


class _Point:
    __match_args__ = ("x",)

    def __init__(self, x: int) -> None:
        self.x = x


def _class_body_code(name: str) -> object:
    module_code = compile(f"class {name}:\n    pass\n", "<match-class-test>", "exec")
    for const in module_code.co_consts:
        if getattr(const, "co_name", None) == name:
            return const
    raise AssertionError(f"missing class body code for {name}")


def _symbolic_class_value(
    name: str, enhanced_cls: EnhancedClass, code_obj: object
) -> SymbolicValue:
    enhanced_class_registry.register_code_object(code_obj, enhanced_cls)
    class_value = SymbolicValue(
        _name=name,
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type="type",
    )
    class_value.attach_enhanced_object(code_obj)
    return class_value


def _symbolic_instance_value(name: str, enhanced_cls: EnhancedClass) -> SymbolicValue:
    instance, _constraints = create_enhanced_instance(enhanced_cls, ObjectState())
    instance.set_attribute("x", 7)
    instance_value = SymbolicValue(
        _name=f"{name}_instance",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type=name,
    )
    instance_value.attach_enhanced_object(instance)
    return instance_value


def test_handle_common_match_class_returns_attr_tuple_for_concrete_keyword_match() -> None:
    state = VMState(stack=cast("list[StackValue]", [_Point(5), _Point, ("x",)]), pc=4)

    result = handle_common_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())

    assert result.new_states[0].stack[-1] == (5,)


def test_handle_common_match_class_returns_match_self_tuple_for_builtin_positional_match() -> None:
    state = VMState(stack=["abc", str, ()], pc=5)

    result = handle_common_match_class(_instr("MATCH_CLASS", 1), state, OpcodeDispatcher())

    assert result.new_states[0].stack[-1] == ("abc",)


def test_handle_common_match_class_returns_none_for_concrete_mismatch() -> None:
    state = VMState(stack=[1, str, ()], pc=6)

    result = handle_common_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())

    assert isinstance(result.new_states[0].stack[-1], SymbolicNone)


def test_handle_common_match_class_constrains_symbolic_builtin_success() -> None:
    subject, type_constraint = SymbolicValue.symbolic("subject")
    state = VMState(stack=[subject, int, ()], pc=7).add_constraint(type_constraint)

    result = handle_common_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())

    match_result = result.new_states[0].stack[-1]
    assert isinstance(match_result, SymbolicValue)
    solver = z3.Solver()
    solver.add(
        *result.new_states[0].path_constraints,
        subject.is_str,
        z3.Not(match_result.is_none),
    )
    assert solver.check() == z3.unsat


def test_handle_common_match_class_uses_enhanced_user_class_identity() -> None:
    class_name = "_MatchPoint"
    code_obj = _class_body_code(class_name)
    enhanced_cls = enhanced_class_registry.register_class(class_name)
    enhanced_cls.class_vars["__match_args__"] = ("x",)
    class_value = _symbolic_class_value(class_name, enhanced_cls, code_obj)
    instance_value = _symbolic_instance_value(class_name, enhanced_cls)
    state = VMState(stack=[instance_value, class_value, ()], pc=8)

    result = handle_common_match_class(_instr("MATCH_CLASS", 1), state, OpcodeDispatcher())

    assert result.new_states[0].stack[-1] == (7,)


def test_handle_common_match_class_rejects_different_enhanced_user_class() -> None:
    subject_cls = enhanced_class_registry.register_class("_SubjectClass")
    pattern_cls = enhanced_class_registry.register_class("_PatternClass")
    pattern_value = _symbolic_class_value(
        "_PatternClass", pattern_cls, _class_body_code("_PatternClass")
    )
    subject_value = _symbolic_instance_value("_SubjectClass", subject_cls)
    state = VMState(stack=[subject_value, pattern_value, ()], pc=9)

    result = handle_common_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())

    assert isinstance(result.new_states[0].stack[-1], SymbolicNone)


def test_handle_common_match_class_accepts_enhanced_user_subclass() -> None:
    parent_cls = enhanced_class_registry.register_class("_PatternParent")
    child_cls = enhanced_class_registry.register_class("_PatternChild", bases=(parent_cls.base,))
    parent_cls.class_vars["__match_args__"] = ("x",)
    pattern_value = _symbolic_class_value(
        "_PatternParent",
        parent_cls,
        _class_body_code("_PatternParent"),
    )
    subject_value = _symbolic_instance_value("_PatternChild", child_cls)
    state = VMState(stack=[subject_value, pattern_value, ()], pc=10)

    result = handle_common_match_class(_instr("MATCH_CLASS", 1), state, OpcodeDispatcher())

    assert result.new_states[0].stack[-1] == (7,)
