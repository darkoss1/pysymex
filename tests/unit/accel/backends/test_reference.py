import numpy as np
import pytest
import z3

from pysymex.accel.backends import BackendType
from pysymex.accel.backends.reference import (
    MAX_TREEWIDTH,
    count_sat,
    evaluate_bag,
    get_info,
    get_satisfying_assignments,
    is_available,
    warmup,
)
from pysymex.accel.bytecode import CompiledConstraint, compile_constraint


def test_is_available_always_true() -> None:
    assert is_available() is True


def test_get_info_reports_reference_backend_contract() -> None:
    info = get_info()
    assert info.backend_type is BackendType.REFERENCE
    assert info.available is True
    assert info.max_treewidth == MAX_TREEWIDTH
    assert info.supports_async is False
    assert info.device_memory_mb == 0
    assert info.compute_units == 1


def test_evaluate_bag_matches_expected_assignments_for_and() -> None:
    x = z3.Bool("x")
    y = z3.Bool("y")
    constraint = compile_constraint(z3.And(x, y), ["x", "y"])
    bitmap = evaluate_bag(constraint)

    assert bitmap.dtype == np.uint8
    assert bitmap.shape == (1,)
    assert int(bitmap[0]) == 0b00001000
    assert count_sat(bitmap) == 1


def test_unpackbits_little_is_not_default_unpackbits_order() -> None:
    x = z3.Bool("x")
    y = z3.Bool("y")
    constraint = compile_constraint(z3.Or(x, y), ["x", "y"])
    bitmap = evaluate_bag(constraint)

    assert int(bitmap[0] & np.uint8(0x0F)) == 0b1110


def test_get_satisfying_assignments_uses_variable_names() -> None:
    x = z3.Bool("x")
    y = z3.Bool("y")
    constraint = compile_constraint(z3.Or(x, y), ["x", "y"])
    bitmap = evaluate_bag(constraint)
    assignments = get_satisfying_assignments(bitmap, 2, ["x", "y"])

    assert len(assignments) == 3
    assert {tuple(sorted(a.items())) for a in assignments} == {
        (("x", True), ("y", False)),
        (("x", False), ("y", True)),
        (("x", True), ("y", True)),
    }


def test_evaluate_bag_raises_for_treewidth_above_maximum() -> None:
    vars_ = [f"v{i}" for i in range(MAX_TREEWIDTH + 1)]
    bools = [z3.Bool(name) for name in vars_]
    expr = z3.And(*bools)
    instr = compile_constraint(expr, vars_).instructions
    too_wide = CompiledConstraint(
        instructions=instr,
        num_variables=MAX_TREEWIDTH + 1,
        register_count=1,
        source_hash=0,
    )
    with pytest.raises(ValueError, match="exceeds reference backend maximum"):
        evaluate_bag(too_wide)


def test_warmup_is_noop() -> None:
    assert warmup() is None
