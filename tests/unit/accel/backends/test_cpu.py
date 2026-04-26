import pytest
import z3

from pysymex.accel.backends import BackendType
from pysymex.accel.backends.cpu import MAX_TREEWIDTH, evaluate_bag, get_info, is_available, warmup
from pysymex.accel.backends.reference import count_sat as ref_count_sat
from pysymex.accel.backends.reference import evaluate_bag as ref_evaluate_bag
from pysymex.accel.bytecode import compile_constraint


def test_is_available_matches_get_info_available_flag() -> None:
    assert get_info().available is is_available()


def test_get_info_reports_cpu_backend_when_available() -> None:
    info = get_info()
    if is_available():
        assert info.backend_type is BackendType.CPU
        assert info.max_treewidth == MAX_TREEWIDTH
        assert info.compute_units >= 1
    else:
        assert info.max_treewidth == 0
        assert info.error_message == "Numba not installed"


def test_evaluate_bag_matches_reference_for_partial_64_chunk_width() -> None:
    if not is_available():
        pytest.skip("Numba CPU backend unavailable")

    vars_ = [f"v{i}" for i in range(5)]
    bools = [z3.Bool(name) for name in vars_]
    expr = z3.And(bools[0], z3.Or(bools[1], bools[2]), z3.Not(bools[4]))
    constraint = compile_constraint(expr, vars_)

    cpu_bitmap = evaluate_bag(constraint)
    ref_bitmap = ref_evaluate_bag(constraint)

    assert [int(x) for x in cpu_bitmap] == [int(x) for x in ref_bitmap]
    assert ref_count_sat(cpu_bitmap) == ref_count_sat(ref_bitmap)


def test_evaluate_bag_matches_reference_for_exact_64_chunk_width() -> None:
    if not is_available():
        pytest.skip("Numba CPU backend unavailable")

    vars_ = [f"v{i}" for i in range(6)]
    bools = [z3.Bool(name) for name in vars_]
    expr = z3.Xor(
        z3.Xor(z3.Xor(bools[0], bools[1]), z3.Xor(bools[2], bools[3])),
        z3.Xor(bools[4], bools[5]),
    )
    constraint = compile_constraint(expr, vars_)

    cpu_bitmap = evaluate_bag(constraint)
    ref_bitmap = ref_evaluate_bag(constraint)

    assert [int(x) for x in cpu_bitmap] == [int(x) for x in ref_bitmap]


def test_warmup_noop_when_backend_unavailable_or_jits_when_available() -> None:
    assert warmup() is None
