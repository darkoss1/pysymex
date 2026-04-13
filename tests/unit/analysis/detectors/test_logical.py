import z3

from pysymex.analysis.detectors.logical import create_logic_detector
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t1_local import (
    ArithmeticImpossibilityRule,
    ComplementContradictionRule,
    EqualityContradictionRule,
    ModularContradictionRule,
    ParityContradictionRule,
    RangeContradictionRule,
    SelfContradictionRule,
)
from pysymex.analysis.detectors.logical.t2_multivar import (
    AntisymmetryRule,
    GcdImpossibilityRule,
    ProductSignContradictionRule,
    SumImpossibilityRule,
    TriangleImpossibilityRule,
)
from pysymex.analysis.detectors.logical.t3_path import (
    LoopInvariantViolationRule,
    NarrowingContradictionRule,
    PostAssignmentContradictionRule,
    ReturnTypeContradictionRule,
    SequentialModularRule,
)
from pysymex.analysis.detectors.logical.t4_interprocedural import (
    ApiContractViolationRule,
    NumericRangePropagationRule,
    PostconditionContradictionRule,
    PreconditionImpossibilityRule,
    TaintConstraintContradictionRule,
)
from pysymex.analysis.detectors.logical.t5_temporal import (
    ConcurrencyContradictionRule,
    ResourceStateContradictionRule,
    StateImpossibilityRule,
)


def _ctx(core: list[z3.BoolRef]) -> ContradictionContext:
    return ContradictionContext(core=core, branch_cond=z3.BoolVal(True), path_constraints=[])


def test_create_logic_detector_registers_all_rules() -> None:
    detector = create_logic_detector()
    assert len(detector.rules) == 25


def test_t1_rules_detect() -> None:
    x = z3.Int("x")

    assert RangeContradictionRule().matches(_ctx([x > 10, x < 5]))
    assert ParityContradictionRule().matches(_ctx([x % 2 == 0, x % 2 == 1]))
    assert ModularContradictionRule().matches(_ctx([x % 3 == 0, x % 3 == 1]))
    assert SelfContradictionRule().matches(_ctx([z3.Not(x == x)]))
    assert ArithmeticImpossibilityRule().matches(_ctx([x + x == 1, x == 0]))
    assert EqualityContradictionRule().matches(_ctx([x == 1, x == 2]))
    assert ComplementContradictionRule().matches(_ctx([x > 3, z3.Not(x > 3)]))


def test_t2_rules_detect() -> None:
    x, y, z = z3.Ints("x y z")

    assert AntisymmetryRule().matches(_ctx([x > y, y >= x]))
    assert TriangleImpossibilityRule().matches(_ctx([x > y, y > z, z >= x]))
    assert SumImpossibilityRule().matches(_ctx([x + y == 3, x > 5, y > 5]))
    assert ProductSignContradictionRule().matches(_ctx([x * y > 0, x > 0, y < 0]))
    assert GcdImpossibilityRule().matches(_ctx([x % 2 == 0, x % 2 == 1, y == 0]))


def test_t3_rules_detect() -> None:
    x = z3.Int("x")
    loop_i = z3.Int("loop_i")
    n = z3.Int("n")
    ret_is_int = z3.Bool("ret_is_int")
    ret_is_str = z3.Bool("ret_is_str")

    assert SequentialModularRule().matches(_ctx([(x * 2) % 3 == 0, (x * 2) % 3 == 1]))
    assert PostAssignmentContradictionRule().matches(_ctx([x == 4, x > 9]))
    assert LoopInvariantViolationRule().matches(_ctx([loop_i == loop_i + 1]))
    assert NarrowingContradictionRule().matches(_ctx([n >= 0, n <= 10, n > 12]))
    assert ReturnTypeContradictionRule().matches(
        _ctx([ret_is_int, ret_is_str, z3.Not(z3.And(ret_is_int, ret_is_str))])
    )


def test_t4_rules_detect() -> None:
    arg_x = z3.Int("arg_x")
    result_val = z3.Int("result_val")
    api_contract_ok = z3.Bool("api_contract_ok")
    taint_user_input = z3.Bool("taint_user_input")
    caller_value, callee_value = z3.Ints("caller_value callee_value")

    assert PreconditionImpossibilityRule().matches(_ctx([arg_x >= 10, arg_x <= 1]))
    assert PostconditionContradictionRule().matches(_ctx([result_val == 1, result_val == 2]))
    assert ApiContractViolationRule().matches(_ctx([api_contract_ok, z3.Not(api_contract_ok)]))
    assert TaintConstraintContradictionRule().matches(_ctx([taint_user_input, z3.Not(taint_user_input)]))
    assert NumericRangePropagationRule().matches(_ctx([caller_value <= callee_value, callee_value < caller_value]))


def test_t5_rules_detect() -> None:
    state_mode = z3.Int("state_mode")
    resource_open = z3.Bool("resource_open")
    lockA_order, lockB_order = z3.Ints("lockA_order lockB_order")

    assert StateImpossibilityRule().matches(_ctx([state_mode == 1, state_mode == 2]))
    assert ResourceStateContradictionRule().matches(_ctx([resource_open, z3.Not(resource_open)]))
    assert ConcurrencyContradictionRule().matches(_ctx([lockA_order < lockB_order, lockB_order <= lockA_order]))
