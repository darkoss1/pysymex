"""Shared detector audit corpus manifest for recall-first detector hardening."""

from __future__ import annotations

from dataclasses import dataclass

from tests.repro.detector_benchmark import RUNTIME_CASES


@dataclass(frozen=True, slots=True)
class DetectorAuditCase:
    """Metadata describing one detector audit case."""

    family: str
    detector_name: str
    case_id: str
    expected_detected: bool
    category: str
    cross_version_sensitive: bool


def _runtime_cases() -> tuple[DetectorAuditCase, ...]:
    """Adapt runtime detector benchmark cases into shared audit corpus entries."""
    cases: list[DetectorAuditCase] = []
    for case in RUNTIME_CASES:
        category = "normal"
        if "path_explosion" in case.function_name:
            category = "edge-path-explosion"
        cases.append(
            DetectorAuditCase(
                family="runtime",
                detector_name=case.detector_name,
                case_id=case.function_name,
                expected_detected=case.expected_detected,
                category=category,
                cross_version_sensitive=False,
            )
        )
    return tuple(cases)


SPECIALIZED_AUDIT_CASES: tuple[DetectorAuditCase, ...] = (
    DetectorAuditCase(
        "specialized", "infinite-loop", "bounded_for_loop_negative", False, "edge-loop", True
    ),
    DetectorAuditCase(
        "specialized", "infinite-loop", "self_backward_jump_positive", True, "normal", True
    ),
    DetectorAuditCase(
        "specialized", "use-after-free", "close_then_read_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "specialized", "use-after-free", "open_and_read_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "specialized", "format-string", "symbolic_format_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "specialized", "format-string", "concrete_format_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "specialized", "null-dereference", "none_attr_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "specialized", "null-dereference", "non_none_attr_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "specialized",
        "integer-overflow",
        "signed_add_overflow_positive",
        True,
        "edge-overflow",
        False,
    ),
    DetectorAuditCase(
        "specialized", "integer-overflow", "small_add_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "specialized", "unreachable-code", "constant_false_branch_positive", True, "normal", True
    ),
    DetectorAuditCase(
        "specialized", "unreachable-code", "reachable_branch_negative", False, "normal", True
    ),
)


LOGICAL_AUDIT_CASES: tuple[DetectorAuditCase, ...] = (
    DetectorAuditCase(
        "logical", "logical-contradiction", "unsat_branch_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "logical-contradiction", "sat_branch_negative", False, "normal", False
    ),
    DetectorAuditCase("logical", "RangeContradictionRule", "range_positive", True, "normal", False),
    DetectorAuditCase(
        "logical", "RangeContradictionRule", "range_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ParityContradictionRule", "parity_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ParityContradictionRule", "parity_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ModularContradictionRule", "modular_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ModularContradictionRule", "modular_negative", False, "normal", False
    ),
    DetectorAuditCase("logical", "SelfContradictionRule", "self_positive", True, "normal", False),
    DetectorAuditCase("logical", "SelfContradictionRule", "self_negative", False, "normal", False),
    DetectorAuditCase(
        "logical", "ArithmeticImpossibilityRule", "arith_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ArithmeticImpossibilityRule", "arith_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "EqualityContradictionRule", "equality_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "EqualityContradictionRule", "equality_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ComplementContradictionRule", "complement_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ComplementContradictionRule", "complement_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "AntisymmetryRule", "antisymmetry_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "AntisymmetryRule", "antisymmetry_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "TriangleImpossibilityRule", "triangle_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "TriangleImpossibilityRule", "triangle_negative", False, "normal", False
    ),
    DetectorAuditCase("logical", "SumImpossibilityRule", "sum_positive", True, "normal", False),
    DetectorAuditCase("logical", "SumImpossibilityRule", "sum_negative", False, "normal", False),
    DetectorAuditCase(
        "logical", "ProductSignContradictionRule", "product_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ProductSignContradictionRule", "product_negative", False, "normal", False
    ),
    DetectorAuditCase("logical", "GcdImpossibilityRule", "gcd_positive", True, "normal", False),
    DetectorAuditCase("logical", "GcdImpossibilityRule", "gcd_negative", False, "normal", False),
    DetectorAuditCase(
        "logical", "SequentialModularRule", "seq_mod_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "SequentialModularRule", "seq_mod_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "PostAssignmentContradictionRule", "post_assign_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "PostAssignmentContradictionRule", "post_assign_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "LoopInvariantViolationRule", "loop_inv_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "LoopInvariantViolationRule", "loop_inv_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "NarrowingContradictionRule", "narrow_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "NarrowingContradictionRule", "narrow_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ReturnTypeContradictionRule", "return_type_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ReturnTypeContradictionRule", "return_type_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "PostconditionContradictionRule", "postcondition_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical",
        "PostconditionContradictionRule",
        "postcondition_negative",
        False,
        "normal",
        False,
    ),
    DetectorAuditCase(
        "logical", "PreconditionImpossibilityRule", "precondition_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "PreconditionImpossibilityRule", "precondition_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ApiContractViolationRule", "api_contract_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ApiContractViolationRule", "api_contract_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical", "NumericRangePropagationRule", "range_prop_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "NumericRangePropagationRule", "range_prop_negative", False, "normal", False
    ),
    DetectorAuditCase("logical", "StateImpossibilityRule", "state_positive", True, "normal", False),
    DetectorAuditCase(
        "logical", "StateImpossibilityRule", "state_negative", False, "normal", False
    ),
    DetectorAuditCase(
        "logical",
        "ResourceStateContradictionRule",
        "resource_state_positive",
        True,
        "normal",
        False,
    ),
    DetectorAuditCase(
        "logical",
        "ResourceStateContradictionRule",
        "resource_state_negative",
        False,
        "normal",
        False,
    ),
    DetectorAuditCase(
        "logical", "ConcurrencyContradictionRule", "concurrency_positive", True, "normal", False
    ),
    DetectorAuditCase(
        "logical", "ConcurrencyContradictionRule", "concurrency_negative", False, "normal", False
    ),
)


RUNTIME_AUDIT_CASES: tuple[DetectorAuditCase, ...] = _runtime_cases()
ALL_AUDIT_CASES: tuple[DetectorAuditCase, ...] = (
    *RUNTIME_AUDIT_CASES,
    *SPECIALIZED_AUDIT_CASES,
    *LOGICAL_AUDIT_CASES,
)
