"""Facade and Evaluator for V3 Acceleration."""

from dataclasses import dataclass
from typing import Protocol

from pysymex.contracts.decorators import ensures, requires
from pysymex.accel.core_index import CoreIndex
from pysymex.accel.types import (
    AccelCandidate,
    PathMask,
    PruneResult,
    TheorySignature,
)


def _is_core_index(value: object) -> bool:
    return isinstance(value, CoreIndex)


def _is_path_state(value: object) -> bool:
    return isinstance(value, PathState)


def _is_chtd_bag(value: object) -> bool:
    return isinstance(value, ChtdBag)


def _is_theory_signature(value: object) -> bool:
    return isinstance(value, TheorySignature)


def _is_prune_result(value: object) -> bool:
    return isinstance(value, PruneResult)


def _is_accel_candidate(value: object) -> bool:
    return isinstance(value, AccelCandidate)


@dataclass
class PathState:
    """Mock state of a path during execution."""

    path_id: int
    atom_mask: PathMask


@dataclass
class ChtdBag:
    """Mock state of a CHTD Bag."""

    bag_id: int
    theory_signature: TheorySignature
    # The actual constraint expression would go here.


class SmtSlicingLayer(Protocol):
    """Protocol for the SMT Validator."""

    def check_bag(self, path: PathState, bag: ChtdBag) -> PruneResult: ...

    def check_full_path(self, path: PathState) -> PruneResult: ...


class EvaluatorFacade:
    """The main evaluation facade for CHTD-TS Acceleration."""

    @requires(_is_core_index)
    def __init__(self, core_index: CoreIndex, smt_slicing_layer: SmtSlicingLayer):
        from pysymex.accel.worker import ThreadLocalSatWorker

        self.core_index = core_index
        self.smt_slicing_layer = smt_slicing_layer
        self.worker = ThreadLocalSatWorker()

    @requires(_is_chtd_bag)
    @ensures(_is_theory_signature)
    def classify_bag_theory(self, bag: ChtdBag) -> TheorySignature:
        """Classify the bag theory signature."""
        return bag.theory_signature

    @requires(_is_path_state)
    @requires(_is_chtd_bag)
    @ensures(_is_prune_result)
    def evaluate_selected_bag(self, path: PathState, bag: ChtdBag) -> PruneResult:
        """Evaluate a selected bag using the tiered CPU dispatcher."""

        # 1. Hot path: Certified Core Containment
        if self.core_index.prunes(path.atom_mask):
            return PruneResult.PRUNED_BY_CERTIFIED_CORE

        # 2. Theory Classification
        theory: TheorySignature = self.classify_bag_theory(bag)

        # 3. Pure Boolean Fast Path
        if theory == TheorySignature.PURE_BOOL:
            # Here we would call the fast SAT evaluator using Tseitin CNF
            candidate: AccelCandidate = self._sat_fast_path_evaluate(bag, path)
            return self._certify_or_return_local(candidate, path, bag)

        # 4. Mixed Theory or Unsupported SMT Path
        smt_theories = {
            TheorySignature.BIT_VECTOR,
            TheorySignature.LINEAR_ARITHMETIC,
            TheorySignature.ARRAYS_UF,
            TheorySignature.MIXED,
        }

        if theory in smt_theories:
            return self.smt_slicing_layer.check_bag(path, bag)

        return self.smt_slicing_layer.check_full_path(path)

    @requires(_is_chtd_bag)
    @requires(_is_path_state)
    @ensures(_is_accel_candidate)
    def _sat_fast_path_evaluate(self, bag: ChtdBag, path: PathState) -> AccelCandidate:
        """Evaluate bag using the thread-local SAT solver."""
        # This is a stub for the native call.
        return AccelCandidate(
            status="unknown",
            atom_ids=tuple(),
            cnf_hash=None,
            translation_hash=None,
            backend="ThreadLocalSatWorker",
            generation_id=1,
        )

    @requires(_is_accel_candidate)
    @requires(_is_path_state)
    @requires(_is_chtd_bag)
    @ensures(_is_prune_result)
    def _certify_or_return_local(
        self, candidate: AccelCandidate, path: PathState, bag: ChtdBag
    ) -> PruneResult:
        """Certify an UNSAT candidate, or return NOT_PRUNED."""
        if candidate.status == "unsat":
            # Mode B: Validated Backend. Validate through SMT_SLICING.
            return self.smt_slicing_layer.check_bag(path, bag)

        # Mode C: SAT or unknown cannot prune the full path.
        return PruneResult.NOT_PRUNED
