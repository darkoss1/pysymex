from pysymex.accel.types import CompressedBitmap, PathMask, TheorySignature, PruneResult
from pysymex.accel.core_index import CoreIndex
from pysymex.accel.evaluator import EvaluatorFacade, PathState, ChtdBag, SmtSlicingLayer


class MockSmtSlicingLayer(SmtSlicingLayer):
    def check_bag(self, path: PathState, bag: ChtdBag) -> PruneResult:
        return PruneResult.PRUNED_AFTER_VALIDATION

    def check_full_path(self, path: PathState) -> PruneResult:
        return PruneResult.NOT_PRUNED


def test_evaluator_pruned_by_certified_core():
    core_index = CoreIndex()
    # Mocking core_index behavior is easier by inserting a core
    from tests.unit.accel.test_core_index import create_core

    core = create_core(1, {1, 2})
    core_index.insert_core(core)

    evaluator = EvaluatorFacade(core_index, MockSmtSlicingLayer())

    path = PathState(path_id=1, atom_mask=PathMask(CompressedBitmap(frozenset({1, 2, 3}))))
    bag = ChtdBag(bag_id=1, theory_signature=TheorySignature.MIXED)

    result = evaluator.evaluate_selected_bag(path, bag)
    assert result == PruneResult.PRUNED_BY_CERTIFIED_CORE


def test_evaluator_smt_slicing_routing():
    core_index = CoreIndex()
    evaluator = EvaluatorFacade(core_index, MockSmtSlicingLayer())

    path = PathState(path_id=1, atom_mask=PathMask(CompressedBitmap(frozenset({4, 5}))))
    bag = ChtdBag(bag_id=1, theory_signature=TheorySignature.LINEAR_ARITHMETIC)

    result = evaluator.evaluate_selected_bag(path, bag)
    # The MockSmtSlicingLayer returns PRUNED_AFTER_VALIDATION for check_bag
    assert result == PruneResult.PRUNED_AFTER_VALIDATION


def test_evaluator_pure_bool_routing():
    core_index = CoreIndex()
    evaluator = EvaluatorFacade(core_index, MockSmtSlicingLayer())

    path = PathState(path_id=1, atom_mask=PathMask(CompressedBitmap(frozenset({4, 5}))))
    bag = ChtdBag(bag_id=1, theory_signature=TheorySignature.PURE_BOOL)

    # Currently our fast path mock returns unknown, which leads to NOT_PRUNED
    result = evaluator.evaluate_selected_bag(path, bag)
    assert result == PruneResult.NOT_PRUNED
