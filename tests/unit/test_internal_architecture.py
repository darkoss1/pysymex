"""Lightweight checks that internal architecture migrations stay in place."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INTERNAL = ROOT / "pysymex" / "_internal"

FORBIDDEN_INTERNAL_BUCKETS = (
    INTERNAL / "helpers",
    INTERNAL / "misc",
    INTERNAL / "common",
)

REMOVED_LOOSE_HELPER_MODULES = (
    INTERNAL / "config" / "helpers.py",
    INTERNAL / "execution" / "opcodes" / "common" / "collections" / "helpers.py",
    INTERNAL / "execution" / "calls" / "helpers.py",
    INTERNAL / "execution" / "opcodes" / "common" / "numeric" / "helpers.py",
    INTERNAL / "execution" / "opcodes" / "common" / "exceptions" / "helpers.py",
    INTERNAL / "execution" / "opcodes" / "common" / "locals" / "helpers.py",
    INTERNAL / "execution" / "opcodes" / "common" / "control" / "match" / "helpers.py",
    INTERNAL / "tracing" / "analyzer" / "helpers.py",
    INTERNAL / "tracing" / "tracer" / "helpers.py",
    INTERNAL / "execution" / "strategies" / "merger" / "helpers.py",
    INTERNAL / "core" / "solver" / "independence" / "helpers.py",
    INTERNAL / "core" / "types" / "containers" / "helpers.py",
    INTERNAL / "core" / "types" / "scalars" / "value" / "helpers.py",
    INTERNAL / "models" / "stdlib" / "dataclasses" / "helpers.py",
    INTERNAL / "models" / "builtins" / "types" / "containers" / "tuples" / "helpers.py",
    INTERNAL / "analysis" / "detectors" / "specialized" / "helpers.py",
    INTERNAL / "benchmarks" / "suite" / "workload" / "helpers.py",
    INTERNAL / "core" / "z3" / "utils.py",
    INTERNAL / "execution" / "detectors" / "suppression" / "helpers",
    INTERNAL / "models" / "stdlib" / "common.py",
    INTERNAL / "execution" / "opcodes" / "common" / "functions" / "misc.py",
    INTERNAL / "models" / "builtins" / "iteration" / "common.py",
    INTERNAL / "models" / "builtins" / "types" / "containers" / "bytes" / "bytearray" / "misc.py",
)


def test_forbidden_internal_utility_buckets_are_absent() -> None:
    """Generic utils/helpers/misc/common buckets must not reappear under _internal."""
    present = [
        path.relative_to(ROOT).as_posix() for path in FORBIDDEN_INTERNAL_BUCKETS if path.exists()
    ]
    assert present == []


def test_removed_loose_helper_modules_stay_removed() -> None:
    """Migrated loose-helper modules must not return as parallel APIs."""
    present = [
        path.relative_to(ROOT).as_posix() for path in REMOVED_LOOSE_HELPER_MODULES if path.exists()
    ]
    assert present == []


def test_no_helpers_modules_anywhere_under_internal() -> None:
    """helpers.py must not reappear anywhere under _internal after consolidation."""
    present = [
        path.relative_to(ROOT).as_posix() for path in INTERNAL.rglob("helpers.py") if path.is_file()
    ]
    assert present == []


def test_domain_owned_config_coercion_namespace_exists() -> None:
    """Config coercion must be owned by ConfigCoercion."""
    from pysymex._internal.config.coercion import ConfigCoercion

    assert ConfigCoercion.to_int("1", 0) == 1
    assert ConfigCoercion.to_bool("true", False) is True


def test_domain_owned_config_values_namespace_exists() -> None:
    """Config shape guards must be owned by ConfigValues."""
    from pysymex._internal.config.values import ConfigValues

    assert ConfigValues.is_object_dict({"a": 1})
    assert ConfigValues.as_object_dict({"a": 1}) == {"a": 1}


def test_domain_owned_collection_stack_ops_namespace_exists() -> None:
    """Collection stack/heap/unpack helpers must be owned by CollectionStackOps."""
    from pysymex._internal.execution.opcodes.common.collections.stack_ops import (
        CollectionStackOps,
    )

    assert CollectionStackOps.require_depth is not None
    assert CollectionStackOps.unpack_at is not None


def test_domain_owned_collection_fallback_events_namespace_exists() -> None:
    """Collection fallback builders must be owned by CollectionFallbackEvents."""
    from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
        CollectionFallbackEvents,
    )

    assert CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    assert CollectionFallbackEvents.for_degraded_passes is not None


def test_domain_owned_call_fallback_events_namespace_exists() -> None:
    """Call fallback builders must be owned by CallFallbackEvents."""
    from pysymex._internal.execution.calls.target.fallbacks import CallFallbackEvents

    assert CallFallbackEvents.UNSUPPORTED_CALL_PROTOCOL
    assert CallFallbackEvents.unmodeled_call_havoc is not None


def test_domain_owned_trace_event_predicates_namespace_exists() -> None:
    """Trace analyzer predicates must be owned by TraceEventPredicates."""
    from pysymex._internal.tracing.analyzer.predicates import TraceEventPredicates

    assert TraceEventPredicates.str_contains("abc", "b") is True
    assert TraceEventPredicates.as_dict({"a": 1}) == {"a": 1}


def test_domain_owned_exception_flow_namespace_exists() -> None:
    """Exception handler flow must be owned by ExceptionFlow."""
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import (
        ExceptionFlow,
    )

    assert ExceptionFlow.require_depth is not None
    assert ExceptionFlow.jump_to_handler is not None
    assert ExceptionFlow.entry_at is not None
    assert ExceptionFlow.getattr_default is not None


def test_domain_owned_local_stack_ops_namespace_exists() -> None:
    """Local opcode stack helpers must be owned by LocalStackOps."""
    from pysymex._internal.execution.opcodes.common.locals.stack_ops import LocalStackOps

    assert LocalStackOps.require_depth is not None
    assert LocalStackOps.fast_names is not None


def test_domain_owned_match_pattern_ops_namespace_exists() -> None:
    """Match pattern helpers must be owned by MatchPatternOps."""
    from pysymex._internal.execution.opcodes.common.control.match.pattern_ops import (
        MatchPatternOps,
    )

    assert MatchPatternOps.subject is not None
    assert MatchPatternOps.keys is not None
    assert MatchPatternOps.class_attr_names is not None
    assert MatchPatternOps.dispatch_class_attrs is not None


def test_domain_owned_trace_serialization_namespace_exists() -> None:
    """Tracer serialization must be owned by TraceSerialization."""
    from pysymex._internal.tracing.tracer.serialization import TraceSerialization

    assert TraceSerialization.scalar("x") == "x"
    assert TraceSerialization.config_snapshot({"a": 1}) == {"a": 1}


def test_domain_owned_merge_guards_namespace_exists() -> None:
    """Merger guards must be owned by MergeGuards."""
    from pysymex._internal.execution.strategies.merger.merge_guards import MergeGuards

    assert MergeGuards.is_stack_value(42) is True
    assert MergeGuards.as_mapping(None) == {}


def test_domain_owned_independence_z3_ops_namespace_exists() -> None:
    """Constraint independence Z3 views must be owned by IndependenceZ3Ops."""
    from pysymex._internal.core.solver.independence.z3_ops import IndependenceZ3Ops

    assert IndependenceZ3Ops.as_z3_expr is not None
    assert IndependenceZ3Ops.decl_dependency_token is not None


def test_domain_owned_container_storage_ops_namespace_exists() -> None:
    """Container storage helpers must be owned by ContainerStorageOps."""
    from pysymex._internal.core.types.containers.storage_ops import ContainerStorageOps

    assert ContainerStorageOps.storage_int_expr is not None
    assert ContainerStorageOps.known_length_truthiness is not None


def test_domain_owned_scalar_value_ops_namespace_exists() -> None:
    """Scalar value helpers must be owned by ScalarValueOps."""
    from pysymex._internal.core.types.scalars.value.scalar_ops import ScalarValueOps

    assert ScalarValueOps.py_floor_div is not None
    assert ScalarValueOps.int_to_bv is not None


def test_domain_owned_dataclass_model_ops_namespace_exists() -> None:
    """Dataclass stdlib models must be owned by DataclassModelOps."""
    from pysymex._internal.models.stdlib.dataclasses.model_ops import DataclassModelOps

    assert DataclassModelOps.field_model is not None
    assert DataclassModelOps.is_dataclass_model({}) is False


def test_domain_owned_tuple_container_ops_namespace_exists() -> None:
    """Tuple container helpers must be owned by TupleContainerOps."""
    from pysymex._internal.models.builtins.types.containers.tuples.tuple_ops import (
        TupleContainerOps,
    )

    assert TupleContainerOps.get_symbolic_tuple((1, 2)) is not None
    assert TupleContainerOps.get_symbolic_tuple(None) is None


def test_domain_owned_specialized_detector_ops_namespace_exists() -> None:
    """Specialized detector helpers must be owned by SpecializedDetectorOps."""
    from pysymex._internal.analysis.detectors.specialized.detector_ops import (
        SpecializedDetectorOps,
    )

    assert SpecializedDetectorOps.display_name(None) is None
    assert SpecializedDetectorOps.target_name is not None


def test_domain_owned_workload_stats_ops_namespace_exists() -> None:
    """Benchmark workload stat helpers must be owned by WorkloadStatsOps."""
    from pysymex._internal.benchmarks.suite.workload.stats_ops import WorkloadStatsOps

    assert WorkloadStatsOps.solver_queries_from_stats({"queries": 3}) == 3
    assert WorkloadStatsOps.coverage_count({1, 2}) == 2


def test_domain_owned_entrypoint_globals_namespaces_exist() -> None:
    """Entrypoint global selectors must be owned by domain namespaces."""
    from pysymex._internal.execution.entrypoint.globals.callables import CallableGlobals
    from pysymex._internal.execution.entrypoint.globals.containers import EntrypointContainerGlobals
    from pysymex._internal.execution.entrypoint.globals.contracts import ContractGlobals
    from pysymex._internal.execution.entrypoint.globals.inspection import GlobalsInspection
    from pysymex._internal.execution.entrypoint.globals.instances import InstanceGlobals

    assert GlobalsInspection.globals_for is not None
    assert GlobalsInspection.referenced_names is not None
    assert CallableGlobals.select is not None
    assert InstanceGlobals.select is not None
    assert EntrypointContainerGlobals.select is not None
    assert ContractGlobals.select is not None


def test_domain_owned_z3_expression_ops_namespace_exists() -> None:
    """Z3 expression comparisons must be owned by Z3ExpressionOps."""
    from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps

    assert Z3ExpressionOps.safe_eq is not None


def test_domain_owned_log_event_policy_namespace_exists() -> None:
    """Logger event emission must be owned by LogEventPolicy."""
    from pysymex._internal.logging.emit import LogEventPolicy

    assert LogEventPolicy.is_enabled is not None
    assert LogEventPolicy.emit is not None
    assert LogEventPolicy.format_message is not None


def test_domain_owned_log_entry_policy_namespace_exists() -> None:
    """Log entry construction helpers must be owned by LogEntryPolicy."""
    from pysymex._internal.logging.entry import LogEntryPolicy

    assert LogEntryPolicy.exception is not None
    assert LogEntryPolicy.exception(None) is None


def test_domain_owned_stack_value_policy_short_names_exist() -> None:
    """Stack coercion helpers must use concise names on StackValuePolicy."""
    from pysymex._internal.core.types.stack_coercion import StackValuePolicy

    assert StackValuePolicy.coerce is not None
    assert StackValuePolicy.as_symbolic is not None
    assert StackValuePolicy.as_index is not None


def test_domain_owned_trace_schema_defaults_namespace_exists() -> None:
    """Trace schema default factories must be owned by TraceSchemaDefaults."""
    from pysymex._internal.tracing.schemas.primitives import TraceSchemaDefaults

    assert TraceSchemaDefaults.empty_strings() == []
    assert TraceSchemaDefaults.empty_constraints() == []


def test_domain_owned_protocol_returns_namespace_exists() -> None:
    """Protocol return normalization must be owned by ProtocolReturns."""
    from pysymex._internal.execution.opcodes.common.control.protocol.returns.core import (
        ProtocolReturns,
    )

    assert ProtocolReturns.truth is not None
    assert ProtocolReturns.numeric is not None
    assert ProtocolReturns.comparison is not None
    assert ProtocolReturns.construction is not None
    assert ProtocolReturns.length is not None


def test_domain_owned_protocol_object_predicates_namespace_exists() -> None:
    """Modeled-object protocol predicates must be owned by ProtocolObjectPredicates."""
    from pysymex._internal.execution.opcodes.common.control.protocol.returns.objects import (
        ProtocolObjectPredicates,
    )

    assert ProtocolObjectPredicates.is_modeled is not None
    assert ProtocolObjectPredicates.is_non_object is not None
    assert ProtocolObjectPredicates.instance_id is not None


def test_domain_owned_suppression_bytecode_ops_namespace_exists() -> None:
    """Bytecode suppression operations must be owned by SuppressionBytecodeOps."""
    from pysymex._internal.execution.detectors.suppression.bytecode import SuppressionBytecodeOps

    assert SuppressionBytecodeOps.catches_name is not None
    assert SuppressionBytecodeOps.cleanup_replaces_original_at is not None
    assert SuppressionBytecodeOps.cleanup_reraise_at is not None
    assert SuppressionBytecodeOps.infer_caught_at is not None
    assert SuppressionBytecodeOps.infer_with_manager_call_at is not None


def test_domain_owned_suppression_manager_policy_namespace_exists() -> None:
    """Context manager suppression policy must be owned by SuppressionManagerPolicy."""
    from pysymex._internal.execution.detectors.suppression.managers import SuppressionManagerPolicy

    assert SuppressionManagerPolicy.known_suppresses is not None
