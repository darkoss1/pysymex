"""Architecture checks for domain-owned policy namespaces."""

from __future__ import annotations


def test_path_fact_policy_exposes_classify() -> None:
    from pysymex._internal.core.solver.facts import PathFactPolicy

    assert callable(PathFactPolicy.classify)
    assert "classify" in PathFactPolicy.__dict__


def test_profile_frame_policy_exposes_classify() -> None:
    from pysymex._internal.profiling.classification import ProfileFramePolicy

    assert callable(ProfileFramePolicy.classify)
    assert "classify" in ProfileFramePolicy.__dict__


def test_assigns_effect_policy_exposes_classify() -> None:
    from pysymex._internal.contracts.effects.classification import AssignsEffectPolicy

    assert callable(AssignsEffectPolicy.classify)
    assert "classify" in AssignsEffectPolicy.__dict__


def test_execution_result_exposes_from_session_factory() -> None:
    from pysymex._internal.execution.results.result import ExecutionResult

    method = ExecutionResult.from_session
    assert callable(method)
    assert getattr(method, "__self__", None) is ExecutionResult


def test_builtin_input_policy_exposes_classifiers() -> None:
    from pysymex._internal.models.builtins.common.builtin_policies import BuiltinInputPolicy

    assert callable(BuiltinInputPolicy.constant_len)
    assert callable(BuiltinInputPolicy.len_type_error)
    assert callable(BuiltinInputPolicy.iter_type_error)
    assert "constant_len" in BuiltinInputPolicy.__dict__


def test_builtin_aggregate_policy_exposes_helpers() -> None:
    from pysymex._internal.models.builtins.common.builtin_policies import BuiltinAggregatePolicy

    assert callable(BuiltinAggregatePolicy.safe_min_concrete)
    assert callable(BuiltinAggregatePolicy.safe_sorted_concrete)
    assert "safe_sum_concrete" in BuiltinAggregatePolicy.__dict__


def test_scan_profile_report_exposes_from_scan_results_factory() -> None:
    from pysymex._internal.profiling.model import ScanProfileReport

    method = ScanProfileReport.from_scan_results
    assert callable(method)
    assert getattr(method, "__self__", None) is ScanProfileReport


def test_models_shared_package_removed() -> None:
    import importlib.util

    spec = importlib.util.find_spec("pysymex._internal.models.shared")
    assert spec is None


def test_stack_value_policy_exposes_coercion() -> None:
    from pysymex._internal.core.types.stack_coercion import StackValuePolicy

    assert callable(StackValuePolicy.coerce)
    assert callable(StackValuePolicy.as_symbolic)
    assert "as_index" in StackValuePolicy.__dict__


def test_concrete_extraction_policy_exposes_extractors() -> None:
    from pysymex._internal.core.types.concrete_extraction import ConcreteExtractionPolicy

    assert callable(ConcreteExtractionPolicy.sequence)
    assert callable(ConcreteExtractionPolicy.mapping)
    assert "has_keys_mapping_protocol" in ConcreteExtractionPolicy.__dict__


def test_capabilities_expose_sequence_queries() -> None:
    import pysymex._internal.core.types.capabilities as capabilities

    assert callable(capabilities.known_sequence_length)
    assert callable(capabilities.none_expr)


def test_core_types_do_not_import_execution_opcodes() -> None:
    import ast
    from pathlib import Path

    root = Path(__file__).parents[3] / "pysymex" / "_internal" / "core" / "types"
    forbidden = "pysymex._internal.execution.opcodes"
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith(forbidden)
            ):
                offenders.append(f"{path.relative_to(root.parent.parent.parent)}:{node.lineno}")
    assert offenders == []


def test_collection_stack_ops_exposes_domain_api() -> None:
    from pysymex._internal.execution.opcodes.common.collections import stack_ops

    assert hasattr(stack_ops.CollectionStackOps, "require_depth")
    assert hasattr(stack_ops.CollectionStackOps, "unpack_arity_error")


def test_builtin_common_helpers_module_removed() -> None:
    import importlib.util

    spec = importlib.util.find_spec("pysymex._internal.models.builtins.common.helpers")
    assert spec is None


def test_profiling_aggregation_module_removed() -> None:
    import importlib.util

    spec = importlib.util.find_spec("pysymex._internal.profiling.aggregation")
    assert spec is None


def test_execution_result_builder_module_removed() -> None:
    import importlib.util

    spec = importlib.util.find_spec("pysymex._internal.execution.results.builder")
    assert spec is None


def test_path_fact_policy_is_only_public_classifier() -> None:
    import pysymex._internal.core.solver.facts as facts

    assert hasattr(facts, "PathFactPolicy")
    assert not hasattr(facts, "classify_path_facts")


def test_container_shared_modules_do_not_export_type_error_aliases() -> None:
    import importlib

    modules = [
        importlib.import_module("pysymex._internal.models.builtins.types.containers.lists.shared"),
        importlib.import_module("pysymex._internal.models.builtins.types.containers.dicts.shared"),
        importlib.import_module("pysymex._internal.models.builtins.types.containers.bytes.shared"),
        importlib.import_module(
            "pysymex._internal.models.builtins.types.containers.strings.shared"
        ),
        importlib.import_module("pysymex._internal.models.builtins.types.containers.sets.shared"),
        importlib.import_module(
            "pysymex._internal.models.builtins.types.containers.frozensets.shared"
        ),
    ]
    for module in modules:
        for alias in (
            "list_type_error_result",
            "dict_type_error_result",
            "bytes_type_error_result",
            "bytearray_type_error_result",
            "method_type_error_result",
            "set_type_error_result",
            "frozenset_type_error_result",
        ):
            assert not hasattr(module, alias)


def test_subscript_shared_exposes_only_domain_api() -> None:
    import pysymex._internal.execution.opcodes.common.collections.subscript.shared as shared

    assert hasattr(shared, "subscript_exception_result")
    assert not hasattr(shared, "subscript_type_error_result")


def test_numeric_shared_module_removed() -> None:
    import importlib.util

    spec = importlib.util.find_spec("pysymex._internal.models.builtins.types.numeric.shared")
    assert spec is None


def test_sequence_precision_semantics_are_core_owned() -> None:
    import inspect
    import importlib.util

    from pysymex._internal.core.types.containers import sequence_precision
    from pysymex._internal.models.builtins.types.containers.lists import items
    from pysymex._internal.models.builtins.types.containers.tuples import queries
    from pysymex._internal.models.builtins.types.containers.lists.mutations import growth
    from pysymex._internal.models.builtins.types.containers.lists.mutations import ordering
    from pysymex._internal.models.builtins.types.containers.lists import shared

    old_spec = importlib.util.find_spec(
        "pysymex._internal.models.builtins.types.containers.sequence_precision"
    )
    assert old_spec is None
    assert callable(sequence_precision.retained_sequence_item_for_index)
    assert callable(sequence_precision.retained_sequence_index_result)
    assert callable(sequence_precision.retained_sequence_absence_condition)
    assert callable(sequence_precision.remove_first_retained_sequence_item)
    assert callable(sequence_precision.insert_retained_sequence_item)
    assert callable(sequence_precision.normalize_insert_index)
    assert callable(sequence_precision.reverse_retained_sequence)
    assert callable(sequence_precision.sort_retained_sequence)
    assert callable(sequence_precision.concrete_bool_value)
    assert callable(sequence_precision.sequence_index_value)
    assert callable(sequence_precision.sequence_index_error_condition)
    assert not hasattr(shared, "absence_condition")
    assert not hasattr(items, "_index_value")
    assert not hasattr(items, "_index_error_condition")
    assert "sequence_index_error_condition" in inspect.getsource(queries.TupleGetitemModel)
    assert "idx_val >= " not in inspect.getsource(queries.TupleGetitemModel)
    assert not hasattr(growth, "_insert_concrete_item")
    assert not hasattr(growth, "_concrete_insert_index")
    assert not hasattr(ordering, "_concrete_reverse")
    assert not hasattr(ordering, "_sort_concrete_items")


def test_string_search_argument_semantics_are_core_owned() -> None:
    from pysymex._internal.core.types.scalars import string_search
    from pysymex._internal.models.builtins.types.containers.strings.search import affixes
    from pysymex._internal.models.builtins.types.containers.strings.search import counts
    from pysymex._internal.models.builtins.types.containers.strings.search import indexing

    assert callable(string_search.string_type_name_if_definitely_not_string)
    assert callable(string_search.string_slice_bounds_are_definitely_invalid)
    assert callable(string_search.concrete_optional_string_index)
    assert callable(string_search.concrete_string_index)
    assert callable(string_search.concrete_string_slice_args)
    for module in (affixes, counts, indexing):
        assert not hasattr(module, "_definite_non_string_type_name")
        assert not hasattr(module, "_definite_invalid_slice_bounds")
        assert not hasattr(module, "_definite_invalid_slice_bound")
        assert not hasattr(module, "_concrete_optional_int")
        assert not hasattr(module, "_concrete_int")
        assert not hasattr(module, "_exact_slice_args")


def test_string_slice_semantics_are_core_owned() -> None:
    import inspect

    from pysymex._internal.core.types.scalars.strings import SymbolicString
    from pysymex._internal.execution.opcodes.common.collections.read import slices as read_slices
    from pysymex._internal.execution.opcodes.common.collections.slice import read as slice_read

    assert callable(SymbolicString.slice_value)
    for module in (read_slices, slice_read):
        helper = getattr(module, "_slice_symbolic_string")
        source = inspect.getsource(helper)
        assert "slice_value" in source
        assert "substring" not in source
        assert "start < 0" not in source
        assert "stop < 0" not in source


def test_string_affix_removal_semantics_are_core_owned() -> None:
    import inspect

    from pysymex._internal.core.types.scalars.strings import SymbolicString
    from pysymex._internal.models.builtins.types.containers.strings.trimming import (
        StrRemovePrefixModel,
    )
    from pysymex._internal.models.builtins.types.containers.strings.trimming import (
        StrRemoveSuffixModel,
    )

    assert callable(SymbolicString.remove_prefix)
    assert callable(SymbolicString.remove_suffix)
    prefix_source = inspect.getsource(StrRemovePrefixModel.apply)
    suffix_source = inspect.getsource(StrRemoveSuffixModel.apply)
    assert "remove_prefix" in prefix_source
    assert "z3.PrefixOf" not in prefix_source
    assert "removeprefix(" not in prefix_source
    assert "remove_suffix" in suffix_source
    assert "z3.SuffixOf" not in suffix_source
    assert "removesuffix(" not in suffix_source


def test_string_strip_semantics_are_core_owned() -> None:
    import inspect

    from pysymex._internal.core.types.scalars.strings import SymbolicString
    from pysymex._internal.models.builtins.types.containers.strings.trimming import (
        StrLstripModel,
    )
    from pysymex._internal.models.builtins.types.containers.strings.trimming import (
        StrRstripModel,
    )
    from pysymex._internal.models.builtins.types.containers.strings.trimming import (
        StrStripModel,
    )

    assert callable(SymbolicString.strip_value)
    for model in (StrStripModel, StrLstripModel, StrRstripModel):
        source = inspect.getsource(model.apply)
        assert "strip_value" in source
        assert ".strip(" not in source
        assert ".lstrip(" not in source
        assert ".rstrip(" not in source
        assert "z3.PrefixOf" not in source
        assert "z3.SuffixOf" not in source


def test_bytes_slice_semantics_are_core_owned() -> None:
    import inspect

    from pysymex._internal.core.types.containers.bytes import SymbolicBytes
    from pysymex._internal.execution.opcodes.common.collections.read import slices as read_slices
    from pysymex._internal.execution.opcodes.common.collections.slice import read as slice_read

    assert callable(SymbolicBytes.slice_value)
    for module in (read_slices, slice_read):
        helper = getattr(module, "_slice_symbolic_bytes")
        source = inspect.getsource(helper)
        assert "slice_value" in source
        assert "SubSeq" not in source
        assert "start < 0" not in source
        assert "stop < 0" not in source


def test_bytes_search_argument_semantics_are_core_owned() -> None:
    from pysymex._internal.core.types.containers import bytes_search
    from pysymex._internal.models.builtins.types.containers.bytes.search import affixes
    from pysymex._internal.models.builtins.types.containers.bytes.search import counts
    from pysymex._internal.models.builtins.types.containers.bytes.search import indexing
    from pysymex._internal.models.builtins.types.containers.bytes.transforms import replace

    assert callable(bytes_search.concrete_bytes_search_literal)
    assert callable(bytes_search.bytes_type_name_if_definitely_not_bytes_like)
    assert callable(bytes_search.bytes_index_type_name_if_definitely_invalid)
    assert callable(bytes_search.bytes_slice_bounds_are_definitely_invalid)
    assert callable(bytes_search.concrete_optional_bytes_index)
    assert callable(bytes_search.concrete_bytes_index)
    assert callable(bytes_search.concrete_bytes_slice_args)
    assert not hasattr(affixes, "_definite_non_bytes_like_type_name")
    for module in (affixes, counts, indexing):
        assert not hasattr(module, "_definite_invalid_slice_bounds")
        assert not hasattr(module, "_definite_invalid_slice_bound")
        assert not hasattr(module, "_concrete_optional_int")
        assert not hasattr(module, "_exact_slice_args")
    assert not hasattr(replace, "_definite_non_bytes_like_type_name")
    assert not hasattr(replace, "_definite_count_type_name")
    assert not hasattr(replace, "_concrete_int")


def test_bytearray_index_normalization_delegates_to_core_sequence_precision() -> None:
    from pysymex._internal.core.types.containers import sequence_precision
    from pysymex._internal.models.builtins.types.containers.bytes.bytearray import growth
    from pysymex._internal.models.builtins.types.containers.bytes.bytearray import removal

    assert callable(sequence_precision.normalize_insert_index)
    assert callable(sequence_precision.normalize_concrete_index)
    assert not hasattr(growth, "_normalized_insert_index")
    assert not hasattr(removal, "_normalized_existing_index")


def test_dict_retained_selection_semantics_are_core_owned() -> None:
    import importlib.util

    from pysymex._internal.core.types.containers.dict.selection import (
        conditional_retained_lookup_value,
    )

    old_spec = importlib.util.find_spec(
        "pysymex._internal.models.builtins.types.containers.dicts.selection"
    )
    assert old_spec is None
    assert callable(conditional_retained_lookup_value)


def test_set_retention_semantics_are_core_owned() -> None:
    from pysymex._internal.core.types.containers import set_retention
    from pysymex._internal.models.builtins.types.containers.sets import shared

    assert callable(set_retention.set_absence_condition)
    assert callable(set_retention.set_presence_condition)
    assert callable(set_retention.replace_exact_set_value)
    assert callable(set_retention.set_length_expr)
    assert not hasattr(shared, "set_absence_condition")
    assert not hasattr(shared, "set_presence_condition")
    assert not hasattr(shared, "replace_exact_set_value")
    assert not hasattr(shared, "set_length_expr")
