from __future__ import annotations

import json
from pathlib import Path

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.frontier.checkpoints import FrontierReconstructionStatus
from pysymex._internal.execution.frontier.entries import FrontierMaterializationError
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from pysymex._internal.execution.frontier.obligations.digests import state_shadow_digest
from pysymex._internal.execution.frontier.spill.codec.digests import spill_payload_integrity_digest
from pysymex._internal.execution.frontier.spill.policy import (
    FrontierSpillPolicy,
    FrontierSpillStatus,
)
from pysymex._internal.execution.frontier.spill.values.decoding import (
    decode_spill_value_ref,
    decode_spill_value_table,
)
from pysymex._internal.execution.frontier.spill.values.decoding import (
    decode_spill_value_ref as decode_spill_value_ref_owner,
)
from pysymex._internal.execution.frontier.spill.values.decoding import (
    decode_spill_value_table as decode_spill_value_table_owner,
)
from pysymex._internal.execution.frontier.spill.values.encoding import SpillValueEncoder
from pysymex._internal.execution.frontier.spill.values.encoding import (
    SpillValueEncoder as SpillValueEncoderOwner,
)
from pysymex._internal.execution.frontier.spill.values.types import SpillValueDecodeError
from pysymex._internal.execution.frontier.store.core import FrontierWorkStore
from pysymex._internal.typing.protocols import StackValue


def _filesystem_spill_policy(tmp_path: Path) -> FrontierSpillPolicy:
    """Return a filesystem spill policy rooted in the test temp directory."""
    return FrontierSpillPolicy(
        filesystem_spill_enabled=True,
        spill_directory=tmp_path / "frontier-spill",
    )


def test_spill_values_public_exports_point_to_family_owners() -> None:
    """Package-level value exports stay wired to direct encode/decode owners."""
    assert SpillValueEncoder is SpillValueEncoderOwner
    assert decode_spill_value_ref is decode_spill_value_ref_owner
    assert decode_spill_value_table is decode_spill_value_table_owner


def test_frontier_spill_policy_preserves_bytes_root_aliases(tmp_path: Path) -> None:
    """Concrete bytes roots spill through an identity-preserving value table."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    payload = b"frontier-bytes-payload"
    state = VMState(
        stack=[payload, payload],
        local_vars={"left": payload},
        global_vars={"right": payload},
        memory={17: payload},
        pc=5,
        path_id=12,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    selected = store.pop_materialized(0)

    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert selected.stack[0] == payload
    assert selected.stack[0] is selected.stack[1]
    assert selected.stack[0] is selected.local_vars["left"]
    assert selected.stack[0] is selected.global_vars["right"]
    assert selected.stack[0] is selected.memory[17]


def test_frontier_spill_policy_preserves_tuple_root_aliases(tmp_path: Path) -> None:
    """Immutable tuple roots spill while preserving alias and non-alias identity."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    shared_bytes = b"tuple-payload"
    shared_tuple = (shared_bytes, 7)
    distinct_equal_tuple = tuple([shared_bytes, 7])
    state = VMState(
        stack=[shared_tuple, shared_tuple, distinct_equal_tuple],
        local_vars={"item": shared_tuple, "bytes": shared_bytes},
        memory={19: distinct_equal_tuple},
        pc=5,
        path_id=16,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    selected = store.pop_materialized(0)

    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert selected.stack[0] == shared_tuple
    assert selected.stack[0] is selected.stack[1]
    assert selected.stack[0] is selected.local_vars["item"]
    assert selected.stack[0] is not selected.stack[2]
    assert selected.stack[2] is selected.memory[19]
    selected_shared_tuple = selected.stack[0]
    selected_distinct_tuple = selected.stack[2]
    assert isinstance(selected_shared_tuple, tuple)
    assert isinstance(selected_distinct_tuple, tuple)
    assert selected_shared_tuple[0] is selected.local_vars["bytes"]
    assert selected_distinct_tuple[0] is selected.local_vars["bytes"]


def test_frontier_spill_policy_rejects_tuple_with_symbolic_member(tmp_path: Path) -> None:
    """Tuple spill remains fail-closed when any element is not spill-safe."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    symbolic_value, symbolic_constraint = SymbolicValue.symbolic("tuple_spill_symbolic_member")
    tuple_root: StackValue = (symbolic_value,)
    state = VMState(
        stack=[tuple_root],
        local_vars={"tuple": tuple_root},
        path_constraints=[symbolic_constraint],
        pending_constraint_count=1,
        pc=5,
        path_id=17,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.UNSUPPORTED_PAYLOAD
    assert selected is state
    assert selected is not None
    assert selected.stack[0] is tuple_root
    assert selected.local_vars["tuple"] is tuple_root


def test_frontier_spill_policy_preserves_acyclic_list_dict_aliases(
    tmp_path: Path,
) -> None:
    """Acyclic builtin containers spill with alias and mutation identity preserved."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    shared_bytes = b"container-payload"
    shared_list: StackValue = [shared_bytes, (1, shared_bytes)]
    distinct_equal_list: StackValue = [shared_bytes, (1, shared_bytes)]
    shared_dict: StackValue = {"items": shared_list, "bytes": shared_bytes}
    state = VMState(
        stack=[shared_list, shared_list, distinct_equal_list, shared_dict],
        local_vars={"items": shared_list, "mapping": shared_dict, "bytes": shared_bytes},
        memory={23: shared_dict},
        pc=5,
        path_id=18,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    selected = store.pop_materialized(0)

    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    selected_shared_list = selected.stack[0]
    selected_distinct_list = selected.stack[2]
    selected_dict = selected.stack[3]
    assert isinstance(selected_shared_list, list)
    assert isinstance(selected_distinct_list, list)
    assert isinstance(selected_dict, dict)
    assert selected_shared_list is selected.stack[1]
    assert selected_shared_list is selected.local_vars["items"]
    assert selected_shared_list is not selected_distinct_list
    assert selected_dict is selected.local_vars["mapping"]
    assert selected_dict is selected.memory[23]
    assert selected_dict["items"] is selected_shared_list
    assert selected_shared_list[0] is selected.local_vars["bytes"]
    assert selected_distinct_list[0] is selected.local_vars["bytes"]


def test_frontier_spill_policy_rejects_cyclic_container_roots(tmp_path: Path) -> None:
    """Cyclic mutable roots remain live until recursive replay is explicit."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    cyclic_list: list[StackValue] = []
    cyclic_list.append(cyclic_list)
    state = VMState(
        stack=[cyclic_list],
        local_vars={"items": cyclic_list},
        pc=5,
        path_id=19,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.UNSUPPORTED_PAYLOAD
    assert selected is state
    assert selected is not None
    assert selected.stack[0] is cyclic_list
    assert selected.local_vars["items"] is cyclic_list


def test_frontier_spill_policy_rejects_corrupt_value_table(tmp_path: Path) -> None:
    """Malformed value tables fail closed during spilled checkpoint materialization."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    store.add_state(0, VMState(stack=[b"payload"], pc=5, path_id=14))
    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    assert decision.spill_path is not None

    payload = json.loads(decision.spill_path.read_text(encoding="utf-8"))
    payload["values"] = {"bad": "table"}
    payload["expected_spill_digest"] = spill_payload_integrity_digest(payload)
    decision.spill_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FrontierMaterializationError) as exc_info:
        store.pop_materialized(0)

    assert exc_info.value.status is FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH


def test_frontier_spill_policy_rejects_corrupt_value_reference(tmp_path: Path) -> None:
    """Out-of-range value references never reconstruct a partial state."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    store.add_state(0, VMState(stack=[b"payload"], pc=5, path_id=15))
    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    assert decision.spill_path is not None

    payload = json.loads(decision.spill_path.read_text(encoding="utf-8"))
    payload["stack"] = [{"$ref": 99}]
    payload["expected_spill_digest"] = spill_payload_integrity_digest(payload)
    decision.spill_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FrontierMaterializationError) as exc_info:
        store.pop_materialized(0)

    assert exc_info.value.status is FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH


def test_spill_value_encoder_rejects_unsupported_dict_roots() -> None:
    """Dictionary spill only accepts string keys and spill-safe values."""
    encoder = SpillValueEncoder()

    assert encoder.value_ref_payload({1: "bad-key"}) is None
    assert encoder.value_ref_payload({"bad": object()}) is None


@pytest.mark.parametrize(
    "raw_ref",
    [
        "not-object",
        {"$ref": 0, "extra": 1},
        {"$ref": True},
        {1: 0},
    ],
)
def test_decode_spill_value_ref_rejects_malformed_references(raw_ref: object) -> None:
    """Malformed value references fail before a partial root is returned."""
    with pytest.raises(SpillValueDecodeError):
        decode_spill_value_ref(raw_ref, {})


@pytest.mark.parametrize(
    "raw_table",
    [
        ["not-object"],
        [{"kind": "primitive", "value": []}],
        [{"kind": "bytes", "base64": 1}],
        [{"kind": "bytes", "base64": "not base64"}],
        [{"kind": "tuple", "items": "bad"}],
        [{"kind": "list", "items": "bad"}],
        [{"kind": "dict", "items": "bad"}],
        [{"kind": "dict", "items": ["bad"]}],
        [{"kind": "dict", "items": [["key"]]}],
        [{"kind": "dict", "items": [[1, {"$ref": 0}]]}],
        [{"kind": "unsupported"}],
        [{1: "bad"}],
    ],
)
def test_decode_spill_value_table_rejects_malformed_records(raw_table: object) -> None:
    """Malformed value-table records never reconstruct partial roots."""
    with pytest.raises(SpillValueDecodeError):
        decode_spill_value_table(raw_table)
