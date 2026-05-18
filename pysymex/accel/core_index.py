"""Certified Core Index and Antichain with Cache Eviction."""

import time
from dataclasses import dataclass
from typing import cast

from pysymex.contracts.decorators import ensures, requires
from pysymex.accel.types import (
    AtomId,
    BagId,
    CoreId,
    CoreMask,
    DecompositionId,
    Hash,
    InsertStatus,
    PathMask,
    SubtreeId,
    TheorySignature,
)


def _is_core_certificate(value: object) -> bool:
    return isinstance(value, CoreCertificate)


def _is_path_mask(value: object) -> bool:
    return isinstance(value, PathMask)


def _is_positive_number(value: object) -> bool:
    return isinstance(value, int | float) and value > 0


def _is_non_negative_int(value: object) -> bool:
    return isinstance(value, int) and value >= 0


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


def _is_insert_status(value: object) -> bool:
    return isinstance(value, InsertStatus)


def _is_core_certificate_list(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, CoreCertificate) for item in cast("list[object]", value)
    )


@dataclass(frozen=True)
class CoreCertificate:
    core_id: CoreId
    atoms: tuple[AtomId, ...]
    core_mask: CoreMask
    bag_ids: tuple[BagId, ...]
    subtree_id: SubtreeId | None
    separator_signature: Hash | None
    decomposition_id: DecompositionId
    theory_signature: TheorySignature
    normalized_formula_hash: Hash
    smtlib_hash: Hash
    solver_backend: str
    solver_version: str
    minimized: bool
    rechecked: bool
    solve_time_ms: float
    discovered_at_depth: int


@dataclass
class _CoreMetadata:
    certificate: CoreCertificate
    last_pruned_time: float
    prune_count: int


class CoreIndex:
    """An antichain index for verified UNSAT cores with rarest-atom lookup and eviction."""

    @requires(_is_positive_number)
    def __init__(self, eviction_threshold_seconds: float = 60.0):
        self._cores: set[CoreCertificate] = set()
        self._rarest_atom_map: dict[AtomId, set[CoreCertificate]] = {}
        self._metadata: dict[CoreCertificate, _CoreMetadata] = {}
        self._eviction_threshold = eviction_threshold_seconds

    @requires(_is_core_certificate)
    @ensures(_is_bool)
    def has_subset(self, core: CoreCertificate) -> bool:
        """Check if we already have a core that is a subset of the given core."""
        # For a new core C, we check if any existing core C' is a subset of C
        # i.e., C'.core_mask \subseteq C.core_mask
        for existing in self._cores:
            if core.core_mask.atoms.contains(existing.core_mask.atoms):
                return True
        return False

    @requires(_is_core_certificate)
    def remove_supersets(self, core: CoreCertificate) -> None:
        """Remove any existing cores that are supersets of the given core."""
        to_remove: list[CoreCertificate] = []
        for existing in self._cores:
            if existing.core_mask.atoms.contains(core.core_mask.atoms):
                to_remove.append(existing)

        for existing in to_remove:
            self._remove(existing)

    @requires(_is_core_certificate)
    def _remove(self, core: CoreCertificate) -> None:
        self._cores.remove(core)
        del self._metadata[core]

        rarest = core.core_mask.atoms.rarest_atom
        if rarest is not None and rarest in self._rarest_atom_map:
            self._rarest_atom_map[rarest].discard(core)
            if not self._rarest_atom_map[rarest]:
                del self._rarest_atom_map[rarest]

    @requires(_is_core_certificate)
    def add(self, core: CoreCertificate) -> None:
        """Add a new core to the index."""
        self._cores.add(core)
        self._metadata[core] = _CoreMetadata(
            certificate=core, last_pruned_time=time.time(), prune_count=0
        )

        rarest = core.core_mask.atoms.rarest_atom
        if rarest is not None:
            if rarest not in self._rarest_atom_map:
                self._rarest_atom_map[rarest] = set()
            self._rarest_atom_map[rarest].add(core)

    @requires(_is_core_certificate)
    @ensures(_is_insert_status)
    def insert_core(self, core: CoreCertificate) -> InsertStatus:
        """Insert a core into the antichain, discarding if redundant."""
        if self.has_subset(core):
            return InsertStatus.DISCARD_REDUNDANT
        self.remove_supersets(core)
        self.add(core)
        return InsertStatus.ADDED

    @requires(_is_path_mask)
    @ensures(_is_bool)
    def prunes(self, path_mask: PathMask) -> bool:
        """Check if any core in the index prunes the given path mask."""
        # Rarest-atom lookup: we only need to check cores whose rarest atom
        # is present in the path_mask.
        for path_atom in path_mask.atoms.native_atoms:
            candidate_cores = self._rarest_atom_map.get(path_atom, set())
            for core in candidate_cores:
                if path_mask.atoms.contains(core.core_mask.atoms):
                    self._mark_used(core)
                    return True
        return False

    @requires(_is_core_certificate)
    def _mark_used(self, core: CoreCertificate) -> None:
        if core in self._metadata:
            meta = self._metadata[core]
            meta.last_pruned_time = time.time()
            meta.prune_count += 1

    @ensures(_is_non_negative_int)
    def evict_stale_cores(self) -> int:
        """Evict cores that haven't been used within the threshold.
        Returns the number of evicted cores.
        """
        now = time.time()
        to_remove = [
            core
            for core, meta in self._metadata.items()
            if (now - meta.last_pruned_time) > self._eviction_threshold
        ]

        for core in to_remove:
            self._remove(core)

        return len(to_remove)

    @requires(_is_non_negative_int)
    @ensures(_is_core_certificate_list)
    def get_candidates_for_minimization(self, min_prune_count: int = 10) -> list[CoreCertificate]:
        """Return highly-reused cores for lazy minimization."""
        return [
            core for core, meta in self._metadata.items() if meta.prune_count >= min_prune_count
        ]
