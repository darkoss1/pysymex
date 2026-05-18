"""Types for the v3 acceleration architecture."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Final, Literal

from pysymex.contracts.decorators import ensures, requires

AtomId = int
Hash = str
DecompositionId = int
BagId = int
SelectorLit = int
ProgramCounter = int
SymbolicVarId = str
HeapObjectId = int
ArraySymbolId = str
UninterpretedFunctionId = str
NormalizedExpr = object  # Stand-in for actual normalized Z3 expression or internal AST
SubtreeId = int
NogoodId = int
CoreId = int


class TheorySignature(Enum):
    PURE_BOOL = auto()
    BIT_VECTOR = auto()
    LINEAR_ARITHMETIC = auto()
    ARRAYS_UF = auto()
    MIXED = auto()
    UNKNOWN = auto()


class InsertStatus(Enum):
    DISCARD_REDUNDANT = auto()
    ADDED = auto()


class PruneResult(Enum):
    PRUNED_BY_CERTIFIED_CORE = auto()
    PRUNED_AFTER_VALIDATION = auto()
    NOT_PRUNED = auto()


def _is_compressed_bitmap(value: object) -> bool:
    return isinstance(value, CompressedBitmap)


def _is_atom_or_none(value: object) -> bool:
    return value is None or isinstance(value, int)


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


@dataclass(frozen=True)
class BranchAtom:
    atom_id: AtomId
    pc: ProgramCounter
    polarity: Literal["true", "false"]
    expr_hash: Hash
    normalized_expr: NormalizedExpr
    variables: frozenset[SymbolicVarId]
    heap_objects: frozenset[HeapObjectId]
    array_symbols: frozenset[ArraySymbolId]
    uf_symbols: frozenset[UninterpretedFunctionId]
    theory_signature: TheorySignature
    ssa_signature: Hash
    memory_epoch: Hash


@dataclass(frozen=True)
class SeparatorNogood:
    nogood_id: NogoodId
    subtree_id: SubtreeId
    separator_signature: Hash
    separator_atoms: tuple[AtomId, ...]
    internal_core: tuple[AtomId, ...]
    core_certificate_id: CoreId
    rechecked: bool


@dataclass(frozen=True)
class CompressedBitmap:
    """A sparse bitmap mask for path and core containment.

    This is a stand-in for a native Roaring Bitmap extension.
    Operations here should theoretically cross the GIL boundary.
    """

    native_atoms: frozenset[AtomId]

    @requires(_is_compressed_bitmap)
    @ensures(_is_bool)
    def contains(self, other: "CompressedBitmap") -> bool:
        """Return True if this bitmap contains the other bitmap."""
        return other.native_atoms.issubset(self.native_atoms)

    @requires(_is_compressed_bitmap)
    @ensures(_is_compressed_bitmap)
    def intersection(self, other: "CompressedBitmap") -> "CompressedBitmap":
        """Return the intersection of two bitmaps."""
        return CompressedBitmap(self.native_atoms.intersection(other.native_atoms))

    @property
    @ensures(_is_atom_or_none)
    def rarest_atom(self) -> AtomId | None:
        """Return a deterministic representative atom (e.g. min ID) for indexing."""
        if not self.native_atoms:
            return None
        return min(self.native_atoms)


@dataclass(frozen=True)
class PathMask:
    atoms: Final[CompressedBitmap]


@dataclass(frozen=True)
class CoreMask:
    atoms: Final[CompressedBitmap]


@dataclass(frozen=True)
class AccelCandidate:
    status: Literal["sat", "unsat", "unknown"]
    atom_ids: tuple[AtomId, ...]
    cnf_hash: Hash | None
    translation_hash: Hash | None
    backend: str
    generation_id: int
