# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""SAT-Accelerated CHTD Bag Solver.

Integrates SAT acceleration into the CHTD message-passing algorithm.
Provides a drop-in replacement for CPU-based bag solving used in executor_core.py.

The key insight: CHTD message passing requires enumerating ALL satisfying
assignments within each bag (not just checking SAT), then projecting
valid assignments onto adhesion variables. The SAT backend can evaluate 2^w
assignments in parallel. Maximum supported treewidth is hardware-dependent determined by available system memory.

Note: This solver conservatively caps at w=25 by default for memory safety.
Override SAT_MAX_TREEWIDTH if you have sufficient SAT memory (2^30+ states
require 128MB+ output bitmaps).
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import Lock
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import numpy as np
import numpy.typing as npt

if TYPE_CHECKING:
    import z3

    from pysymex.core.graph.treewidth import BranchInfo, TreeDecomposition
    from pysymex.accel.chtd_integration import SatBagEvaluator

logger = logging.getLogger(__name__)


def _default_projected_messages() -> dict[frozenset[str], npt.NDArray[np.uint8]]:
    """Return default empty projected-message cache."""
    return {}


@runtime_checkable
class _ProjectedSatBackend(Protocol):
    """Protocol for SAT backends that support projection kernels."""

    def is_available(self) -> bool:
        """Report backend availability."""
        ...

    def evaluate_bag_projected(
        self,
        compiled_constraint: object,
        projection_variables: list[str],
        all_variables: list[str],
    ) -> npt.NDArray[np.uint8]:
        """Evaluate projected bitmap for adhesion variables."""
        ...


def _is_bytecode_compatible(expr: "z3.ExprRef") -> bool:
    """Return True if expression is representable by accel bytecode ops."""
    import z3

    seen: set[int] = set()
    stack: list[z3.ExprRef] = [expr]

    allowed_nary = {
        z3.Z3_OP_AND,
        z3.Z3_OP_OR,
        z3.Z3_OP_XOR,
        z3.Z3_OP_IMPLIES,
        z3.Z3_OP_IFF,
        z3.Z3_OP_EQ,
        z3.Z3_OP_DISTINCT,
        z3.Z3_OP_NOT,
        z3.Z3_OP_ITE,
    }

    while stack:
        node = stack.pop()
        node_id = node.get_id()
        if node_id in seen:
            continue
        seen.add(node_id)

        if z3.is_true(node) or z3.is_false(node):
            continue

        if z3.is_const(node):
            if node.sort() == z3.BoolSort():
                continue
            return False

        if node.sort() != z3.BoolSort():
            return False

        if not z3.is_app(node):
            return False

        kind = node.decl().kind()
        if kind not in allowed_nary:
            return False

        if kind in (z3.Z3_OP_EQ, z3.Z3_OP_IFF, z3.Z3_OP_DISTINCT):
            if node.num_args() != 2:
                return False
            if node.arg(0).sort() != z3.BoolSort() or node.arg(1).sort() != z3.BoolSort():
                return False

        if kind == z3.Z3_OP_NOT and node.num_args() != 1:
            return False

        if kind == z3.Z3_OP_ITE:
            if node.num_args() != 3:
                return False
            if (
                node.arg(0).sort() != z3.BoolSort()
                or node.arg(1).sort() != z3.BoolSort()
                or node.arg(2).sort() != z3.BoolSort()
            ):
                return False

        for i in range(node.num_args()):
            stack.append(node.arg(i))

    return True


def _solve_exact_bitmap(
    combined: "z3.BoolRef",
    variables: list[str],
) -> npt.NDArray[np.uint8]:
    """Build an exact SAT bitmap by model enumeration in Z3."""
    import z3

    w = len(variables)
    num_states = 1 << w
    bitmap: npt.NDArray[np.uint8] = np.zeros((num_states + 7) // 8, dtype=np.uint8)

    from pysymex.core.solver.engine import create_solver

    solver = create_solver()
    solver.add(combined)

    if w == 0:
        if solver.check() == z3.sat:
            bitmap[0] |= np.uint8(1)
        return bitmap

    bool_vars = [z3.Bool(name) for name in variables]

    while solver.check() == z3.sat:
        model = solver.model()
        idx = 0
        block_lits: list[z3.BoolRef] = []
        for bit, var in enumerate(bool_vars):
            val = z3.is_true(model.eval(var, model_completion=True))
            if val:
                idx |= 1 << bit
                block_lits.append(var)
            else:
                block_lits.append(z3.Not(var))

        bitmap[idx >> 3] |= np.uint8(1 << (idx & 7))
        solver.add(z3.Not(z3.And(*block_lits)))

    return bitmap


def _extract_bool_var_names(expr: z3.ExprRef) -> set[str]:
    """Collect Boolean variable names referenced by a Z3 expression."""
    import z3

    names: set[str] = set()
    seen: set[int] = set()
    stack: list[z3.ExprRef] = [expr]
    while stack:
        node = stack.pop()
        node_id = node.get_id()
        if node_id in seen:
            continue
        seen.add(node_id)

        if z3.is_const(node) and node.sort() == z3.BoolSort():
            try:
                name = node.decl().name()
            except Exception:
                name = None
            if isinstance(name, str):
                names.add(name)

        for i in range(node.num_args()):
            stack.append(node.arg(i))
    return names


def _unpackbits_little(bitmap: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    """Return unpacked bits in little-endian bit order for each byte."""
    bits = np.unpackbits(bitmap)
    return bits.reshape(-1, 8)[:, ::-1].reshape(-1)


__all__ = [
    "BagSolution",
    "ChtdBagSolver",
    "create_sat_bag_solver",
]


@dataclass
class BagSolution:
    """Solution for a single CHTD bag.

    Contains the bitmap of all satisfying assignments and metadata
    for message passing to parent bags.

    Attributes:
        bag_id: Identifier for this bag
        variables: Ordered list of variable names in this bag
        bitmap: Packed bitmap of satisfying assignments (bit i = assignment i)
        count: Number of satisfying assignments
        projected_messages: Pre-computed projections for adhesion variables
    """

    bag_id: int
    variables: list[str]
    bitmap: npt.NDArray[np.uint8]
    count: int
    projected_messages: dict[frozenset[str], npt.NDArray[np.uint8]] = field(
        default_factory=_default_projected_messages
    )

    def is_satisfiable(self) -> bool:
        """Check if at least one assignment satisfies the bag."""
        return self.count > 0

    def get_satisfying_indices(self) -> list[int]:
        """Get indices of all satisfying assignments."""
        bits = _unpackbits_little(self.bitmap)
        indices = [i for i, b in enumerate(bits[: self.num_states]) if int(b) != 0]
        return indices

    @property
    def num_states(self) -> int:
        """Total number of possible assignments."""
        return 1 << len(self.variables)


_GLOBAL_BITMAP_CACHE_MAXSIZE = 4096
_GLOBAL_BITMAP_CACHE: OrderedDict[
    int,
    list[tuple["z3.ExprRef", tuple[str, ...], npt.NDArray[np.uint8]]],
] = OrderedDict()
_GLOBAL_BITMAP_CACHE_LOCK = Lock()


def _cache_get(
    cache_key: int,
    expr: "z3.ExprRef",
    variables: tuple[str, ...],
) -> npt.NDArray[np.uint8] | None:
    import z3

    with _GLOBAL_BITMAP_CACHE_LOCK:
        bucket = _GLOBAL_BITMAP_CACHE.get(cache_key)
        if bucket is None:
            return None
        _GLOBAL_BITMAP_CACHE.move_to_end(cache_key)
        for cached_expr, cached_variables, bitmap in bucket:
            try:
                if cached_variables == variables and z3.eq(expr, cached_expr):
                    return bitmap
            except z3.Z3Exception:
                continue
        return None


def _cache_put(
    cache_key: int,
    expr: "z3.ExprRef",
    variables: tuple[str, ...],
    bitmap: npt.NDArray[np.uint8],
) -> None:
    with _GLOBAL_BITMAP_CACHE_LOCK:
        bucket = _GLOBAL_BITMAP_CACHE.get(cache_key)
        if bucket is None:
            _GLOBAL_BITMAP_CACHE[cache_key] = [(expr, variables, bitmap)]
        else:
            bucket.append((expr, variables, bitmap))
        _GLOBAL_BITMAP_CACHE.move_to_end(cache_key)
        while len(_GLOBAL_BITMAP_CACHE) > _GLOBAL_BITMAP_CACHE_MAXSIZE:
            _GLOBAL_BITMAP_CACHE.popitem(last=False)


class ChtdBagSolver:
    """SAT-accelerated solver for CHTD bags.

    Integrates with the existing ConstraintInteractionGraph and
    TreeDecomposition to accelerate the message-passing DP.

    Attributes:
        SAT_THRESHOLD: Minimum treewidth where SAT is beneficial (10)
        SAT_MAX_TREEWIDTH: Conservative memory limit for typical SAT backends (25).
            Hardware supports up to w=36, but w>25 requires 128MB+ per bitmap.
            Override this constant if you have high system memory (16GB+).
    """

    SAT_THRESHOLD: int = 10
    SAT_MAX_TREEWIDTH: int = 25

    def __init__(self, use_sat: bool = True, warmup: bool = True) -> None:
        """Initialize SAT bag solver.

        Args:
            use_sat: Whether to use SAT acceleration when available
            warmup: Whether to warmup SAT JIT compilation
        """
        self._use_sat = use_sat
        self._sat_evaluator: "SatBagEvaluator | None" = None
        self._cached_solutions: dict[int, BagSolution] = {}
        self._message_inbox: dict[int, list[tuple[npt.NDArray[np.uint8], list[str]]]] = {}
        self._message_inbox_lock = Lock()

        if use_sat:
            self._init_sat(warmup)

    def _init_sat(self, warmup: bool) -> None:
        """Initialize SAT evaluator."""
        from pysymex.accel.chtd_integration import SatBagEvaluator

        try:
            self._sat_evaluator = SatBagEvaluator(
                sat_threshold=self.SAT_THRESHOLD,
                warmup=warmup,
            )
            logger.info(f"SAT bag solver initialized: {self._sat_evaluator.get_backend_info()}")
        except ImportError as e:
            logger.debug(f"SAT acceleration not available: {e}")
            self._sat_evaluator = None

    @property
    def is_sat_available(self) -> bool:
        """Check if SAT acceleration is available."""
        if self._sat_evaluator is None:
            return False
        return self._sat_evaluator.is_available

    def solve_children_sequential(
        self,
        children: list[frozenset[int]],
        branch_info: dict[int, BranchInfo],
    ) -> list[BagSolution]:
        """Solve multiple child bags concurrently when possible.

        The legacy method name is preserved for compatibility.

        Args:
            children: List of child bags (sets of PCs)
            branch_info: Branch info mapping

        Returns:
            List of BagSolutions
        """
        if len(children) <= 1 or not self.is_sat_available:
            return [self.solve_bag(c, branch_info) for c in children]

        def _solve_child(child: frozenset[int]) -> BagSolution:
            return self.solve_bag(child, branch_info)

        with ThreadPoolExecutor(max_workers=min(8, len(children))) as executor:
            return list(executor.map(_solve_child, children))

    def solve_bag(
        self,
        bag: frozenset[int],
        branch_info: dict[int, BranchInfo],
        parent_messages: list[tuple[npt.NDArray[np.uint8], list[str]]] | None = None,
        adhesion: frozenset[int] | None = None,
    ) -> BagSolution:
        """Solve a single CHTD bag using SAT acceleration.

        Args:
            bag: Set of branch PCs in this bag
            branch_info: Mapping from PC to BranchInfo
            parent_messages: Constraint bitmaps from child bags
            adhesion: Optional shared adhesion with parent for SAT projection

        Returns:
            BagSolution with satisfying assignment bitmap
        """
        import z3

        constraints: list[z3.BoolRef] = []
        all_vars: set[str] = set()

        for pc in bag:
            info = branch_info.get(pc)
            if info is not None and info.condition is not None:
                constraints.append(info.condition)
                all_vars.update(info.base_vars)

        for constraint in constraints:
            try:
                all_vars.update(_extract_bool_var_names(constraint))
            except Exception:
                logger.debug("Failed to extract bool variable names", exc_info=True)

        variables = sorted(all_vars)
        w = len(variables)

        if not constraints:
            num_vars = max(1, len(all_vars))
            num_states = 1 << num_vars
            bitmap: npt.NDArray[np.uint8] = np.ones((num_states + 7) // 8, dtype=np.uint8)
            return BagSolution(
                bag_id=hash(bag), variables=variables or ["_dummy"], bitmap=bitmap, count=num_states
            )

        combined = z3.And(*constraints) if len(constraints) > 1 else constraints[0]
        bytecode_compatible = _is_bytecode_compatible(combined)

        projected_cache: dict[frozenset[str], npt.NDArray[np.uint8]] = {}
        if self._should_use_sat(w) and adhesion is not None and bytecode_compatible:
            adhesion_vars: set[str] = set()
            for pc in adhesion:
                info = branch_info.get(pc)
                if info:
                    adhesion_vars.update(info.base_vars)

            if adhesion_vars:
                from pysymex.accel.bytecode import compile_constraint

                compiled = compile_constraint(combined, variables)

                from pysymex.accel.backends import sat

                if isinstance(sat, _ProjectedSatBackend) and sat.is_available():
                    _proj_bitmap = sat.evaluate_bag_projected(
                        compiled, sorted(adhesion_vars), variables
                    )
                    projected_cache[frozenset(adhesion_vars)] = _proj_bitmap

        if self._should_use_sat(w):
            bitmap = self._solve_sat(constraints, variables)
        else:
            bitmap = self._solve_cpu(constraints, variables)

        if parent_messages:
            for msg_bitmap, msg_vars in parent_messages:
                msg_indices = [variables.index(v) for v in msg_vars if v in variables]
                if not msg_indices:
                    continue

                w_msg = len(msg_vars)
                num_msg_states = 1 << w_msg

                if w_msg == w and msg_indices == list(range(w)):
                    if len(msg_bitmap) == len(bitmap):
                        bitmap = bitmap & msg_bitmap
                    continue

                for i in range(1 << w):
                    if not (bitmap[i >> 3] & (1 << (i & 7))):
                        continue

                    msg_idx = 0
                    for j, pos in enumerate(msg_indices):
                        if (i >> pos) & 1:
                            msg_idx |= 1 << j

                    if msg_idx < num_msg_states:
                        if not (msg_bitmap[msg_idx >> 3] & (1 << (msg_idx & 7))):
                            bitmap[i >> 3] &= ~(1 << (i & 7))

        count = int(_unpackbits_little(bitmap)[: 1 << w].sum())

        return BagSolution(
            bag_id=hash(bag),
            variables=variables,
            bitmap=bitmap,
            count=count,
            projected_messages=projected_cache,
        )

    def _should_use_sat(self, w: int) -> bool:
        """Determine if SAT should be used for this bag width."""
        if not self.is_sat_available:
            return False
        if w < self.SAT_THRESHOLD:
            return False
        if w > self.SAT_MAX_TREEWIDTH:
            return False
        return True

    def _solve_sat(
        self,
        constraints: list[z3.BoolRef],
        variables: list[str],
    ) -> npt.NDArray[np.uint8]:
        """Solve using SAT acceleration."""
        import z3

        combined = z3.And(*constraints) if len(constraints) > 1 else constraints[0]

        if not _is_bytecode_compatible(combined):
            return self._solve_cpu(constraints, variables)

        variables_key = tuple(variables)
        cache_key = combined.hash()
        cached = _cache_get(cache_key, combined, variables_key)
        if cached is not None:
            return cached

        if self._sat_evaluator is None:
            bitmap = self._solve_cpu(constraints, variables)
            _cache_put(cache_key, combined, variables_key, bitmap)
            return bitmap

        bitmap = self._sat_evaluator.evaluate_bag([combined], variables)
        if bitmap is None:
            bitmap = self._solve_cpu(constraints, variables)
            _cache_put(cache_key, combined, variables_key, bitmap)
            return bitmap

        _cache_put(cache_key, combined, variables_key, bitmap)
        return bitmap

    def _solve_cpu(
        self,
        constraints: list[z3.BoolRef],
        variables: list[str],
    ) -> npt.NDArray[np.uint8]:
        """Solve using hardware dispatcher (SAT or CPU or Reference).

        Args:
            constraints: List of Z3 constraints
            variables: List of variable names

        Returns:
            Packed bitmap of satisfying assignments
        """
        import z3

        try:
            from pysymex.accel import dispatcher
            from pysymex.accel.bytecode import compile_constraint

            combined = z3.And(*constraints) if len(constraints) > 1 else constraints[0]

            if not _is_bytecode_compatible(combined):
                variables_key = tuple(variables)
                cache_key = combined.hash()
                cached = _cache_get(cache_key, combined, variables_key)
                if cached is not None:
                    return cached
                bitmap = _solve_exact_bitmap(combined, variables)
                _cache_put(cache_key, combined, variables_key, bitmap)
                return bitmap

            variables_key = tuple(variables)
            cache_key = combined.hash()
            cached = _cache_get(cache_key, combined, variables_key)
            if cached is not None:
                return cached

            compiled = compile_constraint(combined, variables)
            result = dispatcher.evaluate_bag(compiled)
            bitmap = result.bitmap

            _cache_put(cache_key, combined, variables_key, bitmap)
            return bitmap
        except Exception:
            logger.debug("Falling back to conservative bitmap in _solve_cpu", exc_info=True)
            w = len(variables)
            num_states = 1 << w
            bitmap = np.ones((num_states + 7) // 8, dtype=np.uint8)

        return bitmap

    def pass_message(
        self,
        solution: BagSolution,
        parent_bag_id: int,
        adhesion: frozenset[int],
        branch_info: dict[int, BranchInfo],
    ) -> None:
        """Project solution onto adhesion variables and send to parent.

        The projection keeps only the bits corresponding to adhesion
        variable assignments, marginalizing out non-adhesion variables.

        Args:
            solution: Solution from child bag
            parent_bag_id: ID of parent bag
            adhesion: Set of branch PCs shared with parent
            branch_info: Branch info mapping
        """
        adhesion_vars: set[str] = set()
        for pc in adhesion:
            info = branch_info.get(pc)
            if info is not None:
                adhesion_vars.update(info.base_vars)

        if not adhesion_vars:
            return

        if frozenset(adhesion_vars) in solution.projected_messages:
            projected = solution.projected_messages[frozenset(adhesion_vars)]
            with self._message_inbox_lock:
                if parent_bag_id not in self._message_inbox:
                    self._message_inbox[parent_bag_id] = []
                self._message_inbox[parent_bag_id].append((projected, sorted(adhesion_vars)))
            return

        var_positions = {name: idx for idx, name in enumerate(solution.variables)}
        adhesion_list = sorted(adhesion_vars)
        adhesion_indices = [var_positions[var] for var in adhesion_list if var in var_positions]

        if not adhesion_indices:
            return

        w_adhesion = len(adhesion_indices)
        num_adhesion_states = 1 << w_adhesion

        projected: npt.NDArray[np.uint8] = np.zeros((num_adhesion_states + 7) // 8, dtype=np.uint8)

        sat_indices = solution.get_satisfying_indices()
        for idx in sat_indices:
            adhesion_idx = 0
            for i, pos in enumerate(adhesion_indices):
                if (idx >> pos) & 1:
                    adhesion_idx |= 1 << i

            projected[adhesion_idx >> 3] |= np.uint8(1 << (adhesion_idx & 7))

        with self._message_inbox_lock:
            if parent_bag_id not in self._message_inbox:
                self._message_inbox[parent_bag_id] = []
            actual_adhesion_vars = [var for var in adhesion_list if var in var_positions]
            self._message_inbox[parent_bag_id].append((projected, actual_adhesion_vars))

    def get_messages_for_bag(self, bag_id: int) -> list[tuple[npt.NDArray[np.uint8], list[str]]]:
        """Get accumulated messages for a bag from its children."""
        with self._message_inbox_lock:
            return list(self._message_inbox.get(bag_id, []))

    def clear_messages(self, num_bags: int = 0) -> None:
        """Clear all accumulated messages and pre-allocate inbox.

        Args:
            num_bags: Number of bags to pre-allocate inboxes for thread safety.
        """
        with self._message_inbox_lock:
            self._message_inbox.clear()
            for i in range(num_bags):
                self._message_inbox[i] = []
        self._cached_solutions.clear()

    def propagate_all(
        self,
        td: TreeDecomposition,
        branch_info: dict[int, BranchInfo],
    ) -> bool:
        """Run full CHTD message-passing with SAT/Thread acceleration.

        This replaces the sequential propagate_bag_constraints loop.
        It groups bags by depth (layers) and processes each layer in parallel
        using a ThreadPoolExecutor, simulating true stream parallelism.

        Args:
            td: Tree decomposition
            branch_info: Branch info mapping

        Returns:
            True if all bags satisfiable, False if any bag UNSAT
        """
        if not td.bags:
            return True

        num_bags = len(td.bags)
        self.clear_messages(num_bags)

        children_map: dict[int, list[int]] = {i: [] for i in range(num_bags)}
        for i in range(num_bags):
            p = td.get_parent(i)
            if p is not None:
                children_map[p].append(i)

        in_degree = {i: len(children_map[i]) for i in range(num_bags)}

        layers: list[list[int]] = []
        ready = [i for i in range(num_bags) if in_degree[i] == 0]

        while ready:
            layers.append(ready)
            next_ready: list[int] = []
            for node in ready:
                p = td.get_parent(node)
                if p is not None:
                    in_degree[p] -= 1
                    if in_degree[p] == 0:
                        next_ready.append(p)
            ready = next_ready

        def process_bag(bag_id: int) -> bool:
            bag = td.bags.get(bag_id)
            if bag is None:
                return True

            parent = td.get_parent(bag_id)
            adhesion = (
                td.adhesion.get((bag_id, parent), frozenset()) if parent is not None else None
            )

            messages = self.get_messages_for_bag(bag_id)
            solution = self.solve_bag(bag, branch_info, messages, adhesion)

            if not solution.is_satisfiable():
                logger.debug(f"CHTD: Bag {bag_id} is UNSAT")
                return False

            self._cached_solutions[bag_id] = solution

            if parent is not None:
                edge = (bag_id, parent)
                p_adhesion = td.adhesion.get(edge, frozenset())
                self.pass_message(solution, parent, p_adhesion, branch_info)

            return True

        if not self.is_sat_available:
            for layer in layers:
                results = [process_bag(bag_id) for bag_id in layer]
                if not all(results):
                    return False
            return True

        with ThreadPoolExecutor(max_workers=min(8, max(1, num_bags))) as executor:
            for layer in layers:
                results = list(executor.map(process_bag, layer))
                if not all(results):
                    return False

        return True


def create_sat_bag_solver(use_sat: bool = True) -> ChtdBagSolver:
    """Factory function to create SAT bag solver.

    Args:
        use_sat: Whether to use SAT acceleration

    Returns:
        Configured ChtdBagSolver instance
    """
    return ChtdBagSolver(use_sat=use_sat)
