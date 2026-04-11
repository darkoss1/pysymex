# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""GPU-Accelerated CHTD Bag Solver.

Integrates GPU acceleration into the CHTD message-passing algorithm.
Provides a drop-in replacement for CPU-based bag solving used in executor_core.py.

The key insight: CHTD message passing requires enumerating ALL satisfying
assignments within each bag (not just checking SAT), then projecting
valid assignments onto adhesion variables. The GPU can evaluate 2^w
assignments in parallel. Maximum supported treewidth is hardware-dependent determined by available GPU VRAM.

Note: This solver conservatively caps at w=25 by default for memory safety.
Override GPU_MAX_TREEWIDTH if you have sufficient GPU memory (2^30+ states
require 128MB+ output bitmaps).
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import Lock
from typing import TYPE_CHECKING, cast

import numpy as np
import numpy.typing as npt

from pysymex.core.solver.constraints import structural_hash

if TYPE_CHECKING:
    import z3

    from pysymex.core.graph.treewidth import BranchInfo, TreeDecomposition
    from pysymex.accel.chtd_integration import GPUBagEvaluator

logger = logging.getLogger(__name__)


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
    "GPUBagSolver",
    "create_gpu_bag_solver",
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
    projected_messages: dict[frozenset[str], npt.NDArray[np.uint8]] = field(default_factory=dict)

    def is_satisfiable(self) -> bool:
        """Check if at least one assignment satisfies the bag."""
        return self.count > 0

    def get_satisfying_indices(self) -> npt.NDArray[np.intp]:
        """Get indices of all satisfying assignments."""
        bits = _unpackbits_little(self.bitmap)
        indices = [i for i, b in enumerate(bits[: self.num_states]) if int(b) != 0]
        return cast("npt.NDArray[np.intp]", indices)

    @property
    def num_states(self) -> int:
        """Total number of possible assignments."""
        return 1 << len(self.variables)


_GLOBAL_BITMAP_CACHE_MAXSIZE = 4096
_GLOBAL_BITMAP_CACHE: OrderedDict[int, npt.NDArray[np.uint8]] = OrderedDict()
_GLOBAL_BITMAP_CACHE_LOCK = Lock()


def _cache_get(cache_key: int) -> npt.NDArray[np.uint8] | None:
    with _GLOBAL_BITMAP_CACHE_LOCK:
        bitmap = _GLOBAL_BITMAP_CACHE.get(cache_key)
        if bitmap is None:
            return None
        _GLOBAL_BITMAP_CACHE.move_to_end(cache_key)
        return bitmap


def _cache_put(cache_key: int, bitmap: npt.NDArray[np.uint8]) -> None:
    with _GLOBAL_BITMAP_CACHE_LOCK:
        _GLOBAL_BITMAP_CACHE[cache_key] = bitmap
        _GLOBAL_BITMAP_CACHE.move_to_end(cache_key)
        while len(_GLOBAL_BITMAP_CACHE) > _GLOBAL_BITMAP_CACHE_MAXSIZE:
            _GLOBAL_BITMAP_CACHE.popitem(last=False)


class GPUBagSolver:
    """GPU-accelerated solver for CHTD bags.

    Integrates with the existing ConstraintInteractionGraph and
    TreeDecomposition to accelerate the message-passing DP.

    Attributes:
        GPU_THRESHOLD: Minimum treewidth where GPU is beneficial (10)
        GPU_MAX_TREEWIDTH: Conservative memory limit for typical GPUs (25).
            Hardware supports up to w=36, but w>25 requires 128MB+ per bitmap.
            Override this constant if you have high VRAM (16GB+).
    """

    GPU_THRESHOLD: int = 10
    GPU_MAX_TREEWIDTH: int = 25

    def __init__(self, use_gpu: bool = True, warmup: bool = True) -> None:
        """Initialize GPU bag solver.

        Args:
            use_gpu: Whether to use GPU acceleration when available
            warmup: Whether to warmup GPU JIT compilation
        """
        self._use_gpu = use_gpu
        self._gpu_evaluator: GPUBagEvaluator | None = None
        self._cached_solutions: dict[int, BagSolution] = {}
        self._message_inbox: dict[int, list[npt.NDArray[np.uint8]]] = {}
        self._message_inbox_lock = Lock()

        if use_gpu:
            self._init_gpu(warmup)

    def _init_gpu(self, warmup: bool) -> None:
        """Initialize GPU evaluator."""
        from pysymex.accel.chtd_integration import GPUBagEvaluator

        try:
            self._gpu_evaluator = GPUBagEvaluator(
                gpu_threshold=self.GPU_THRESHOLD,
                warmup=warmup,
            )
            logger.info(f"GPU bag solver initialized: {self._gpu_evaluator.get_backend_info()}")
        except ImportError as e:
            logger.debug(f"GPU acceleration not available: {e}")
            self._gpu_evaluator = None

    @property
    def is_gpu_available(self) -> bool:
        """Check if GPU acceleration is available."""
        if self._gpu_evaluator is None:
            return False
        return self._gpu_evaluator.is_available

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
        if len(children) <= 1 or not self.is_gpu_available:
            return [self.solve_bag(c, branch_info) for c in children]

        def _solve_child(child: frozenset[int]) -> BagSolution:
            return self.solve_bag(child, branch_info)

        with ThreadPoolExecutor(max_workers=min(8, len(children))) as executor:
            return list(executor.map(_solve_child, children))

    def solve_bag(
        self,
        bag: frozenset[int],
        branch_info: dict[int, BranchInfo],
        parent_messages: list[npt.NDArray[np.uint8]] | None = None,
        adhesion: frozenset[int] | None = None,
    ) -> BagSolution:
        """Solve a single CHTD bag using GPU acceleration.

        Args:
            bag: Set of branch PCs in this bag
            branch_info: Mapping from PC to BranchInfo
            parent_messages: Constraint bitmaps from child bags
            adhesion: Optional shared adhesion with parent for GPU projection

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

        projected_cache = {}
        if self._should_use_gpu(w) and adhesion is not None:
            adhesion_vars: set[str] = set()
            for pc in adhesion:
                info = branch_info.get(pc)
                if info:
                    adhesion_vars.update(info.base_vars)

            if adhesion_vars:
                combined = z3.And(*constraints) if len(constraints) > 1 else constraints[0]
                from pysymex.accel.bytecode import compile_constraint

                compiled = compile_constraint(combined, variables)

                from pysymex.accel.backends import gpu as cuda

                if cuda.is_available() and hasattr(cuda, "evaluate_bag_projected"):
                    _proj_bitmap = cuda.evaluate_bag_projected(
                        compiled, sorted(adhesion_vars), variables
                    )
                    projected_cache[frozenset(adhesion_vars)] = _proj_bitmap

        if self._should_use_gpu(w):
            bitmap = self._solve_gpu(constraints, variables)
        else:
            bitmap = self._solve_cpu(constraints, variables)

        if parent_messages:
            for msg in parent_messages:
                if len(msg) == len(bitmap):
                    bitmap = bitmap & msg

        count = int(_unpackbits_little(bitmap)[: 1 << w].sum())

        return BagSolution(
            bag_id=hash(bag),
            variables=variables,
            bitmap=bitmap,
            count=count,
            projected_messages=projected_cache,
        )

    def _should_use_gpu(self, w: int) -> bool:
        """Determine if GPU should be used for this bag width."""
        if not self.is_gpu_available:
            return False
        if w < self.GPU_THRESHOLD:
            return False
        if w > self.GPU_MAX_TREEWIDTH:
            return False
        return True

    def _solve_gpu(
        self,
        constraints: list[z3.BoolRef],
        variables: list[str],
    ) -> npt.NDArray[np.uint8]:
        """Solve using GPU acceleration."""
        import z3

        combined = z3.And(*constraints) if len(constraints) > 1 else constraints[0]

        cache_key = hash((structural_hash([combined]), tuple(variables)))
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

        if self._gpu_evaluator is None:
            bitmap = self._solve_cpu(constraints, variables)
            _cache_put(cache_key, bitmap)
            return bitmap

        bitmap = self._gpu_evaluator.evaluate_bag([combined], variables)
        if bitmap is None:
            bitmap = self._solve_cpu(constraints, variables)
            _cache_put(cache_key, bitmap)
            return bitmap

        _cache_put(cache_key, bitmap)
        return bitmap

    def _solve_cpu(
        self,
        constraints: list[z3.BoolRef],
        variables: list[str],
    ) -> npt.NDArray[np.uint8]:
        """Solve using hardware dispatcher (CPU or GPU or Reference).

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

            cache_key = hash((structural_hash([combined]), tuple(variables)))
            cached = _cache_get(cache_key)
            if cached is not None:
                return cached

            compiled = compile_constraint(combined, variables)
            result = dispatcher.evaluate_bag(compiled)
            bitmap = result.bitmap

            _cache_put(cache_key, bitmap)
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
                self._message_inbox[parent_bag_id].append(projected)
            return

        var_positions = {name: idx for idx, name in enumerate(solution.variables)}
        adhesion_indices = [
            var_positions[var] for var in sorted(adhesion_vars) if var in var_positions
        ]

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
            self._message_inbox[parent_bag_id].append(projected)

    def get_messages_for_bag(self, bag_id: int) -> list[npt.NDArray[np.uint8]]:
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
        """Run full CHTD message-passing with GPU/Thread acceleration.

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
            next_ready = []
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

        if not self.is_gpu_available:
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


def create_gpu_bag_solver(use_gpu: bool = True) -> GPUBagSolver:
    """Factory function to create GPU bag solver.

    Args:
        use_gpu: Whether to use GPU acceleration

    Returns:
        Configured GPUBagSolver instance
    """
    return GPUBagSolver(use_gpu=use_gpu)

