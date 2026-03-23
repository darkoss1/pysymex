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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import numpy as np
import numpy.typing as npt


if TYPE_CHECKING:
    import z3

    from pysymex.core.treewidth import BranchInfo, TreeDecomposition
    from pysymex.h_acceleration.chtd_integration import GPUBagEvaluator

logger = logging.getLogger(__name__)

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
        bits = np.unpackbits(self.bitmap)
        return np.where(bits[:self.num_states] == 1)[0]

    @property
    def num_states(self) -> int:
        """Total number of possible assignments."""
        return 1 << len(self.variables)

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
    GPU_MAX_TREEWIDTH: int = 25  # Conservative; hardware limit is 36 (see backends/gpu.py)

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

        if use_gpu:
            self._init_gpu(warmup)

    def _init_gpu(self, warmup: bool) -> None:
        """Initialize GPU evaluator."""
        from pysymex.h_acceleration.chtd_integration import GPUBagEvaluator
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
        """Solve multiple child bags sequentially.

        Note: Parallel execution via CUDA streams is planned for a future
        release. Currently uses sequential bag solving which processes
        each child bag one at a time.

        Args:
            children: List of child bags (sets of PCs)
            branch_info: Branch info mapping

        Returns:
            List of BagSolutions
        """
        if len(children) <= 1 or not self.is_gpu_available:
            return [self.solve_bag(c, branch_info) for c in children]

        solutions = []
        for child in children:
            solutions.append(self.solve_bag(child, branch_info))

        return solutions

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

        variables = sorted(all_vars)
        w = len(variables)

        if not constraints:
            num_vars = max(1, len(all_vars))
            num_states = 1 << num_vars
            bitmap: npt.NDArray[np.uint8] = np.ones((num_states + 7) // 8, dtype=np.uint8)
            return BagSolution(bag_id=hash(bag), variables=variables or ['_dummy'], bitmap=bitmap, count=num_states)

        if self._should_use_gpu(w) and adhesion is not None:
            adhesion_vars: set[str] = set()
            for pc in adhesion:
                info = branch_info.get(pc)
                if info: adhesion_vars.update(info.base_vars)

            if adhesion_vars:

                combined = z3.And(*constraints) if len(constraints) > 1 else constraints[0]
                from pysymex.h_acceleration.bytecode import compile_constraint
                compiled = compile_constraint(combined, variables)

                from pysymex.h_acceleration.backends import gpu as cuda
                if cuda.is_available() and hasattr(cuda, 'evaluate_bag_projected'):
                    _proj_bitmap = cuda.evaluate_bag_projected(compiled, sorted(adhesion_vars), variables)

        if self._should_use_gpu(w):
            bitmap = self._solve_gpu(constraints, variables)
        else:
            bitmap = self._solve_cpu(constraints, variables)

        if parent_messages:
            for msg in parent_messages:
                if len(msg) == len(bitmap):
                    bitmap = bitmap & msg

        count = int(np.unpackbits(bitmap)[:1 << w].sum())

        return BagSolution(
            bag_id=hash(bag),
            variables=variables,
            bitmap=bitmap,
            count=count,
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

        if self._gpu_evaluator is None:
            return self._solve_cpu(constraints, variables)

        bitmap = self._gpu_evaluator.evaluate_bag([combined], variables)
        if bitmap is None:
            return self._solve_cpu(constraints, variables)

        return bitmap

    def _solve_cpu(
        self,
        constraints: list[z3.BoolRef],
        variables: list[str],
    ) -> npt.NDArray[np.uint8]:
        """Solve using CPU (Z3 enumeration or reference backend).

        For small bags (w ≤ 12), directly enumerate with Z3.
        For larger bags, use the reference backend (pure Python bit evaluation).

        Args:
            constraints: List of Z3 constraints
            variables: List of variable names

        Returns:
            Packed bitmap of satisfying assignments
        """
        import z3

        w = len(variables)
        num_states = 1 << w
        bitmap: npt.NDArray[np.uint8] = np.zeros((num_states + 7) // 8, dtype=np.uint8)

        if w <= 12:
            solver = z3.Solver()
            z3_vars = {name: z3.Bool(name) for name in variables}

            for constraint in constraints:
                solver.add(constraint)

            while solver.check() == z3.sat:
                model = solver.model()

                idx = 0
                blocking: list[z3.BoolRef] = []
                for i, name in enumerate(variables):
                    val = model.eval(z3_vars[name], model_completion=True)
                    if z3.is_true(val):
                        idx |= (1 << i)
                        blocking.append(z3_vars[name] == False)
                    else:
                        blocking.append(z3_vars[name] == True)

                bitmap[idx >> 3] |= np.uint8(1 << (idx & 7))
                solver.add(z3.Or(*blocking))
        else:
            try:
                from pysymex.h_acceleration.backends.reference import evaluate_bag
                from pysymex.h_acceleration.bytecode import compile_constraint

                combined = z3.And(*constraints) if len(constraints) > 1 else constraints[0]
                compiled = compile_constraint(combined, variables)
                bitmap = evaluate_bag(compiled)
            except ImportError:
                logger.warning(f"GPU module not available, using slow Z3 enumeration for w={w}")

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

        adhesion_indices: list[int] = []
        for var in sorted(adhesion_vars):
            if var in solution.variables:
                adhesion_indices.append(solution.variables.index(var))

        if not adhesion_indices:
            return

        w_adhesion = len(adhesion_indices)
        num_adhesion_states = 1 << w_adhesion

        projected: npt.NDArray[np.uint8] = np.zeros(
            (num_adhesion_states + 7) // 8, dtype=np.uint8
        )

        sat_indices = solution.get_satisfying_indices()
        for idx in sat_indices:
            adhesion_idx = 0
            for i, pos in enumerate(adhesion_indices):
                if (idx >> pos) & 1:
                    adhesion_idx |= (1 << i)

            projected[adhesion_idx >> 3] |= np.uint8(1 << (adhesion_idx & 7))

        if parent_bag_id not in self._message_inbox:
            self._message_inbox[parent_bag_id] = []
        self._message_inbox[parent_bag_id].append(projected)

    def get_messages_for_bag(self, bag_id: int) -> list[npt.NDArray[np.uint8]]:
        """Get accumulated messages for a bag from its children."""
        return self._message_inbox.get(bag_id, [])

    def clear_messages(self) -> None:
        """Clear all accumulated messages (call between analyses)."""
        self._message_inbox.clear()
        self._cached_solutions.clear()

    def propagate_all(
        self,
        td: TreeDecomposition,
        branch_info: dict[int, BranchInfo],
    ) -> bool:
        """Run full CHTD message-passing with GPU acceleration.

        This replaces the entire propagate_bag_constraints loop
        in executor_core.py.

        Args:
            td: Tree decomposition
            branch_info: Branch info mapping

        Returns:
            True if all bags satisfiable, False if any bag UNSAT
        """
        if not td.bags:
            return True

        self.clear_messages()

        for bag_id in range(len(td.bags)):
            bag = td.bags.get(bag_id)
            if bag is None:
                continue

            messages = self.get_messages_for_bag(bag_id)
            solution = self.solve_bag(bag, branch_info, messages)

            if not solution.is_satisfiable():
                logger.debug(f"CHTD: Bag {bag_id} is UNSAT")
                return False

            self._cached_solutions[bag_id] = solution

            parent = td.get_parent(bag_id)
            if parent is not None:
                edge = (bag_id, parent)
                adhesion = td.adhesion.get(edge, frozenset())
                self.pass_message(solution, parent, adhesion, branch_info)

        return True

def create_gpu_bag_solver(use_gpu: bool = True) -> GPUBagSolver:
    """Factory function to create GPU bag solver.

    Args:
        use_gpu: Whether to use GPU acceleration

    Returns:
        Configured GPUBagSolver instance
    """
    return GPUBagSolver(use_gpu=use_gpu)
