from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import extract_bool_assignments, get_variable_names_all

class ResourceStateContradictionRule(LogicRule):
    name = "Resource State Contradiction"
    tier = 5

    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        resource_names = [
            n
            for n in names
            if any(tag in n.lower() for tag in ("resource", "file", "socket", "handle", "stream", "lock"))
        ]
        if not resource_names:
            return False

        bool_values = extract_bool_assignments(ctx.core)
        for name in resource_names:
            values = bool_values.get(name)
            if values and len(values) > 1:
                return True

        lower_names = {n.lower() for n in names}
        # Common lifecycle conflicts such as open + closed or released + in_use.
        conflict_pairs = [
            ("open", "closed"),
            ("acquired", "released"),
            ("locked", "unlocked"),
            ("in_use", "closed"),
        ]
        for a, b in conflict_pairs:
            if any(a in n for n in lower_names) and any(b in n for n in lower_names):
                return True

        return False
