# PySyMex: CHTD-TS Structural Intelligence Map
# -----------------------------------------------
import ast
import json
from pathlib import Path

class CHTDMapper(ast.NodeVisitor):
    def __init__(self):
        self.hits = []
        self.current_func = "module"
        self.targets = {
            "GPUBagSolver", "TreeDecomposition", "ConstraintInteractionGraph",
            "ThompsonSampler", "AdaptivePathManager", "PathManager",
            "propagate_all", "solve_bag", "update_rewards", "select_state",
            "use_chtd", "use_adaptive_path_selection"
        }

    def visit_FunctionDef(self, node):
        old = self.current_func
        self.current_func = node.name
        self.generic_visit(node)
        self.current_func = old

    def visit_Name(self, node):
        if node.id in self.targets:
            self.hits.append((self.current_func, node.id, node.lineno))
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr in self.targets:
            self.hits.append((self.current_func, node.attr, node.lineno))
        self.generic_visit(node)

def analyze():
    print("\nPySyMex CHTD-TS Structural Intelligence Map")
    print("="*60)
    
    root = Path(__file__).parent.parent / "pysymex"
    results = {}
    orphans = []

    for path in root.rglob("*.py"):
        # Normalize slashes for safety
        path_str = str(path).replace("\\", "/")
        
        # Skip the providers
        if any(x in path_str for x in ["treewidth.py", "sampling.py"]): 
            continue 
        
        with open(path, "r", encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read())
                mapper = CHTDMapper()
                mapper.visit(tree)
                if mapper.hits:
                    # Store standard relative path for the dictionary keys
                    results[str(path.relative_to(root.parent)).replace("\\", "/")] = mapper.hits
            # Catch specific errors
            except SyntaxError:
                print(f"  [WARNING] Syntax error in {path.name}, skipping...")
            except Exception: 
                pass

    for path, hits in sorted(results.items()):
        print(f"\n[OK] {path}")
        for func, target, line in hits:
            print(f"     - L{line}: {func} interacts with {target}")

    # Identify files that SHOULD use CHTD but don't
    print("\n[!] ORPHANED PATH LOGIC (Missing CHTD integration):")
    for path in root.rglob("*.py"):
        rel = str(path.relative_to(root.parent)).replace("\\", "/")
        if rel not in results and "execution/strategies" in rel:
            orphans.append(rel)
            print(f"     - {rel}")

    # Export to JSON for the LLM
    export_data = {
        "chtd_integrations": results,
        "orphaned_strategies": orphans
    }
    
    export_path = root.parent / "pysymex_chtd_map.json"
    with open(export_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)
        
    print("\n" + "="*60)
    print(f"[+] Exported structured map to: {export_path.name}")

if __name__ == "__main__":
    analyze()