# PySyMex: Cache Implementation & Coverage Analyzer
# --------------------------------------------------
import ast
import json
from pathlib import Path

class CacheMapper(ast.NodeVisitor):
    def __init__(self):
        self.hits = []
        self.current_func = "module"
        # FIX 1: Removed the '@' from CachedAnalysis so the AST parser can catch it
        self.targets = {
            "LRUCache", "PersistentCache", "TieredCache", 
            "hash_function", "hash_bytecode", "structural_hash",
            "cached_is_satisfiable", "CachedAnalysis"
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
    print("\nPySyMex Caching Intelligence Map")
    print("="*60)
    
    # Assuming this script is in pysymex/scripts/
    root = Path(__file__).parent.parent / "pysymex"
    results = {}
    candidates = []

    for path in root.rglob("*.py"):
        # FIX 2: Strict path boundary to avoid skipping valid consumers
        if "pysymex/cache" in str(path).replace("\\", "/"): 
            continue 
            
        with open(path, "r", encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read())
                mapper = CacheMapper()
                mapper.visit(tree)
                if mapper.hits:
                    results[str(path.relative_to(root.parent))] = mapper.hits
            # FIX 3: Catch specific errors so you aren't blind to crashes
            except SyntaxError:
                print(f"  [WARNING] Syntax error in {path.name}, skipping...")
            except Exception: 
                pass

    for path, hits in sorted(results.items()):
        print(f"\n[OK] {path}")
        for func, target, line in hits:
            print(f"     - L{line}: {func} uses {target}")

    # Identify "Cold" files (Heavy logic, no cache)
    print("\n[!] CANDIDATES FOR CACHING (Logic heavy, 0% Cache usage):")
    for path in root.rglob("*.py"):
        rel = str(path.relative_to(root.parent))
        if rel not in results and any(x in rel for x in ["opcodes", "detectors", "models"]):
            candidates.append(rel)
            print(f"     - {rel}")

    # FIX 4: The LLM Bridge (Export to JSON)
    export_data = {
        "cache_hits": results,
        "cold_candidates": candidates
    }
    
    export_path = root.parent / "pysymex_cache_map.json"
    with open(export_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)
        
    print("\n" + "="*60)
    print(f"[+] Exported structured map to: {export_path.name}")

if __name__ == "__main__":
    analyze()