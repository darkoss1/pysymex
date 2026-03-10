import ast
import sys
from collections import defaultdict
from pathlib import Path


def audit_file(filepath):
    issues = []
    try:
        with open(filepath, encoding="utf-8") as f:
            content = f.read()
        tree = ast.parse(content)

        for node in ast.walk(tree):
            # Bare excepts
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    issues.append(
                        f"Line {node.lineno}: Bare 'except:' clause (catches KeyboardInterrupt/SystemExit)"
                    )
                elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    # While catching Exception is common, it's worth noting if doing it silently
                    if not node.body or (
                        len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
                    ):
                        issues.append(
                            f"Line {node.lineno}: Silenced Exception in 'except Exception:' (no logging)"
                        )

            # eval/exec
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ("eval", "exec"):
                        issues.append(f"Line {node.lineno}: Unsafe use of '{node.func.id}()'")

            # Mutable default arguments
            if isinstance(node, ast.FunctionDef):
                for arg_default in node.args.defaults:
                    if isinstance(arg_default, (ast.List, ast.Dict, ast.Set)):
                        issues.append(
                            f"Line {node.lineno}: Mutable default argument in function '{node.name}'"
                        )

            # Assertions (shouldn't be used for control flow)
            if isinstance(node, ast.Assert):
                issues.append(
                    f"Line {node.lineno}: Use of 'assert' statement (will be compiled away with -O)"
                )

    except Exception as e:
        issues.append(f"Failed to parse or read file: {e}")

    return issues


def main():
    target_dir = Path(sys.argv[1])
    all_issues = defaultdict(list)

    for filepath in target_dir.rglob("*.py"):
        issues = audit_file(filepath)
        if issues:
            # store relative path
            rel_path = filepath.relative_to(target_dir)
            all_issues[str(rel_path)] = issues

    total_issues = sum(len(v) for v in all_issues.values())
    print(f"Found {total_issues} code smells/issues.\n")

    for file, issues in all_issues.items():
        print(f"--- {file} ---")
        for i in issues:
            print(f"  - {i}")
        print()


if __name__ == "__main__":
    main()
