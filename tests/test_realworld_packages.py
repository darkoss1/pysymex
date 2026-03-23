import os
import subprocess
import sys
import tempfile
import pytest

from pysymex.api import scan_pipeline

# These are small, real-world, complex packages.
# six: Extensive use of metaprogramming, sys.modules manipulation, and dynamic classes.
# markupsafe: High string manipulation and type wrapping.
# idna: Massive data tables, tests large file/AST scalability.
REALWORLD_PACKAGES = ["six", "markupsafe", "idna"]

@pytest.fixture(scope="module")
def realworld_env():
    """
    Downloads and installs real-world PyPI packages into an isolated
    temporary directory for PySyMex to analyze.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Install packages into the temporary directory
        packages_to_install = " ".join(REALWORLD_PACKAGES)
        cmd = [sys.executable, "-m", "pip", "install", "--no-deps", "-t", tmpdir] + REALWORLD_PACKAGES
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            yield tmpdir
        except subprocess.CalledProcessError as e:
            pytest.skip(f"Failed to download real-world packages: {e.stderr}")

@pytest.mark.slow
@pytest.mark.parametrize("package_name", REALWORLD_PACKAGES)
def test_pipeline_on_realworld_package(realworld_env, package_name):
    """
    Executes the PySyMex pipeline scanner over real-world packages.
    The primary goal is to ensure the analyzer handles extreme edge cases,
    metaprogramming, massive arrays, and complex control flows WITHOUT
    crashing or raising internal exceptions.
    """
    target_path = os.path.join(realworld_env, package_name)
    
    # six is a single file module, whereas markupsafe and idna are directories
    if package_name == "six":
        target_path += ".py"

    assert os.path.exists(target_path), f"Package path {target_path} not found in test environment."

    # Run the top-level pipeline scan
    try:
        results = scan_pipeline(target_path, recursive=True)
    except Exception as e:
        pytest.fail(f"PySyMex crashed while analyzing real-world package '{package_name}': {e}")

    # Ensure results map was returned
    assert isinstance(results, dict)
    
    # Ensure every scanned file returned an execution result (even if it has 0 issues)
    # We shouldn't assert 0 issues, because real-world code often has actual SMT violations (e.g. division by zero paths)
    for file_path, result in results.items():
        assert result is not None, f"Analysis of {file_path} returned None."
        assert hasattr(result, "issues"), f"Result for {file_path} missing 'issues' attribute."

def test_pysymex_cli_on_requests(realworld_env):
    """
    Test the CLI entry point running against a package.
    We just test 'six' here to ensure the CLI formatting and argparsing 
    doesn't break when throwing real files at it.
    """
    target_path = os.path.join(realworld_env, "six.py")
    
    cmd = [
        sys.executable, "-m", "pysymex", "scan", 
        target_path, 
        "--mode", "pipeline",
        "--format", "json",
        "--auto"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # We expect an exit code of 1 if issues are found, or 0 if 0 issues.
    # What matters is it didn't crash with an unhandled exception (return code 2 or higher usually, though python might just return 1).
    # Let's check stderr for "Internal Error" or "Traceback"
    if "Traceback" in result.stderr:
        pytest.fail(f"CLI crashed during real-world scan:\n{result.stderr}")
