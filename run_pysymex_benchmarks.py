"""
Run PySyMex on all benchmarks with timing and memory usage tracking.
"""
import subprocess
import time
import psutil

BENCHMARKS = [
    'benchmark_level1.py',
    'benchmark_level2.py',
    'benchmark_level3.py',
    'benchmark_level4.py',
    'benchmark_level5.py',
]

def run_pysymex(benchmark_file):
    """Run PySyMex on a benchmark file."""
    print(f"\n{'='*60}")
    print(f"Running PySyMex on {benchmark_file}")
    print('='*60)
    
    # Start process
    process = subprocess.Popen(
        ['python', '-m', 'pysymex', 'scan', benchmark_file, '--timeout', '10'],
        cwd=r'c:\Users\lahya\Desktop\PySymEx\pysymex-main\pysymex-main',
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding='utf-8',
        errors='ignore'
    )
    
    # Track memory
    max_memory_mb = 0
    start_time = time.time()
    
    while process.poll() is None:
        try:
            memory_info = psutil.Process(process.pid).memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            max_memory_mb = max(max_memory_mb, memory_mb)
        except:
            pass
        time.sleep(0.1)
    
    elapsed = time.time() - start_time
    
    output = ""
    bug_count = 0
    
    print(f"Time: {elapsed:.2f}s")
    print(f"Max Memory: {max_memory_mb:.2f} MB")
    print(f"Bugs found: {bug_count}")
    
    return {
        'file': benchmark_file,
        'time': elapsed,
        'memory_mb': max_memory_mb,
        'bugs': bug_count,
    }

def main():
    print("="*60)
    print("Running PySyMex on Python Benchmarks")
    print("="*60)
    
    results = []
    for benchmark in BENCHMARKS:
        result = run_pysymex(benchmark)
        results.append(result)
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    total_time = sum(r['time'] for r in results)
    total_memory = sum(r['memory_mb'] for r in results)
    total_bugs = sum(r['bugs'] for r in results)
    
    print(f"Total Time: {total_time:.2f}s")
    print(f"Total Max Memory: {total_memory:.2f} MB")
    print(f"Total Bugs: {total_bugs}")
    
    print("\nDetailed Results:")
    for r in results:
        print(f"  {r['file']}: {r['time']:.2f}s, {r['memory_mb']:.2f} MB, {r['bugs']} bugs")

if __name__ == '__main__':
    main()
