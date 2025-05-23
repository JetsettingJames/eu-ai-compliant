#!/usr/bin/env python
"""
Benchmark runner for the EU AI Compliance Assistant.

This script runs all benchmarks and generates a comprehensive performance report.
"""
import os
import sys
import argparse
import asyncio
import time
import subprocess
from datetime import datetime
from typing import List, Dict, Any, Optional

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from tests.benchmarks.utils import BenchmarkManager, BenchmarkResult

# Directory for storing benchmark results
BENCHMARK_RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'benchmark_results')
os.makedirs(BENCHMARK_RESULTS_DIR, exist_ok=True)


def run_benchmark_module(module_path: str) -> None:
    """
    Run a benchmark module as a separate process using pytest.
    
    Args:
        module_path: Path to the benchmark module
    """
    print(f"Running benchmarks in {module_path} using pytest...")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    env = os.environ.copy()
    env['PYTHONPATH'] = project_root + os.pathsep + env.get('PYTHONPATH', '')
    # Use pytest to run the module
    subprocess.run([sys.executable, "-m", "pytest", module_path], check=True, env=env)


def run_all_benchmarks(modules: Optional[List[str]] = None) -> None:
    """
    Run all benchmark modules.
    
    Args:
        modules: Optional list of specific modules to run
    """
    benchmark_dir = os.path.dirname(__file__)
    
    if modules is None:
        # Find all benchmark modules
        modules = [
            os.path.join(benchmark_dir, f)
            for f in os.listdir(benchmark_dir)
            if f.startswith('test_') and f.endswith('_performance.py')
        ]
    else:
        # Use the specified modules
        modules = [
            os.path.join(benchmark_dir, f) if not os.path.isabs(f) else f
            for f in modules
        ]
    
    print(f"Found {len(modules)} benchmark modules to run:")
    for module in modules:
        print(f"  - {os.path.basename(module)}")
    
    # Run each module
    for module in modules:
        run_benchmark_module(module)


def generate_consolidated_report() -> str:
    """
    Generate a consolidated report from all benchmark results.
    
    Returns:
        Path to the consolidated report
    """
    print("Generating consolidated report...")
    
    # Load all benchmark results
    result_files = [
        os.path.join(BENCHMARK_RESULTS_DIR, f)
        for f in os.listdir(BENCHMARK_RESULTS_DIR)
        if f.endswith('.json')
    ]
    
    if not result_files:
        print("No benchmark results found.")
        return ""
    
    results = [BenchmarkManager.load_result(f) for f in result_files]
    
    # Group results by module
    grouped_results = {}
    for result in results:
        module_name = result.name.split('.')[0] if '.' in result.name else 'unknown'
        if module_name not in grouped_results:
            grouped_results[module_name] = []
        grouped_results[module_name].append(result)
    
    # Generate timestamp for report
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(BENCHMARK_RESULTS_DIR, f"consolidated_report_{timestamp_str}")
    os.makedirs(report_dir, exist_ok=True)
    
    # Generate consolidated report
    report_path = BenchmarkManager.generate_report(results, report_path=report_dir)
    
    # Generate module-specific reports
    for module_name, module_results in grouped_results.items():
        module_report_dir = os.path.join(report_dir, module_name)
        os.makedirs(module_report_dir, exist_ok=True)
        BenchmarkManager.generate_report(module_results, report_path=module_report_dir)
    
    print(f"Consolidated report generated at: {report_dir}")
    return report_dir


def generate_optimization_recommendations(results: List[BenchmarkResult]) -> List[str]:
    """
    Generate optimization recommendations based on benchmark results.
    
    Args:
        results: List of benchmark results
        
    Returns:
        List of optimization recommendations
    """
    recommendations = []
    
    # Sort results by average execution time (descending)
    sorted_results = sorted(results, key=lambda r: r.avg_time, reverse=True)
    
    # Identify the slowest operations
    slowest_operations = sorted_results[:3]
    for result in slowest_operations:
        recommendations.append(f"Optimize {result.name}: Currently takes {result.avg_time:.4f}s on average.")
        
        # Add specific recommendations based on the operation
        if "vector_processing" in result.name:
            recommendations.append(f"  - Consider optimizing vector operations in {result.name} by using batch processing.")
            recommendations.append(f"  - Evaluate if the embedding model can be replaced with a faster alternative.")
            recommendations.append(f"  - Consider caching embeddings for frequently accessed content.")
        
        elif "determine_risk_tier" in result.name:
            recommendations.append(f"  - Optimize keyword matching algorithm in {result.name}.")
            recommendations.append(f"  - Consider parallel processing for analyzing different risk tiers.")
            recommendations.append(f"  - Implement early stopping if a high-confidence match is found.")
        
        elif "find_documentation_files" in result.name or "find_code_files" in result.name:
            recommendations.append(f"  - Optimize file traversal in {result.name} by using more efficient algorithms.")
            recommendations.append(f"  - Consider using a more targeted approach instead of scanning all files.")
            recommendations.append(f"  - Implement caching for repository structure.")
    
    # Identify memory-intensive operations
    memory_sorted = sorted(
        [r for r in results if r.memory_usage], 
        key=lambda r: r.peak_memory, 
        reverse=True
    )
    
    if memory_sorted:
        memory_intensive_operations = memory_sorted[:3]
        for result in memory_intensive_operations:
            peak_mb = result.peak_memory / (1024 * 1024)
            recommendations.append(f"Reduce memory usage in {result.name}: Currently uses {peak_mb:.2f} MB at peak.")
            
            # Add specific recommendations based on the operation
            if "upsert" in result.name or "vector" in result.name:
                recommendations.append(f"  - Implement streaming for large document processing in {result.name}.")
                recommendations.append(f"  - Consider reducing chunk size or optimizing text splitting strategy.")
                recommendations.append(f"  - Evaluate if a more memory-efficient vector store can be used.")
            
            elif "analyze" in result.name:
                recommendations.append(f"  - Implement incremental analysis in {result.name} to reduce memory footprint.")
                recommendations.append(f"  - Consider using generators instead of loading all content into memory.")
    
    # General recommendations
    recommendations.append("General optimization recommendations:")
    recommendations.append("  - Implement caching for frequently accessed data.")
    recommendations.append("  - Consider parallel processing for independent operations.")
    recommendations.append("  - Optimize database queries and reduce unnecessary I/O operations.")
    recommendations.append("  - Profile the application in production to identify real-world bottlenecks.")
    
    return recommendations


def main():
    """Main entry point for the benchmark runner."""
    parser = argparse.ArgumentParser(description="Run benchmarks for the EU AI Compliance Assistant.")
    parser.add_argument(
        "--modules", 
        nargs="*", 
        help="Specific benchmark modules to run (default: all)"
    )
    parser.add_argument(
        "--report-only", 
        action="store_true", 
        help="Generate report from existing results without running benchmarks"
    )
    
    args = parser.parse_args()
    
    if not args.report_only:
        run_all_benchmarks(args.modules)
    
    report_dir = generate_consolidated_report()
    
    if report_dir:
        # Load all benchmark results for optimization recommendations
        result_files = [
            os.path.join(BENCHMARK_RESULTS_DIR, f)
            for f in os.listdir(BENCHMARK_RESULTS_DIR)
            if f.endswith('.json')
        ]
        
        results = [BenchmarkManager.load_result(f) for f in result_files]
        
        # Generate optimization recommendations
        recommendations = generate_optimization_recommendations(results)
        
        # Save recommendations to file
        recommendations_path = os.path.join(report_dir, "optimization_recommendations.txt")
        with open(recommendations_path, "w") as f:
            f.write("\n".join(recommendations))
        
        print(f"Optimization recommendations saved to: {recommendations_path}")
        
        # Print recommendations to console
        print("\nOptimization Recommendations:")
        for recommendation in recommendations:
            print(recommendation)


if __name__ == "__main__":
    main()
