"""
Benchmarking utilities for measuring and reporting performance metrics.
"""
import time
import functools
import statistics
import json
import os
from typing import List, Dict, Any, Callable, Optional, Union, Tuple
import asyncio
import inspect
import tracemalloc
import csv
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np

# Directory for storing benchmark results
BENCHMARK_RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'benchmark_results')
os.makedirs(BENCHMARK_RESULTS_DIR, exist_ok=True)

class BenchmarkResult:
    """Container for benchmark results with analysis capabilities."""
    
    def __init__(self, 
                 name: str, 
                 execution_times: List[float], 
                 memory_usage: List[Tuple[int, int]] = None,
                 metadata: Dict[str, Any] = None):
        """
        Initialize benchmark result.
        
        Args:
            name: Name of the benchmarked function or operation
            execution_times: List of execution times in seconds
            memory_usage: List of memory usage measurements (peak, diff)
            metadata: Additional information about the benchmark
        """
        self.name = name
        self.execution_times = execution_times
        self.memory_usage = memory_usage or []
        self.metadata = metadata or {}
        self.timestamp = datetime.now()
    
    @property
    def avg_time(self) -> float:
        """Average execution time."""
        return statistics.mean(self.execution_times)
    
    @property
    def median_time(self) -> float:
        """Median execution time."""
        return statistics.median(self.execution_times)
    
    @property
    def min_time(self) -> float:
        """Minimum execution time."""
        return min(self.execution_times)
    
    @property
    def max_time(self) -> float:
        """Maximum execution time."""
        return max(self.execution_times)
    
    @property
    def std_dev(self) -> float:
        """Standard deviation of execution times."""
        return statistics.stdev(self.execution_times) if len(self.execution_times) > 1 else 0
    
    @property
    def peak_memory(self) -> int:
        """Peak memory usage in bytes."""
        return max([peak for peak, _ in self.memory_usage]) if self.memory_usage else 0
    
    @property
    def avg_memory_diff(self) -> float:
        """Average memory difference."""
        return statistics.mean([diff for _, diff in self.memory_usage]) if self.memory_usage else 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "name": self.name,
            "timestamp": self.timestamp.isoformat(),
            "execution_times": {
                "values": self.execution_times,
                "avg": self.avg_time,
                "median": self.median_time,
                "min": self.min_time,
                "max": self.max_time,
                "std_dev": self.std_dev
            },
            "memory_usage": {
                "measurements": self.memory_usage,
                "peak_bytes": self.peak_memory,
                "avg_diff_bytes": self.avg_memory_diff
            },
            "metadata": self.metadata
        }
    
    def save_to_file(self, filename: Optional[str] = None) -> str:
        """
        Save benchmark results to file.
        
        Args:
            filename: Optional filename, defaults to name_timestamp.json
            
        Returns:
            Path to the saved file
        """
        if filename is None:
            timestamp_str = self.timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"{self.name.replace(' ', '_')}_{timestamp_str}.json"
        
        filepath = os.path.join(BENCHMARK_RESULTS_DIR, filename)
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        
        return filepath
    
    def plot(self, save_path: Optional[str] = None) -> str:
        """
        Generate performance plots.
        
        Args:
            save_path: Optional path to save the plot
            
        Returns:
            Path to the saved plot
        """
        if save_path is None:
            timestamp_str = self.timestamp.strftime("%Y%m%d_%H%M%S")
            save_path = os.path.join(BENCHMARK_RESULTS_DIR, 
                                    f"{self.name.replace(' ', '_')}_{timestamp_str}.png")
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
        
        # Execution time plot
        iterations = range(1, len(self.execution_times) + 1)
        ax1.plot(iterations, self.execution_times, 'bo-', label='Execution Time')
        ax1.axhline(y=self.avg_time, color='r', linestyle='--', label=f'Average: {self.avg_time:.4f}s')
        ax1.fill_between(iterations, 
                         [self.avg_time - self.std_dev] * len(iterations),
                         [self.avg_time + self.std_dev] * len(iterations),
                         alpha=0.2, color='r')
        ax1.set_xlabel('Iteration')
        ax1.set_ylabel('Time (seconds)')
        ax1.set_title(f'Execution Time: {self.name}')
        ax1.legend()
        ax1.grid(True)
        
        # Memory usage plot if available
        if self.memory_usage:
            peaks = [peak / (1024 * 1024) for peak, _ in self.memory_usage]  # Convert to MB
            diffs = [diff / (1024 * 1024) for _, diff in self.memory_usage]  # Convert to MB
            
            ax2.bar(iterations, peaks, alpha=0.7, label='Peak Memory (MB)')
            ax2.plot(iterations, diffs, 'ro-', label='Memory Difference (MB)')
            ax2.set_xlabel('Iteration')
            ax2.set_ylabel('Memory (MB)')
            ax2.set_title('Memory Usage')
            ax2.legend()
            ax2.grid(True)
        else:
            ax2.text(0.5, 0.5, 'No memory data available', 
                     horizontalalignment='center', verticalalignment='center',
                     transform=ax2.transAxes)
        
        plt.tight_layout()
        plt.savefig(save_path)
        plt.close()
        
        return save_path
    
    def __str__(self) -> str:
        """String representation of benchmark results."""
        result = [
            f"Benchmark: {self.name}",
            f"Timestamp: {self.timestamp}",
            f"Iterations: {len(self.execution_times)}",
            f"Average Time: {self.avg_time:.6f}s",
            f"Median Time: {self.median_time:.6f}s",
            f"Min Time: {self.min_time:.6f}s",
            f"Max Time: {self.max_time:.6f}s",
            f"Std Dev: {self.std_dev:.6f}s"
        ]
        
        if self.memory_usage:
            result.extend([
                f"Peak Memory: {self.peak_memory / (1024 * 1024):.2f} MB",
                f"Avg Memory Diff: {self.avg_memory_diff / (1024 * 1024):.2f} MB"
            ])
        
        if self.metadata:
            result.append("Metadata:")
            for key, value in self.metadata.items():
                result.append(f"  {key}: {value}")
        
        return "\n".join(result)


def benchmark(func=None, *, 
              iterations: int = 5, 
              warmup: int = 1,
              track_memory: bool = True,
              metadata: Dict[str, Any] = None) -> Callable:
    """
    Decorator for benchmarking functions.
    
    Args:
        func: Function to benchmark
        iterations: Number of iterations to run
        warmup: Number of warmup iterations (not included in results)
        track_memory: Whether to track memory usage
        metadata: Additional metadata to include in results
        
    Returns:
        Decorated function
    """
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        
        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            # Warmup runs
            for _ in range(warmup):
                fn(*args, **kwargs)
            
            execution_times = []
            memory_measurements = []
            
            for _ in range(iterations):
                if track_memory:
                    tracemalloc.start()
                    start_memory = tracemalloc.get_traced_memory()
                
                start_time = time.perf_counter()
                result = fn(*args, **kwargs)
                end_time = time.perf_counter()
                
                if track_memory:
                    peak_memory, _ = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
                    memory_diff = peak_memory - start_memory[0]
                    memory_measurements.append((peak_memory, memory_diff))
                
                execution_times.append(end_time - start_time)
            
            # Create and save benchmark results
            bench_result = BenchmarkResult(
                name=fn.__name__,
                execution_times=execution_times,
                memory_usage=memory_measurements if track_memory else None,
                metadata=metadata
            )
            
            # Print results to console
            print(bench_result)
            
            # Save results to file
            bench_result.save_to_file()
            bench_result.plot()
            
            return result
        
        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            # Warmup runs
            for _ in range(warmup):
                await fn(*args, **kwargs)
            
            execution_times = []
            memory_measurements = []
            
            for _ in range(iterations):
                if track_memory:
                    tracemalloc.start()
                    start_memory = tracemalloc.get_traced_memory()
                
                start_time = time.perf_counter()
                result = await fn(*args, **kwargs)
                end_time = time.perf_counter()
                
                if track_memory:
                    peak_memory, _ = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
                    memory_diff = peak_memory - start_memory[0]
                    memory_measurements.append((peak_memory, memory_diff))
                
                execution_times.append(end_time - start_time)
            
            # Create and save benchmark results
            bench_result = BenchmarkResult(
                name=fn.__name__,
                execution_times=execution_times,
                memory_usage=memory_measurements if track_memory else None,
                metadata=metadata
            )
            
            # Print results to console
            print(bench_result)
            
            # Save results to file
            bench_result.save_to_file()
            bench_result.plot()
            
            return result
        
        return async_wrapper if is_async else sync_wrapper
    
    return decorator(func) if func else decorator


class BenchmarkManager:
    """
    Manager for running and comparing benchmarks.
    """
    
    @staticmethod
    def load_result(filepath: str) -> BenchmarkResult:
        """Load benchmark result from file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        result = BenchmarkResult(
            name=data["name"],
            execution_times=data["execution_times"]["values"],
            memory_usage=data.get("memory_usage", {}).get("measurements", []),
            metadata=data.get("metadata", {})
        )
        result.timestamp = datetime.fromisoformat(data["timestamp"])
        return result
    
    @staticmethod
    def compare_results(results: List[BenchmarkResult], 
                        save_path: Optional[str] = None) -> str:
        """
        Compare multiple benchmark results.
        
        Args:
            results: List of benchmark results to compare
            save_path: Optional path to save the comparison plot
            
        Returns:
            Path to the saved comparison plot
        """
        if not results:
            raise ValueError("No results to compare")
        
        if save_path is None:
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = os.path.join(BENCHMARK_RESULTS_DIR, f"comparison_{timestamp_str}.png")
        
        # Prepare data for plotting
        names = [result.name for result in results]
        avg_times = [result.avg_time for result in results]
        std_devs = [result.std_dev for result in results]
        
        # Create comparison plot
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        
        # Execution time comparison
        x = np.arange(len(names))
        ax1.bar(x, avg_times, yerr=std_devs, align='center', alpha=0.7, ecolor='black', capsize=10)
        ax1.set_ylabel('Average Time (seconds)')
        ax1.set_xticks(x)
        ax1.set_xticklabels(names, rotation=45, ha='right')
        ax1.set_title('Execution Time Comparison')
        ax1.grid(True, axis='y')
        
        # Memory usage comparison if available
        has_memory = all(result.memory_usage for result in results)
        if has_memory:
            peak_memory = [result.peak_memory / (1024 * 1024) for result in results]  # Convert to MB
            avg_memory_diff = [result.avg_memory_diff / (1024 * 1024) for result in results]  # Convert to MB
            
            ax2.bar(x - 0.2, peak_memory, width=0.4, label='Peak Memory (MB)', color='blue', alpha=0.7)
            ax2.bar(x + 0.2, avg_memory_diff, width=0.4, label='Avg Memory Diff (MB)', color='red', alpha=0.7)
            ax2.set_ylabel('Memory (MB)')
            ax2.set_xticks(x)
            ax2.set_xticklabels(names, rotation=45, ha='right')
            ax2.set_title('Memory Usage Comparison')
            ax2.legend()
            ax2.grid(True, axis='y')
        else:
            ax2.text(0.5, 0.5, 'Memory data not available for all benchmarks', 
                     horizontalalignment='center', verticalalignment='center',
                     transform=ax2.transAxes)
        
        plt.tight_layout()
        plt.savefig(save_path)
        plt.close()
        
        return save_path
    
    @staticmethod
    def generate_report(results: List[BenchmarkResult], 
                        report_path: Optional[str] = None) -> str:
        """
        Generate a comprehensive benchmark report.
        
        Args:
            results: List of benchmark results
            report_path: Optional path to save the report
            
        Returns:
            Path to the saved report
        """
        if not results:
            raise ValueError("No results to report")
        
        if report_path is None:
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(BENCHMARK_RESULTS_DIR, f"report_{timestamp_str}")
        
        # Create report directory
        os.makedirs(report_path, exist_ok=True)
        
        # Generate CSV report
        csv_path = os.path.join(report_path, "benchmark_summary.csv")
        with open(csv_path, 'w', newline='') as csvfile:
            fieldnames = ['Name', 'Avg Time (s)', 'Median Time (s)', 'Min Time (s)', 
                          'Max Time (s)', 'Std Dev (s)', 'Peak Memory (MB)', 
                          'Avg Memory Diff (MB)', 'Timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'Name': result.name,
                    'Avg Time (s)': f"{result.avg_time:.6f}",
                    'Median Time (s)': f"{result.median_time:.6f}",
                    'Min Time (s)': f"{result.min_time:.6f}",
                    'Max Time (s)': f"{result.max_time:.6f}",
                    'Std Dev (s)': f"{result.std_dev:.6f}",
                    'Peak Memory (MB)': f"{result.peak_memory / (1024 * 1024):.2f}" if result.memory_usage else "N/A",
                    'Avg Memory Diff (MB)': f"{result.avg_memory_diff / (1024 * 1024):.2f}" if result.memory_usage else "N/A",
                    'Timestamp': result.timestamp.isoformat()
                })
        
        # Generate comparison plot
        plot_path = os.path.join(report_path, "comparison_plot.png")
        BenchmarkManager.compare_results(results, save_path=plot_path)
        
        # Generate individual plots
        for result in results:
            result.plot(save_path=os.path.join(report_path, f"{result.name.replace(' ', '_')}_plot.png"))
        
        # Generate HTML report
        html_path = os.path.join(report_path, "report.html")
        with open(html_path, 'w') as f:
            f.write(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Benchmark Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1, h2 {{ color: #333; }}
                    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    .plot {{ margin: 20px 0; max-width: 100%; }}
                    .plot img {{ max-width: 100%; height: auto; }}
                    .metadata {{ margin: 10px 0; padding: 10px; background-color: #f5f5f5; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <h1>Benchmark Report</h1>
                <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                
                <h2>Summary</h2>
                <table>
                    <tr>
                        <th>Name</th>
                        <th>Avg Time (s)</th>
                        <th>Median Time (s)</th>
                        <th>Min Time (s)</th>
                        <th>Max Time (s)</th>
                        <th>Std Dev (s)</th>
                        <th>Peak Memory (MB)</th>
                        <th>Avg Memory Diff (MB)</th>
                    </tr>
                    {"".join(f'''
                    <tr>
                        <td>{result.name}</td>
                        <td>{result.avg_time:.6f}</td>
                        <td>{result.median_time:.6f}</td>
                        <td>{result.min_time:.6f}</td>
                        <td>{result.max_time:.6f}</td>
                        <td>{result.std_dev:.6f}</td>
                        <td>{f"{result.peak_memory / (1024 * 1024):.2f}" if result.memory_usage else "N/A"}</td>
                        <td>{f"{result.avg_memory_diff / (1024 * 1024):.2f}" if result.memory_usage else "N/A"}</td>
                    </tr>
                    ''' for result in results)}
                </table>
                
                <h2>Comparison</h2>
                <div class="plot">
                    <img src="comparison_plot.png" alt="Benchmark Comparison">
                </div>
                
                <h2>Individual Benchmarks</h2>
                {"".join(f'''
                <div>
                    <h3>{result.name}</h3>
                    <p>Timestamp: {result.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</p>
                    <p>Iterations: {len(result.execution_times)}</p>
                    
                    <div class="metadata">
                        <h4>Metadata</h4>
                        {"".join(f"<p><strong>{key}:</strong> {value}</p>" for key, value in result.metadata.items()) if result.metadata else "<p>No metadata available</p>"}
                    </div>
                    
                    <div class="plot">
                        <img src="{result.name.replace(' ', '_')}_plot.png" alt="{result.name} Performance">
                    </div>
                </div>
                ''' for result in results)}
            </body>
            </html>
            """)
        
        return report_path


def time_function(func: Callable, *args, **kwargs) -> Tuple[float, Any]:
    """
    Time a function execution.
    
    Args:
        func: Function to time
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function
        
    Returns:
        Tuple of (execution_time, function_result)
    """
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    return end_time - start_time, result


async def time_async_function(func: Callable, *args, **kwargs) -> Tuple[float, Any]:
    """
    Time an async function execution.
    
    Args:
        func: Async function to time
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function
        
    Returns:
        Tuple of (execution_time, function_result)
    """
    start_time = time.perf_counter()
    result = await func(*args, **kwargs)
    end_time = time.perf_counter()
    return end_time - start_time, result


def profile_memory(func: Callable, *args, **kwargs) -> Tuple[Tuple[int, int], Any]:
    """
    Profile memory usage of a function.
    
    Args:
        func: Function to profile
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function
        
    Returns:
        Tuple of ((peak_memory, memory_diff), function_result)
    """
    tracemalloc.start()
    start_memory = tracemalloc.get_traced_memory()
    
    result = func(*args, **kwargs)
    
    peak_memory, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    memory_diff = peak_memory - start_memory[0]
    return (peak_memory, memory_diff), result


async def profile_async_memory(func: Callable, *args, **kwargs) -> Tuple[Tuple[int, int], Any]:
    """
    Profile memory usage of an async function.
    
    Args:
        func: Async function to profile
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function
        
    Returns:
        Tuple of ((peak_memory, memory_diff), function_result)
    """
    tracemalloc.start()
    start_memory = tracemalloc.get_traced_memory()
    
    result = await func(*args, **kwargs)
    
    peak_memory, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    memory_diff = peak_memory - start_memory[0]
    return (peak_memory, memory_diff), result
