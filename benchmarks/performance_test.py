"""
Performance benchmarking for PP-TIO system.
"""

import time
import json
import matplotlib.pyplot as plt
from pathlib import Path
from typing import List, Dict

from src.data.dataset_loader import DatasetLoader
from src.computation.protocol import run_simulation


class PerformanceBenchmark:
    """Performance benchmarking utility."""
    
    def __init__(self):
        self.results = []
    
    def benchmark_dataset_sizes(self, 
                               sizes: List[int],
                               overlap_percentage: int = 50,
                               bloom_size: int = 10000,
                               hash_count: int = 5) -> Dict:
        """
        Benchmark performance across different dataset sizes.
        
        Args:
            sizes: List of dataset sizes to test
            overlap_percentage: Overlap percentage
            bloom_size: Bloom filter size
            hash_count: Number of hash functions
            
        Returns:
            Dictionary with benchmark results
        """
        print("Benchmarking dataset sizes...")
        print("=" * 60)
        
        results = []
        
        for size in sizes:
            print(f"\nTesting dataset size: {size}")
            
            # Generate datasets
            dataset1, dataset2 = DatasetLoader.create_test_datasets(
                size, size, overlap_percentage, 'ip'
            )
            
            # Measure time
            start_time = time.time()
            
            simulation_results = run_simulation(
                dataset1, dataset2,
                bloom_size=bloom_size,
                hash_count=hash_count,
                verify=True
            )
            
            elapsed_time = time.time() - start_time
            
            # Store results
            result = {
                'dataset_size': size,
                'execution_time': elapsed_time,
                'estimated_overlap': simulation_results['overlap_statistics']['estimated_item_overlap'],
                'actual_overlap': simulation_results['verification']['actual_overlap'],
                'jaccard_similarity': simulation_results['overlap_statistics']['jaccard_similarity'],
                'error_percentage': simulation_results['accuracy']['error_percentage']
            }
            
            results.append(result)
            
            print(f"  Time: {elapsed_time:.2f}s")
            print(f"  Estimated overlap: {result['estimated_overlap']}")
            print(f"  Actual overlap: {result['actual_overlap']}")
            print(f"  Error: {result['error_percentage']:.2f}%")
        
        self.results = results
        return {'benchmark_type': 'dataset_sizes', 'results': results}
    
    def benchmark_bloom_sizes(self,
                             bloom_sizes: List[int],
                             dataset_size: int = 1000,
                             overlap_percentage: int = 50,
                             hash_count: int = 5) -> Dict:
        """
        Benchmark performance across different Bloom filter sizes.
        
        Args:
            bloom_sizes: List of Bloom filter sizes to test
            dataset_size: Size of datasets
            overlap_percentage: Overlap percentage
            hash_count: Number of hash functions
            
        Returns:
            Dictionary with benchmark results
        """
        print("Benchmarking Bloom filter sizes...")
        print("=" * 60)
        
        results = []
        
        # Generate datasets once
        dataset1, dataset2 = DatasetLoader.create_test_datasets(
            dataset_size, dataset_size, overlap_percentage, 'ip'
        )
        
        for bloom_size in bloom_sizes:
            print(f"\nTesting Bloom size: {bloom_size}")
            
            # Measure time
            start_time = time.time()
            
            simulation_results = run_simulation(
                dataset1, dataset2,
                bloom_size=bloom_size,
                hash_count=hash_count,
                verify=True
            )
            
            elapsed_time = time.time() - start_time
            
            # Store results
            result = {
                'bloom_size': bloom_size,
                'execution_time': elapsed_time,
                'error_percentage': simulation_results['accuracy']['error_percentage']
            }
            
            results.append(result)
            
            print(f"  Time: {elapsed_time:.2f}s")
            print(f"  Error: {result['error_percentage']:.2f}%")
        
        return {'benchmark_type': 'bloom_sizes', 'results': results}
    
    def plot_results(self, output_dir: str = "benchmarks/results"):
        """
        Plot benchmark results.
        
        Args:
            output_dir: Directory to save plots
        """
        if not self.results:
            print("No results to plot")
            return
        
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Extract data
        sizes = [r['dataset_size'] for r in self.results]
        times = [r['execution_time'] for r in self.results]
        errors = [r['error_percentage'] for r in self.results]
        
        # Plot execution time
        plt.figure(figsize=(10, 6))
        plt.plot(sizes, times, marker='o', linewidth=2, markersize=8)
        plt.xlabel('Dataset Size', fontsize=12)
        plt.ylabel('Execution Time (seconds)', fontsize=12)
        plt.title('PP-TIO Performance: Execution Time vs Dataset Size', fontsize=14)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"{output_dir}/execution_time.png", dpi=300)
        print(f"Saved plot: {output_dir}/execution_time.png")
        
        # Plot error percentage
        plt.figure(figsize=(10, 6))
        plt.plot(sizes, errors, marker='s', linewidth=2, markersize=8, color='red')
        plt.xlabel('Dataset Size', fontsize=12)
        plt.ylabel('Error Percentage (%)', fontsize=12)
        plt.title('PP-TIO Accuracy: Error vs Dataset Size', fontsize=14)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"{output_dir}/error_percentage.png", dpi=300)
        print(f"Saved plot: {output_dir}/error_percentage.png")
    
    def save_results(self, filepath: str):
        """
        Save results to JSON file.
        
        Args:
            filepath: Path to save results
        """
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"Results saved to: {filepath}")


def main():
    """Run benchmarks."""
    benchmark = PerformanceBenchmark()
    
    # Benchmark different dataset sizes
    sizes = [100, 500, 1000, 2000, 5000]
    results = benchmark.benchmark_dataset_sizes(sizes)
    
    # Save results
    Path("benchmarks/results").mkdir(parents=True, exist_ok=True)
    benchmark.save_results("benchmarks/results/benchmark_results.json")
    
    # Plot results
    try:
        benchmark.plot_results()
    except Exception as e:
        print(f"Could not generate plots: {e}")
    
    print("\n" + "=" * 60)
    print("Benchmark complete!")


if __name__ == '__main__':
    main()
