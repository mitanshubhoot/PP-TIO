"""
Command-line interface for PP-TIO system.
"""

import click
import json
import yaml
import time
from pathlib import Path
from typing import Optional

from ..crypto.he_engine import HEEngine
from ..crypto.key_manager import KeyManager
from ..data.dataset_loader import DatasetLoader
from ..computation.protocol import run_simulation


@click.group()
def cli():
    """Privacy-Preserving Threat Intelligence Overlap (PP-TIO) CLI."""
    pass


@cli.command()
@click.option('--output', '-o', default='keys/', help='Output directory for keys')
@click.option('--poly-modulus-degree', default=8192, help='Polynomial modulus degree')
@click.option('--plain-modulus', default=1032193, help='Plaintext modulus')
def generate_keys(output: str, poly_modulus_degree: int, plain_modulus: int):
    """Generate homomorphic encryption keys."""
    click.echo("Generating homomorphic encryption keys...")
    
    # Create HE engine
    he_engine = HEEngine(
        poly_modulus_degree=poly_modulus_degree,
        plain_modulus=plain_modulus
    )
    
    # Generate keys
    public_key, private_key = he_engine.generate_keys()
    
    # Save keys
    key_manager = KeyManager(output)
    public_path, private_path = key_manager.save_keys(public_key, private_key)
    
    click.echo(f"✓ Public key saved to: {public_path}")
    click.echo(f"✓ Private key saved to: {private_path}")
    click.echo(f"\nKey parameters:")
    click.echo(f"  Polynomial modulus degree: {poly_modulus_degree}")
    click.echo(f"  Plaintext modulus: {plain_modulus}")


@cli.command()
@click.option('--dataset1-size', default=1000, help='Size of first dataset')
@click.option('--dataset2-size', default=1000, help='Size of second dataset')
@click.option('--overlap-percentage', default=50, help='Overlap percentage (0-100)')
@click.option('--ioc-type', default='ip', 
              type=click.Choice(['ip', 'domain', 'url', 'hash', 'mixed']),
              help='Type of IoCs to generate')
@click.option('--bloom-size', default=10000, help='Bloom filter size')
@click.option('--hash-count', default=5, help='Number of hash functions')
@click.option('--output', '-o', help='Output file for results (JSON)')
@click.option('--verify/--no-verify', default=True, help='Verify with plaintext computation')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def simulate(dataset1_size: int, dataset2_size: int, overlap_percentage: int,
            ioc_type: str, bloom_size: int, hash_count: int,
            output: Optional[str], verify: bool, verbose: bool):
    """Run two-party overlap simulation."""
    
    click.echo("=" * 60)
    click.echo("Privacy-Preserving Threat Intelligence Overlap Simulation")
    click.echo("=" * 60)
    
    # Generate datasets
    click.echo(f"\n[1/4] Generating datasets...")
    click.echo(f"  Dataset 1: {dataset1_size} IoCs")
    click.echo(f"  Dataset 2: {dataset2_size} IoCs")
    click.echo(f"  Overlap: {overlap_percentage}%")
    click.echo(f"  IoC type: {ioc_type}")
    
    dataset1, dataset2 = DatasetLoader.create_test_datasets(
        dataset1_size, dataset2_size, overlap_percentage, ioc_type
    )
    
    if verbose:
        click.echo(f"  ✓ Generated {len(dataset1)} IoCs for Dataset 1")
        click.echo(f"  ✓ Generated {len(dataset2)} IoCs for Dataset 2")
    
    # Setup protocol
    click.echo(f"\n[2/4] Setting up encryption...")
    click.echo(f"  Bloom filter size: {bloom_size}")
    click.echo(f"  Hash functions: {hash_count}")
    
    start_time = time.time()
    
    # Run simulation
    click.echo(f"\n[3/4] Executing privacy-preserving protocol...")
    results = run_simulation(
        dataset1, dataset2,
        bloom_size=bloom_size,
        hash_count=hash_count,
        verify=verify
    )
    
    elapsed_time = time.time() - start_time
    
    # Display results
    click.echo(f"\n[4/4] Results:")
    click.echo("=" * 60)
    
    overlap_stats = results['overlap_statistics']
    click.echo(f"\n📊 Overlap Statistics:")
    click.echo(f"  Estimated item overlap: {overlap_stats['estimated_item_overlap']}")
    click.echo(f"  Jaccard similarity: {overlap_stats['jaccard_similarity']:.4f}")
    click.echo(f"  Overlapping bits: {overlap_stats['overlap_bits']}")
    
    party1 = results['party1_info']
    party2 = results['party2_info']
    click.echo(f"\n🏢 Party Information:")
    click.echo(f"  {party1['name']}: {party1['ioc_count']} IoCs, {party1['bloom_set_bits']} bits set")
    click.echo(f"  {party2['name']}: {party2['ioc_count']} IoCs, {party2['bloom_set_bits']} bits set")
    
    if verify and 'accuracy' in results:
        accuracy = results['accuracy']
        click.echo(f"\n✓ Verification (Plaintext Comparison):")
        click.echo(f"  Actual overlap: {accuracy['actual_overlap']}")
        click.echo(f"  Estimated overlap: {accuracy['estimated_overlap']}")
        click.echo(f"  Error: {accuracy['error']} items ({accuracy['error_percentage']:.2f}%)")
    
    click.echo(f"\n🔒 Privacy:")
    click.echo(f"  Privacy preserved: {results['privacy_preserved']}")
    click.echo(f"  Raw IoCs exposed: {results['raw_iocs_exposed']}")
    
    click.echo(f"\n⏱️  Performance:")
    click.echo(f"  Total time: {elapsed_time:.2f} seconds")
    
    # Save results
    if output:
        results['execution_time_seconds'] = elapsed_time
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\n💾 Results saved to: {output}")
    
    click.echo("\n" + "=" * 60)


@cli.command()
@click.option('--config', '-c', default='config/default.yaml', help='Configuration file')
def info(config: str):
    """Display system information and configuration."""
    click.echo("PP-TIO System Information")
    click.echo("=" * 60)
    
    # Load config
    if Path(config).exists():
        with open(config, 'r') as f:
            cfg = yaml.safe_load(f)
        
        click.echo("\n📋 Configuration:")
        click.echo(f"  Bloom filter size: {cfg['bloom_filter']['size']}")
        click.echo(f"  Hash functions: {cfg['bloom_filter']['hash_count']}")
        click.echo(f"  Polynomial modulus degree: {cfg['encryption']['poly_modulus_degree']}")
        click.echo(f"  Plaintext modulus: {cfg['encryption']['plain_modulus']}")
    else:
        click.echo(f"\n⚠️  Configuration file not found: {config}")
    
    # Check for keys
    key_manager = KeyManager()
    if key_manager.keys_exist():
        click.echo("\n🔑 Keys: Found")
    else:
        click.echo("\n🔑 Keys: Not found (run 'generate-keys' command)")


@cli.command()
@click.argument('file1', type=click.Path(exists=True))
@click.argument('file2', type=click.Path(exists=True))
@click.option('--ioc-type', help='Type of IoCs in files')
@click.option('--bloom-size', default=10000, help='Bloom filter size')
@click.option('--hash-count', default=5, help='Number of hash functions')
@click.option('--output', '-o', help='Output file for results (JSON)')
def compare_files(file1: str, file2: str, ioc_type: Optional[str],
                 bloom_size: int, hash_count: int, output: Optional[str]):
    """Compare two IoC files for overlap."""
    
    click.echo("Loading IoC files...")
    
    # Load datasets from files
    dataset1 = DatasetLoader.load_from_file(file1, ioc_type)
    dataset2 = DatasetLoader.load_from_file(file2, ioc_type)
    
    click.echo(f"  File 1: {len(dataset1)} IoCs")
    click.echo(f"  File 2: {len(dataset2)} IoCs")
    
    # Run simulation
    click.echo("\nExecuting protocol...")
    results = run_simulation(
        dataset1, dataset2,
        bloom_size=bloom_size,
        hash_count=hash_count,
        verify=True
    )
    
    # Display results
    overlap_stats = results['overlap_statistics']
    click.echo(f"\nEstimated overlap: {overlap_stats['estimated_item_overlap']} IoCs")
    click.echo(f"Jaccard similarity: {overlap_stats['jaccard_similarity']:.4f}")
    
    if 'accuracy' in results:
        click.echo(f"Actual overlap: {results['accuracy']['actual_overlap']} IoCs")
    
    # Save results
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\nResults saved to: {output}")


if __name__ == '__main__':
    cli()
