"""
Integration tests for the two-party protocol.
"""

import pytest
from src.data.dataset_loader import DatasetLoader
from src.computation.protocol import run_simulation, TwoPartyProtocol


def test_protocol_with_known_overlap():
    """Test protocol with datasets of known overlap."""
    # Create datasets with 50% overlap
    dataset1, dataset2 = DatasetLoader.create_test_datasets(
        size1=100,
        size2=100,
        overlap_percentage=50,
        ioc_type='ip'
    )
    
    # Run simulation
    results = run_simulation(dataset1, dataset2, verify=True)
    
    # Check results structure
    assert 'overlap_statistics' in results
    assert 'party1_info' in results
    assert 'party2_info' in results
    assert 'privacy_preserved' in results
    assert results['privacy_preserved'] is True
    assert results['raw_iocs_exposed'] is False
    
    # Check verification
    assert 'verification' in results
    assert 'accuracy' in results
    
    # Actual overlap should be 50 items
    actual_overlap = results['verification']['actual_overlap']
    assert actual_overlap == 50
    
    # Estimated overlap should be close to actual
    estimated_overlap = results['overlap_statistics']['estimated_item_overlap']
    error_percentage = results['accuracy']['error_percentage']
    
    # Allow up to 20% error due to Bloom filter approximation
    assert error_percentage < 20


def test_protocol_with_no_overlap():
    """Test protocol with no overlap."""
    dataset1, dataset2 = DatasetLoader.create_test_datasets(
        size1=50,
        size2=50,
        overlap_percentage=0,
        ioc_type='domain'
    )
    
    results = run_simulation(dataset1, dataset2, verify=True)
    
    # Should detect no overlap
    actual_overlap = results['verification']['actual_overlap']
    assert actual_overlap == 0
    
    estimated_overlap = results['overlap_statistics']['estimated_item_overlap']
    # Estimated should be very low (may not be exactly 0 due to false positives)
    assert estimated_overlap < 5


def test_protocol_with_complete_overlap():
    """Test protocol with 100% overlap."""
    dataset1, dataset2 = DatasetLoader.create_test_datasets(
        size1=50,
        size2=50,
        overlap_percentage=100,
        ioc_type='hash'
    )
    
    results = run_simulation(dataset1, dataset2, verify=True)
    
    # Should detect complete overlap
    actual_overlap = results['verification']['actual_overlap']
    assert actual_overlap == 50
    
    # Jaccard similarity should be close to 1.0
    jaccard = results['overlap_statistics']['jaccard_similarity']
    assert jaccard > 0.8


def test_protocol_with_different_sizes():
    """Test protocol with different dataset sizes."""
    dataset1, dataset2 = DatasetLoader.create_test_datasets(
        size1=100,
        size2=50,
        overlap_percentage=50,
        ioc_type='url'
    )
    
    results = run_simulation(dataset1, dataset2, verify=True)
    
    # Check party info
    assert results['party1_info']['ioc_count'] == 100
    assert results['party2_info']['ioc_count'] == 50
    
    # Overlap should be 50% of smaller set = 25 items
    actual_overlap = results['verification']['actual_overlap']
    assert actual_overlap == 25


def test_jaccard_similarity_calculation():
    """Test Jaccard similarity calculation."""
    # Create datasets with known overlap
    dataset1, dataset2 = DatasetLoader.create_test_datasets(
        size1=100,
        size2=100,
        overlap_percentage=50,
        ioc_type='ip'
    )
    
    results = run_simulation(dataset1, dataset2, verify=True)
    
    # Calculate expected Jaccard
    # 100 + 100 - 50 = 150 union, 50 intersection
    # Jaccard = 50 / 150 = 0.333
    expected_jaccard = 50 / 150
    
    actual_jaccard = results['verification']['actual_jaccard_similarity']
    assert abs(actual_jaccard - expected_jaccard) < 0.01


def test_protocol_privacy_guarantees():
    """Test that protocol preserves privacy."""
    dataset1, dataset2 = DatasetLoader.create_test_datasets(
        size1=50,
        size2=50,
        overlap_percentage=50,
        ioc_type='ip'
    )
    
    results = run_simulation(dataset1, dataset2, verify=False)
    
    # Ensure no raw IoCs in results
    results_str = str(results)
    
    # Check that individual IoCs are not in results
    for ioc in dataset1[:10]:  # Check first 10
        assert str(ioc) not in results_str
    
    for ioc in dataset2[:10]:
        assert str(ioc) not in results_str


def test_two_party_protocol_setup():
    """Test TwoPartyProtocol setup."""
    protocol = TwoPartyProtocol(bloom_size=1000, hash_count=3)
    
    dataset1 = DatasetLoader.load_synthetic_dataset(50, 'ip')
    dataset2 = DatasetLoader.load_synthetic_dataset(50, 'ip')
    
    protocol.setup_parties("Party-A", "Party-B", dataset1, dataset2)
    
    assert protocol.party1 is not None
    assert protocol.party2 is not None
    assert protocol.party1.name == "Party-A"
    assert protocol.party2.name == "Party-B"
    assert len(protocol.party1.ioc_list) == 50
    assert len(protocol.party2.ioc_list) == 50


def test_protocol_execution_without_setup():
    """Test that protocol fails without setup."""
    protocol = TwoPartyProtocol()
    
    with pytest.raises(ValueError):
        protocol.execute_protocol()
