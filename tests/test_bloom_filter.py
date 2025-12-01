"""
Unit tests for Bloom filter implementation.
"""

import pytest
from src.data.bloom_filter import BloomFilter


def test_bloom_filter_creation():
    """Test Bloom filter initialization."""
    bf = BloomFilter(size=1000, hash_count=3)
    assert bf.size == 1000
    assert bf.hash_count == 3
    assert bf.item_count == 0
    assert bf.count_set_bits() == 0


def test_add_and_contains():
    """Test adding items and checking membership."""
    bf = BloomFilter(size=1000, hash_count=3)
    
    # Add items
    bf.add("192.168.1.1")
    bf.add("example.com")
    bf.add("malware.exe")
    
    # Check membership
    assert bf.contains("192.168.1.1")
    assert bf.contains("example.com")
    assert bf.contains("malware.exe")
    
    # Item count should be 3
    assert bf.item_count == 3


def test_add_multiple():
    """Test adding multiple items at once."""
    bf = BloomFilter(size=1000, hash_count=3)
    
    items = ["item1", "item2", "item3", "item4", "item5"]
    bf.add_multiple(items)
    
    assert bf.item_count == 5
    for item in items:
        assert bf.contains(item)


def test_false_positives():
    """Test that items not added are likely not in the filter."""
    bf = BloomFilter(size=10000, hash_count=5)
    
    # Add some items
    added_items = [f"item{i}" for i in range(100)]
    bf.add_multiple(added_items)
    
    # Check items that were not added
    # Some may be false positives, but most should not be
    not_added = [f"notadded{i}" for i in range(100)]
    false_positives = sum(1 for item in not_added if bf.contains(item))
    
    # False positive rate should be low (< 10% for this configuration)
    assert false_positives < 10


def test_bit_array_operations():
    """Test getting and setting bit arrays."""
    bf = BloomFilter(size=100, hash_count=3)
    
    bf.add("test1")
    bf.add("test2")
    
    # Get bit array
    bit_array = bf.get_bit_array()
    assert len(bit_array) == 100
    assert all(bit in [0, 1] for bit in bit_array)
    
    # Create new filter from bit array
    bf2 = BloomFilter.from_bit_array(bit_array, hash_count=3)
    assert bf2.contains("test1")
    assert bf2.contains("test2")


def test_intersection():
    """Test Bloom filter intersection."""
    bf1 = BloomFilter(size=1000, hash_count=3)
    bf2 = BloomFilter(size=1000, hash_count=3)
    
    # Add overlapping items
    bf1.add_multiple(["item1", "item2", "item3"])
    bf2.add_multiple(["item2", "item3", "item4"])
    
    # Compute intersection
    intersection = bf1.intersect(bf2)
    
    # Intersection should contain overlapping items
    assert intersection.contains("item2")
    assert intersection.contains("item3")


def test_union():
    """Test Bloom filter union."""
    bf1 = BloomFilter(size=1000, hash_count=3)
    bf2 = BloomFilter(size=1000, hash_count=3)
    
    bf1.add_multiple(["item1", "item2"])
    bf2.add_multiple(["item3", "item4"])
    
    # Compute union
    union = bf1.union(bf2)
    
    # Union should contain all items
    assert union.contains("item1")
    assert union.contains("item2")
    assert union.contains("item3")
    assert union.contains("item4")


def test_count_set_bits():
    """Test counting set bits."""
    bf = BloomFilter(size=1000, hash_count=3)
    
    initial_bits = bf.count_set_bits()
    assert initial_bits == 0
    
    bf.add("test")
    after_add = bf.count_set_bits()
    assert after_add > 0
    assert after_add <= 3  # At most hash_count bits set per item


def test_false_positive_rate_estimation():
    """Test false positive rate estimation."""
    bf = BloomFilter(size=10000, hash_count=5)
    
    # Initially should be 0
    assert bf.estimate_false_positive_rate() == 0.0
    
    # Add items
    for i in range(100):
        bf.add(f"item{i}")
    
    # FPR should be > 0 but small
    fpr = bf.estimate_false_positive_rate()
    assert 0 < fpr < 0.1


def test_repr():
    """Test string representation."""
    bf = BloomFilter(size=1000, hash_count=3)
    bf.add("test")
    
    repr_str = repr(bf)
    assert "BloomFilter" in repr_str
    assert "size=1000" in repr_str
    assert "hash_count=3" in repr_str
