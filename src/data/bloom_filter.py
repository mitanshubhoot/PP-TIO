"""
Bloom Filter implementation for efficient set representation.
"""

import hashlib
import numpy as np
from typing import List, Set, Any


class BloomFilter:
    """
    Bloom filter for probabilistic set membership testing.
    Used to encode IoC lists efficiently before encryption.
    """
    
    def __init__(self, size: int = 10000, hash_count: int = 5):
        """
        Initialize Bloom filter.
        
        Args:
            size: Size of the bit array
            hash_count: Number of hash functions to use
        """
        self.size = size
        self.hash_count = hash_count
        self.bit_array = np.zeros(size, dtype=int)
        self.item_count = 0
        
    def _hash(self, item: str, seed: int) -> int:
        """
        Hash function using SHA256 with seed.
        
        Args:
            item: Item to hash
            seed: Seed for hash function
            
        Returns:
            Hash value modulo size
        """
        hash_input = f"{item}{seed}".encode('utf-8')
        hash_digest = hashlib.sha256(hash_input).hexdigest()
        return int(hash_digest, 16) % self.size
    
    def add(self, item: str):
        """
        Add an item to the Bloom filter.
        
        Args:
            item: Item to add (will be converted to string)
        """
        item_str = str(item)
        for i in range(self.hash_count):
            index = self._hash(item_str, i)
            self.bit_array[index] = 1
        self.item_count += 1
    
    def add_multiple(self, items: List[str]):
        """
        Add multiple items to the Bloom filter.
        
        Args:
            items: List of items to add
        """
        for item in items:
            self.add(item)
    
    def contains(self, item: str) -> bool:
        """
        Check if an item might be in the set.
        
        Args:
            item: Item to check
            
        Returns:
            True if item might be in set (with possible false positives),
            False if item is definitely not in set
        """
        item_str = str(item)
        for i in range(self.hash_count):
            index = self._hash(item_str, i)
            if self.bit_array[index] == 0:
                return False
        return True
    
    def get_bit_array(self) -> List[int]:
        """
        Get the bit array for encryption.
        
        Returns:
            List of integers (0 or 1) representing the bit array
        """
        return self.bit_array.tolist()
    
    def set_bit_array(self, bit_array: List[int]):
        """
        Set the bit array from a list.
        
        Args:
            bit_array: List of integers to set as bit array
        """
        if len(bit_array) != self.size:
            raise ValueError(f"Bit array size mismatch: expected {self.size}, got {len(bit_array)}")
        self.bit_array = np.array(bit_array, dtype=int)
    
    @classmethod
    def from_bit_array(cls, bit_array: List[int], hash_count: int = 5):
        """
        Create a Bloom filter from a bit array.
        
        Args:
            bit_array: Bit array to use
            hash_count: Number of hash functions
            
        Returns:
            BloomFilter instance
        """
        bf = cls(size=len(bit_array), hash_count=hash_count)
        bf.set_bit_array(bit_array)
        return bf
    
    def count_set_bits(self) -> int:
        """
        Count the number of set bits in the filter.
        
        Returns:
            Number of bits set to 1
        """
        return int(np.sum(self.bit_array))
    
    def estimate_false_positive_rate(self) -> float:
        """
        Estimate the false positive rate based on current state.
        
        Formula: (1 - e^(-k*n/m))^k
        where k = hash_count, n = item_count, m = size
        
        Returns:
            Estimated false positive probability
        """
        if self.item_count == 0:
            return 0.0
        
        k = self.hash_count
        n = self.item_count
        m = self.size
        
        # Calculate false positive rate
        exponent = -k * n / m
        fpr = (1 - np.exp(exponent)) ** k
        return float(fpr)
    
    def intersect(self, other: 'BloomFilter') -> 'BloomFilter':
        """
        Compute intersection with another Bloom filter (AND operation).
        
        Args:
            other: Another Bloom filter
            
        Returns:
            New Bloom filter representing intersection
        """
        if self.size != other.size or self.hash_count != other.hash_count:
            raise ValueError("Bloom filters must have same size and hash count")
        
        result = BloomFilter(size=self.size, hash_count=self.hash_count)
        result.bit_array = np.logical_and(self.bit_array, other.bit_array).astype(int)
        return result
    
    def union(self, other: 'BloomFilter') -> 'BloomFilter':
        """
        Compute union with another Bloom filter (OR operation).
        
        Args:
            other: Another Bloom filter
            
        Returns:
            New Bloom filter representing union
        """
        if self.size != other.size or self.hash_count != other.hash_count:
            raise ValueError("Bloom filters must have same size and hash count")
        
        result = BloomFilter(size=self.size, hash_count=self.hash_count)
        result.bit_array = np.logical_or(self.bit_array, other.bit_array).astype(int)
        return result
    
    def __len__(self) -> int:
        """Return the number of items added (with duplicates)."""
        return self.item_count
    
    def __repr__(self) -> str:
        """String representation of Bloom filter."""
        return (f"BloomFilter(size={self.size}, hash_count={self.hash_count}, "
                f"items={self.item_count}, set_bits={self.count_set_bits()}, "
                f"fpr={self.estimate_false_positive_rate():.4f})")
