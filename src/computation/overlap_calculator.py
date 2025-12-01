"""
Overlap calculator for privacy-preserving set intersection.
"""

import numpy as np
from typing import List, Tuple
from ..crypto.he_engine import HEEngine
from ..data.bloom_filter import BloomFilter


class OverlapCalculator:
    """
    Calculates overlap between two encrypted Bloom filters
    using homomorphic encryption.
    """
    
    def __init__(self, he_engine: HEEngine):
        """
        Initialize overlap calculator.
        
        Args:
            he_engine: Homomorphic encryption engine
        """
        self.he_engine = he_engine
    
    def compute_encrypted_overlap(self, 
                                  bloom1_encrypted: bytes,
                                  bloom2_encrypted: bytes) -> bytes:
        """
        Compute overlap between two encrypted Bloom filters.
        Uses homomorphic multiplication (AND operation on bits).
        
        Args:
            bloom1_encrypted: First encrypted Bloom filter
            bloom2_encrypted: Second encrypted Bloom filter
            
        Returns:
            Encrypted result of intersection
        """
        # Perform homomorphic multiplication (element-wise AND)
        intersection = self.he_engine.multiply_encrypted(
            bloom1_encrypted, 
            bloom2_encrypted
        )
        
        return intersection
    
    def count_overlap_bits(self, intersection_encrypted: bytes) -> int:
        """
        Count the number of set bits in encrypted intersection.
        This requires decryption.
        
        Args:
            intersection_encrypted: Encrypted intersection result
            
        Returns:
            Number of overlapping bits
        """
        # Decrypt the intersection
        intersection_bits = self.he_engine.decrypt(intersection_encrypted)
        
        # Count set bits
        return sum(intersection_bits)
    
    def calculate_jaccard_similarity(self, 
                                     overlap_bits: int,
                                     bloom1_bits: int,
                                     bloom2_bits: int) -> float:
        """
        Calculate Jaccard similarity from bit counts.
        
        Jaccard similarity = |A ∩ B| / |A ∪ B|
        For Bloom filters: intersection_bits / (bloom1_bits + bloom2_bits - intersection_bits)
        
        Args:
            overlap_bits: Number of bits set in intersection
            bloom1_bits: Number of bits set in first Bloom filter
            bloom2_bits: Number of bits set in second Bloom filter
            
        Returns:
            Jaccard similarity coefficient (0.0 to 1.0)
        """
        # Union size = size1 + size2 - intersection
        union_bits = bloom1_bits + bloom2_bits - overlap_bits
        
        if union_bits == 0:
            return 0.0
        
        return overlap_bits / union_bits
    
    def estimate_set_overlap(self,
                            overlap_bits: int,
                            bloom1_bits: int,
                            bloom2_bits: int,
                            bloom_size: int,
                            hash_count: int) -> int:
        """
        Estimate the actual number of overlapping items from Bloom filter statistics.
        
        Uses the formula derived from Bloom filter theory to estimate
        the number of items that caused the observed bit overlap.
        
        Args:
            overlap_bits: Number of bits set in intersection
            bloom1_bits: Number of bits set in first Bloom filter
            bloom2_bits: Number of bits set in second Bloom filter
            bloom_size: Size of Bloom filter
            hash_count: Number of hash functions
            
        Returns:
            Estimated number of overlapping items
        """
        # Estimate number of items in each Bloom filter
        # Formula: n ≈ -(m/k) * ln(1 - X/m)
        # where m = bloom_size, k = hash_count, X = number of set bits
        
        def estimate_items(set_bits: int) -> float:
            if set_bits == 0:
                return 0
            ratio = set_bits / bloom_size
            if ratio >= 1.0:
                ratio = 0.999  # Avoid log(0)
            return -(bloom_size / hash_count) * np.log(1 - ratio)
        
        n1 = estimate_items(bloom1_bits)
        n2 = estimate_items(bloom2_bits)
        
        # Improved estimation using Inclusion-Exclusion Principle
        # |A ∩ B| = |A| + |B| - |A ∪ B|
        # We estimate |A ∪ B| from the union of bits (OR operation)
        # bits(A ∪ B) = bits(A) + bits(B) - bits(A ∩ B)
        
        union_bits = bloom1_bits + bloom2_bits - overlap_bits
        n_union = estimate_items(union_bits)
        
        estimated_overlap = n1 + n2 - n_union
        
        return int(max(0, estimated_overlap))
    
    def compute_overlap_statistics(self,
                                   bloom1: BloomFilter,
                                   bloom2: BloomFilter,
                                   bloom1_encrypted: bytes,
                                   bloom2_encrypted: bytes) -> dict:
        """
        Compute comprehensive overlap statistics.
        
        Args:
            bloom1: First Bloom filter (for metadata)
            bloom2: Second Bloom filter (for metadata)
            bloom1_encrypted: Encrypted first Bloom filter
            bloom2_encrypted: Encrypted second Bloom filter
            
        Returns:
            Dictionary with overlap statistics
        """
        # Compute encrypted intersection
        intersection_encrypted = self.compute_encrypted_overlap(
            bloom1_encrypted,
            bloom2_encrypted
        )
        
        # Count bits
        overlap_bits = self.count_overlap_bits(intersection_encrypted)
        bloom1_bits = bloom1.count_set_bits()
        bloom2_bits = bloom2.count_set_bits()
        
        # Calculate Jaccard similarity
        jaccard = self.calculate_jaccard_similarity(
            overlap_bits,
            bloom1_bits,
            bloom2_bits
        )
        
        # Estimate actual item overlap
        estimated_overlap = self.estimate_set_overlap(
            overlap_bits,
            bloom1_bits,
            bloom2_bits,
            bloom1.size,
            bloom1.hash_count
        )
        
        return {
            'overlap_bits': overlap_bits,
            'bloom1_bits': bloom1_bits,
            'bloom2_bits': bloom2_bits,
            'jaccard_similarity': jaccard,
            'estimated_item_overlap': estimated_overlap,
            'bloom1_items': bloom1.item_count,
            'bloom2_items': bloom2.item_count,
            'bloom_size': bloom1.size,
            'hash_count': bloom1.hash_count
        }
