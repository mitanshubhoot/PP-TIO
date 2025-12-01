"""
Two-party protocol for privacy-preserving threat intelligence sharing.
"""

from typing import List, Dict, Tuple
from ..crypto.he_engine import HEEngine
from ..crypto.key_manager import KeyManager
from ..data.bloom_filter import BloomFilter
from ..data.ioc_models import IoC
from .overlap_calculator import OverlapCalculator


class Party:
    """
    Represents one party (e.g., an ISP) in the protocol.
    """
    
    def __init__(self, name: str, he_engine: HEEngine):
        """
        Initialize a party.
        
        Args:
            name: Party identifier
            he_engine: Homomorphic encryption engine
        """
        self.name = name
        self.he_engine = he_engine
        self.ioc_list: List[IoC] = []
        self.bloom_filter: BloomFilter = None
        self.encrypted_bloom: bytes = None
        
    def set_ioc_list(self, iocs: List[IoC]):
        """
        Set the party's IoC list.
        
        Args:
            iocs: List of IoC objects
        """
        self.ioc_list = iocs
    
    def create_bloom_filter(self, size: int = 10000, hash_count: int = 5):
        """
        Create a Bloom filter from the IoC list.
        
        Args:
            size: Bloom filter size
            hash_count: Number of hash functions
        """
        self.bloom_filter = BloomFilter(size=size, hash_count=hash_count)
        
        # Add all IoCs to the Bloom filter
        for ioc in self.ioc_list:
            self.bloom_filter.add(str(ioc))
    
    def encrypt_bloom_filter(self) -> bytes:
        """
        Encrypt the Bloom filter.
        
        Returns:
            Encrypted Bloom filter
        """
        if self.bloom_filter is None:
            raise ValueError("Bloom filter not created. Call create_bloom_filter first.")
        
        # Get bit array and encrypt
        bit_array = self.bloom_filter.get_bit_array()
        self.encrypted_bloom = self.he_engine.encrypt(bit_array)
        
        return self.encrypted_bloom
    
    def get_bloom_stats(self) -> dict:
        """
        Get statistics about the Bloom filter.
        
        Returns:
            Dictionary with Bloom filter statistics
        """
        if self.bloom_filter is None:
            return {"status": "not_created"}
        
        return {
            "party_name": self.name,
            "ioc_count": len(self.ioc_list),
            "bloom_size": self.bloom_filter.size,
            "hash_count": self.bloom_filter.hash_count,
            "set_bits": self.bloom_filter.count_set_bits(),
            "false_positive_rate": self.bloom_filter.estimate_false_positive_rate()
        }


class TwoPartyProtocol:
    """
    Implements the two-party privacy-preserving overlap protocol.
    """
    
    def __init__(self, bloom_size: int = 10000, hash_count: int = 5):
        """
        Initialize the protocol.
        
        Args:
            bloom_size: Size of Bloom filters
            hash_count: Number of hash functions
        """
        self.bloom_size = bloom_size
        self.hash_count = hash_count
        self.he_engine = HEEngine()
        self.party1: Party = None
        self.party2: Party = None
        
    def setup_parties(self, party1_name: str, party2_name: str,
                     party1_iocs: List[IoC], party2_iocs: List[IoC]):
        """
        Set up both parties with their IoC lists.
        
        Args:
            party1_name: Name of first party
            party2_name: Name of second party
            party1_iocs: IoC list for party 1
            party2_iocs: IoC list for party 2
        """
        # Generate keys
        public_key, private_key = self.he_engine.generate_keys()
        
        # Create parties
        self.party1 = Party(party1_name, self.he_engine)
        self.party2 = Party(party2_name, self.he_engine)
        
        # Set IoC lists
        self.party1.set_ioc_list(party1_iocs)
        self.party2.set_ioc_list(party2_iocs)
        
        # Create Bloom filters
        self.party1.create_bloom_filter(self.bloom_size, self.hash_count)
        self.party2.create_bloom_filter(self.bloom_size, self.hash_count)
    
    def execute_protocol(self) -> Dict:
        """
        Execute the privacy-preserving overlap protocol.
        
        Returns:
            Dictionary with results (only aggregate statistics)
        """
        if self.party1 is None or self.party2 is None:
            raise ValueError("Parties not set up. Call setup_parties first.")
        
        # Step 1: Each party encrypts their Bloom filter
        encrypted1 = self.party1.encrypt_bloom_filter()
        encrypted2 = self.party2.encrypt_bloom_filter()
        
        # Step 2: Compute overlap using homomorphic operations
        calculator = OverlapCalculator(self.he_engine)
        
        stats = calculator.compute_overlap_statistics(
            self.party1.bloom_filter,
            self.party2.bloom_filter,
            encrypted1,
            encrypted2
        )
        
        # Step 3: Add party information
        stats['party1'] = self.party1.get_bloom_stats()
        stats['party2'] = self.party2.get_bloom_stats()
        
        # Step 4: Ensure privacy - only return aggregate statistics
        result = {
            'overlap_statistics': {
                'estimated_item_overlap': stats['estimated_item_overlap'],
                'jaccard_similarity': stats['jaccard_similarity'],
                'overlap_bits': stats['overlap_bits']
            },
            'party1_info': {
                'name': stats['party1']['party_name'],
                'ioc_count': stats['party1']['ioc_count'],
                'bloom_set_bits': stats['party1']['set_bits']
            },
            'party2_info': {
                'name': stats['party2']['party_name'],
                'ioc_count': stats['party2']['ioc_count'],
                'bloom_set_bits': stats['party2']['set_bits']
            },
            'bloom_filter_params': {
                'size': self.bloom_size,
                'hash_count': self.hash_count
            },
            'privacy_preserved': True,
            'raw_iocs_exposed': False
        }
        
        return result
    
    def verify_correctness(self, party1_iocs: List[IoC], 
                          party2_iocs: List[IoC]) -> Dict:
        """
        Verify protocol correctness by computing actual overlap in plaintext.
        This is for testing purposes only and should NOT be used in production.
        
        Args:
            party1_iocs: IoC list for party 1
            party2_iocs: IoC list for party 2
            
        Returns:
            Dictionary with actual overlap statistics
        """
        # Convert to sets for intersection
        set1 = set(str(ioc) for ioc in party1_iocs)
        set2 = set(str(ioc) for ioc in party2_iocs)
        
        # Compute actual overlap
        intersection = set1 & set2
        union = set1 | set2
        
        actual_overlap = len(intersection)
        actual_jaccard = len(intersection) / len(union) if len(union) > 0 else 0.0
        
        return {
            'actual_overlap': actual_overlap,
            'actual_jaccard_similarity': actual_jaccard,
            'set1_size': len(set1),
            'set2_size': len(set2),
            'union_size': len(union)
        }


def run_simulation(party1_iocs: List[IoC], party2_iocs: List[IoC],
                   bloom_size: int = 10000, hash_count: int = 5,
                   verify: bool = True) -> Dict:
    """
    Run a complete simulation of the two-party protocol.
    
    Args:
        party1_iocs: IoC list for party 1
        party2_iocs: IoC list for party 2
        bloom_size: Bloom filter size
        hash_count: Number of hash functions
        verify: Whether to verify correctness with plaintext computation
        
    Returns:
        Dictionary with simulation results
    """
    # Initialize protocol
    protocol = TwoPartyProtocol(bloom_size=bloom_size, hash_count=hash_count)
    
    # Setup parties
    protocol.setup_parties("ISP-A", "ISP-B", party1_iocs, party2_iocs)
    
    # Execute protocol
    results = protocol.execute_protocol()
    
    # Verify correctness if requested
    if verify:
        verification = protocol.verify_correctness(party1_iocs, party2_iocs)
        results['verification'] = verification
        
        # Calculate error
        estimated = results['overlap_statistics']['estimated_item_overlap']
        actual = verification['actual_overlap']
        error = abs(estimated - actual)
        error_percentage = (error / actual * 100) if actual > 0 else 0
        
        results['accuracy'] = {
            'estimated_overlap': estimated,
            'actual_overlap': actual,
            'error': error,
            'error_percentage': error_percentage
        }
    
    return results
