"""
Dataset loader for IoC lists (synthetic and public sources).
"""

import random
import string
import requests
from typing import List, Tuple, Set
from .ioc_models import IoC, IPAddress, Domain, URL, FileHash, create_ioc


class DatasetLoader:
    """Utility class for loading and generating IoC datasets."""
    
    @staticmethod
    def generate_random_ip() -> str:
        """Generate a random IP address."""
        return '.'.join(str(random.randint(0, 255)) for _ in range(4))
    
    @staticmethod
    def generate_random_domain() -> str:
        """Generate a random domain name."""
        tlds = ['com', 'net', 'org', 'io', 'co', 'info']
        length = random.randint(5, 15)
        name = ''.join(random.choices(string.ascii_lowercase, k=length))
        return f"{name}.{random.choice(tlds)}"
    
    @staticmethod
    def generate_random_url() -> str:
        """Generate a random URL."""
        domain = DatasetLoader.generate_random_domain()
        path_length = random.randint(5, 20)
        path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=path_length))
        return f"http://{domain}/{path}"
    
    @staticmethod
    def generate_random_hash(hash_type: str = 'sha256') -> str:
        """
        Generate a random file hash.
        
        Args:
            hash_type: Type of hash ('md5', 'sha1', 'sha256')
            
        Returns:
            Random hash string
        """
        lengths = {'md5': 32, 'sha1': 40, 'sha256': 64}
        length = lengths.get(hash_type, 64)
        return ''.join(random.choices(string.hexdigits.lower(), k=length))
    
    @staticmethod
    def load_synthetic_dataset(size: int, ioc_type: str = 'ip') -> List[IoC]:
        """
        Generate a synthetic dataset of IoCs.
        
        Args:
            size: Number of IoCs to generate
            ioc_type: Type of IoCs ('ip', 'domain', 'url', 'hash', 'mixed')
            
        Returns:
            List of IoC objects
        """
        iocs = []
        
        if ioc_type == 'mixed':
            # Generate mixed types
            types = ['ip', 'domain', 'url', 'hash']
            for _ in range(size):
                chosen_type = random.choice(types)
                iocs.append(DatasetLoader._generate_single_ioc(chosen_type))
        else:
            # Generate single type
            for _ in range(size):
                iocs.append(DatasetLoader._generate_single_ioc(ioc_type))
        
        return iocs
    
    @staticmethod
    def _generate_single_ioc(ioc_type: str) -> IoC:
        """Generate a single IoC of specified type."""
        if ioc_type == 'ip':
            return IPAddress(DatasetLoader.generate_random_ip())
        elif ioc_type == 'domain':
            return Domain(DatasetLoader.generate_random_domain())
        elif ioc_type == 'url':
            return URL(DatasetLoader.generate_random_url())
        elif ioc_type == 'hash':
            return FileHash(DatasetLoader.generate_random_hash())
        else:
            raise ValueError(f"Unknown IoC type: {ioc_type}")
    
    @staticmethod
    def create_test_datasets(size1: int, size2: int, 
                            overlap_percentage: float,
                            ioc_type: str = 'ip') -> Tuple[List[IoC], List[IoC]]:
        """
        Create two datasets with controlled overlap.
        
        Args:
            size1: Size of first dataset
            size2: Size of second dataset
            overlap_percentage: Percentage of overlap (0-100)
            ioc_type: Type of IoCs to generate
            
        Returns:
            Tuple of (dataset1, dataset2)
        """
        if not 0 <= overlap_percentage <= 100:
            raise ValueError("Overlap percentage must be between 0 and 100")
        
        # Calculate overlap size
        overlap_size = int(min(size1, size2) * overlap_percentage / 100)
        
        # Generate overlapping items
        overlap_items = DatasetLoader.load_synthetic_dataset(overlap_size, ioc_type)
        
        # Generate unique items for dataset1
        unique1_size = size1 - overlap_size
        unique1 = DatasetLoader.load_synthetic_dataset(unique1_size, ioc_type)
        
        # Generate unique items for dataset2
        unique2_size = size2 - overlap_size
        unique2 = DatasetLoader.load_synthetic_dataset(unique2_size, ioc_type)
        
        # Combine to create datasets
        dataset1 = overlap_items + unique1
        dataset2 = overlap_items + unique2
        
        # Shuffle to randomize order
        random.shuffle(dataset1)
        random.shuffle(dataset2)
        
        return dataset1, dataset2
    
    @staticmethod
    def load_from_file(filepath: str, ioc_type: str = None) -> List[IoC]:
        """
        Load IoCs from a text file (one per line).
        
        Args:
            filepath: Path to file
            ioc_type: Type of IoCs in file (auto-detect if None)
            
        Returns:
            List of IoC objects
        """
        iocs = []
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ioc = create_ioc(line, ioc_type)
                        iocs.append(ioc)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filepath}")
        
        return iocs
    
    @staticmethod
    def load_from_url(url: str, ioc_type: str = None) -> List[IoC]:
        """
        Load IoCs from a URL (one per line).
        
        Args:
            url: URL to fetch from
            ioc_type: Type of IoCs (auto-detect if None)
            
        Returns:
            List of IoC objects
        """
        iocs = []
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            for line in response.text.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        ioc = create_ioc(line, ioc_type)
                        iocs.append(ioc)
                    except Exception:
                        # Skip invalid lines
                        continue
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch from URL: {e}")
        
        return iocs
    
    @staticmethod
    def save_to_file(iocs: List[IoC], filepath: str):
        """
        Save IoCs to a text file (one per line).
        
        Args:
            iocs: List of IoC objects
            filepath: Path to save file
        """
        with open(filepath, 'w') as f:
            for ioc in iocs:
                f.write(f"{ioc}\n")
