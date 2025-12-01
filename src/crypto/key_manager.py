"""
Key Manager for storing and loading cryptographic keys.
"""

import os
from pathlib import Path
from typing import Tuple, Optional


class KeyManager:
    """
    Manages storage and retrieval of homomorphic encryption keys.
    """
    
    def __init__(self, key_dir: str = "keys"):
        """
        Initialize key manager.
        
        Args:
            key_dir: Directory to store keys
        """
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        
    def save_keys(self, public_key: bytes, private_key: bytes,
                  public_key_name: str = "public.key",
                  private_key_name: str = "private.key") -> Tuple[str, str]:
        """
        Save public and private keys to files.
        
        Args:
            public_key: Serialized public key
            private_key: Serialized private key
            public_key_name: Filename for public key
            private_key_name: Filename for private key
            
        Returns:
            Tuple of (public_key_path, private_key_path)
        """
        public_path = self.key_dir / public_key_name
        private_path = self.key_dir / private_key_name
        
        # Write keys to files
        with open(public_path, 'wb') as f:
            f.write(public_key)
            
        with open(private_path, 'wb') as f:
            f.write(private_key)
        
        # Set restrictive permissions on private key
        os.chmod(private_path, 0o600)
        
        return str(public_path), str(private_path)
    
    def load_public_key(self, public_key_name: str = "public.key") -> bytes:
        """
        Load public key from file.
        
        Args:
            public_key_name: Filename of public key
            
        Returns:
            Serialized public key
        """
        public_path = self.key_dir / public_key_name
        
        if not public_path.exists():
            raise FileNotFoundError(f"Public key not found: {public_path}")
        
        with open(public_path, 'rb') as f:
            return f.read()
    
    def load_private_key(self, private_key_name: str = "private.key") -> bytes:
        """
        Load private key from file.
        
        Args:
            private_key_name: Filename of private key
            
        Returns:
            Serialized private key
        """
        private_path = self.key_dir / private_key_name
        
        if not private_path.exists():
            raise FileNotFoundError(f"Private key not found: {private_path}")
        
        with open(private_path, 'rb') as f:
            return f.read()
    
    def keys_exist(self, public_key_name: str = "public.key",
                   private_key_name: str = "private.key") -> bool:
        """
        Check if both keys exist.
        
        Args:
            public_key_name: Filename of public key
            private_key_name: Filename of private key
            
        Returns:
            True if both keys exist, False otherwise
        """
        public_path = self.key_dir / public_key_name
        private_path = self.key_dir / private_key_name
        
        return public_path.exists() and private_path.exists()
    
    def delete_keys(self, public_key_name: str = "public.key",
                    private_key_name: str = "private.key"):
        """
        Delete key files.
        
        Args:
            public_key_name: Filename of public key
            private_key_name: Filename of private key
        """
        public_path = self.key_dir / public_key_name
        private_path = self.key_dir / private_key_name
        
        if public_path.exists():
            public_path.unlink()
            
        if private_path.exists():
            private_path.unlink()
