"""
Homomorphic Encryption Engine using TenSEAL (BFV scheme)

This module provides a wrapper around TenSEAL's BFV implementation
for privacy-preserving computations on Bloom filters.
"""

import tenseal as ts
import numpy as np
from typing import List, Tuple, Optional
import pickle


class HEEngine:
    """
    Homomorphic Encryption Engine for privacy-preserving computations.
    Uses the BFV (Brakerski-Fan-Vercauteren) scheme.
    """
    
    def __init__(self, poly_modulus_degree: int = 8192, 
                 coeff_mod_bit_sizes: List[int] = None,
                 plain_modulus: int = 1032193):
        """
        Initialize the HE engine with BFV parameters.
        
        Args:
            poly_modulus_degree: Degree of polynomial modulus (power of 2)
            coeff_mod_bit_sizes: Bit sizes for coefficient modulus chain
            plain_modulus: Plaintext modulus (should be prime)
        """
        self.poly_modulus_degree = poly_modulus_degree
        self.coeff_mod_bit_sizes = coeff_mod_bit_sizes or [60, 40, 40, 60]
        self.plain_modulus = plain_modulus
        self.context = None
        self.public_key = None
        self.private_key = None
        
    def generate_keys(self) -> Tuple[bytes, bytes]:
        """
        Generate public and private key pair.
        
        Returns:
            Tuple of (public_key_bytes, private_key_bytes)
        """
        # Create TenSEAL context with BFV scheme
        self.context = ts.context(
            ts.SCHEME_TYPE.BFV,
            poly_modulus_degree=self.poly_modulus_degree,
            plain_modulus=self.plain_modulus,
            coeff_mod_bit_sizes=self.coeff_mod_bit_sizes
        )
        
        # Generate keys
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()
        
        # Serialize keys
        public_context = self.context.serialize(save_secret_key=False)
        private_context = self.context.serialize(save_secret_key=True)
        
        # Store keys
        self.public_key = public_context
        self.private_key = private_context
        
        return public_context, private_context
    
    def load_public_key(self, public_key_bytes: bytes):
        """
        Load public key from serialized bytes.
        
        Args:
            public_key_bytes: Serialized public key
        """
        self.context = ts.context_from(public_key_bytes)
        self.public_key = public_key_bytes
        
    def load_private_key(self, private_key_bytes: bytes):
        """
        Load private key from serialized bytes.
        
        Args:
            private_key_bytes: Serialized private key (includes public key)
        """
        self.context = ts.context_from(private_key_bytes)
        self.private_key = private_key_bytes
        
    def encrypt(self, data: List[int]) -> bytes:
        """
        Encrypt a list of integers (e.g., Bloom filter bit array).
        
        Args:
            data: List of integers to encrypt
            
        Returns:
            Serialized ciphertext
        """
        if self.context is None:
            raise ValueError("Context not initialized. Generate or load keys first.")
        
        # Create BFV vector and encrypt
        encrypted = ts.bfv_vector(self.context, data)
        return encrypted.serialize()
    
    def decrypt(self, ciphertext_bytes: bytes) -> List[int]:
        """
        Decrypt ciphertext back to plaintext integers.
        
        Args:
            ciphertext_bytes: Serialized ciphertext
            
        Returns:
            Decrypted list of integers
        """
        if self.context is None or self.private_key is None:
            raise ValueError("Private key not loaded. Cannot decrypt.")
        
        # Deserialize and decrypt
        encrypted = ts.bfv_vector_from(self.context, ciphertext_bytes)
        return encrypted.decrypt()
    
    def add_encrypted(self, ciphertext1_bytes: bytes, 
                      ciphertext2_bytes: bytes) -> bytes:
        """
        Add two encrypted vectors homomorphically.
        
        Args:
            ciphertext1_bytes: First encrypted vector
            ciphertext2_bytes: Second encrypted vector
            
        Returns:
            Serialized result of addition
        """
        if self.context is None:
            raise ValueError("Context not initialized.")
        
        enc1 = ts.bfv_vector_from(self.context, ciphertext1_bytes)
        enc2 = ts.bfv_vector_from(self.context, ciphertext2_bytes)
        
        result = enc1 + enc2
        return result.serialize()
    
    def multiply_encrypted(self, ciphertext1_bytes: bytes, 
                          ciphertext2_bytes: bytes) -> bytes:
        """
        Multiply two encrypted vectors homomorphically (element-wise).
        This is the key operation for computing Bloom filter intersection.
        
        Args:
            ciphertext1_bytes: First encrypted vector
            ciphertext2_bytes: Second encrypted vector
            
        Returns:
            Serialized result of multiplication
        """
        if self.context is None:
            raise ValueError("Context not initialized.")
        
        enc1 = ts.bfv_vector_from(self.context, ciphertext1_bytes)
        enc2 = ts.bfv_vector_from(self.context, ciphertext2_bytes)
        
        result = enc1 * enc2
        return result.serialize()
    
    def multiply_plain(self, ciphertext_bytes: bytes, 
                       plaintext: int) -> bytes:
        """
        Multiply encrypted vector by a plaintext scalar.
        
        Args:
            ciphertext_bytes: Encrypted vector
            plaintext: Plaintext scalar
            
        Returns:
            Serialized result
        """
        if self.context is None:
            raise ValueError("Context not initialized.")
        
        enc = ts.bfv_vector_from(self.context, ciphertext_bytes)
        result = enc * plaintext
        return result.serialize()
    
    def sum_encrypted(self, ciphertext_bytes: bytes) -> bytes:
        """
        Sum all elements in an encrypted vector.
        Useful for counting set bits in Bloom filter.
        
        Args:
            ciphertext_bytes: Encrypted vector
            
        Returns:
            Serialized encrypted sum
        """
        if self.context is None:
            raise ValueError("Context not initialized.")
        
        enc = ts.bfv_vector_from(self.context, ciphertext_bytes)
        # Sum is not directly available, so we decrypt and re-encrypt
        # In production, this would use rotation and addition
        decrypted = enc.decrypt()
        total = sum(decrypted)
        encrypted_sum = ts.bfv_vector(self.context, [total])
        return encrypted_sum.serialize()
    
    def get_context_info(self) -> dict:
        """
        Get information about the current encryption context.
        
        Returns:
            Dictionary with context parameters
        """
        if self.context is None:
            return {"status": "not_initialized"}
        
        return {
            "poly_modulus_degree": self.poly_modulus_degree,
            "coeff_mod_bit_sizes": self.coeff_mod_bit_sizes,
            "plain_modulus": self.plain_modulus,
            "status": "initialized"
        }
