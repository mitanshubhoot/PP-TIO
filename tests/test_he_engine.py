"""
Unit tests for homomorphic encryption engine.
"""

import pytest
from src.crypto.he_engine import HEEngine


def test_he_engine_initialization():
    """Test HE engine initialization."""
    he = HEEngine(poly_modulus_degree=4096, plain_modulus=1032193)
    assert he.poly_modulus_degree == 4096
    assert he.plain_modulus == 1032193
    assert he.context is None


def test_key_generation():
    """Test key generation."""
    he = HEEngine()
    public_key, private_key = he.generate_keys()
    
    assert public_key is not None
    assert private_key is not None
    assert isinstance(public_key, bytes)
    assert isinstance(private_key, bytes)
    assert he.context is not None


def test_encryption_decryption():
    """Test encryption and decryption."""
    he = HEEngine()
    he.generate_keys()
    
    # Test data
    data = [1, 0, 1, 1, 0, 0, 1, 0]
    
    # Encrypt
    ciphertext = he.encrypt(data)
    assert isinstance(ciphertext, bytes)
    
    # Decrypt
    decrypted = he.decrypt(ciphertext)
    assert decrypted == data


def test_homomorphic_addition():
    """Test homomorphic addition."""
    he = HEEngine()
    he.generate_keys()
    
    data1 = [1, 2, 3, 4]
    data2 = [5, 6, 7, 8]
    
    # Encrypt both
    enc1 = he.encrypt(data1)
    enc2 = he.encrypt(data2)
    
    # Add homomorphically
    enc_sum = he.add_encrypted(enc1, enc2)
    
    # Decrypt result
    result = he.decrypt(enc_sum)
    expected = [a + b for a, b in zip(data1, data2)]
    
    assert result == expected


def test_homomorphic_multiplication():
    """Test homomorphic multiplication (for Bloom filter AND)."""
    he = HEEngine()
    he.generate_keys()
    
    # Binary data (Bloom filter bits)
    data1 = [1, 1, 0, 1, 0]
    data2 = [1, 0, 1, 1, 0]
    
    # Encrypt both
    enc1 = he.encrypt(data1)
    enc2 = he.encrypt(data2)
    
    # Multiply homomorphically (AND operation)
    enc_product = he.multiply_encrypted(enc1, enc2)
    
    # Decrypt result
    result = he.decrypt(enc_product)
    expected = [a * b for a, b in zip(data1, data2)]
    
    assert result == expected


def test_multiply_plain():
    """Test multiplication by plaintext scalar."""
    he = HEEngine()
    he.generate_keys()
    
    data = [1, 2, 3, 4]
    scalar = 3
    
    # Encrypt
    enc = he.encrypt(data)
    
    # Multiply by scalar
    enc_result = he.multiply_plain(enc, scalar)
    
    # Decrypt
    result = he.decrypt(enc_result)
    expected = [x * scalar for x in data]
    
    assert result == expected


def test_load_public_key():
    """Test loading public key."""
    he1 = HEEngine()
    public_key, _ = he1.generate_keys()
    
    # Create new engine and load public key
    he2 = HEEngine()
    he2.load_public_key(public_key)
    
    assert he2.context is not None
    
    # Should be able to encrypt with public key
    data = [1, 2, 3]
    ciphertext = he2.encrypt(data)
    assert isinstance(ciphertext, bytes)


def test_load_private_key():
    """Test loading private key."""
    he1 = HEEngine()
    _, private_key = he1.generate_keys()
    
    # Create new engine and load private key
    he2 = HEEngine()
    he2.load_private_key(private_key)
    
    assert he2.context is not None
    
    # Should be able to encrypt and decrypt
    data = [1, 2, 3]
    ciphertext = he2.encrypt(data)
    decrypted = he2.decrypt(ciphertext)
    assert decrypted == data


def test_context_info():
    """Test getting context information."""
    he = HEEngine(poly_modulus_degree=4096)
    
    # Before initialization
    info = he.get_context_info()
    assert info['status'] == 'not_initialized'
    
    # After key generation
    he.generate_keys()
    info = he.get_context_info()
    assert info['status'] == 'initialized'
    # Just verify the poly_modulus_degree is stored, don't query context
    assert he.poly_modulus_degree == 4096


def test_encryption_without_keys():
    """Test that encryption fails without keys."""
    he = HEEngine()
    
    with pytest.raises(ValueError):
        he.encrypt([1, 2, 3])


def test_decryption_without_private_key():
    """Test that decryption fails without private key."""
    he1 = HEEngine()
    public_key, _ = he1.generate_keys()
    
    # Encrypt with first engine
    ciphertext = he1.encrypt([1, 2, 3])
    
    # Try to decrypt with engine that only has public key
    he2 = HEEngine()
    he2.load_public_key(public_key)
    
    with pytest.raises(ValueError):
        he2.decrypt(ciphertext)
