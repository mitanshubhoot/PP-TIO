"""
Unit tests for IoC models.
"""

import pytest
from src.data.ioc_models import (
    IoC, IPAddress, Domain, URL, FileHash, create_ioc
)


def test_ip_address_normalization():
    """Test IP address normalization."""
    ip = IPAddress("192.168.1.1")
    assert str(ip) == "192.168.1.1"
    
    ip_with_space = IPAddress("  10.0.0.1  ")
    assert str(ip_with_space) == "10.0.0.1"


def test_domain_normalization():
    """Test domain normalization."""
    domain = Domain("Example.COM")
    assert str(domain) == "example.com"
    
    domain_with_dot = Domain("example.com.")
    assert str(domain_with_dot) == "example.com"
    
    domain_with_protocol = Domain("https://example.com")
    assert str(domain_with_protocol) == "example.com"
    
    domain_with_path = Domain("example.com/path")
    assert str(domain_with_path) == "example.com"


def test_url_normalization():
    """Test URL normalization."""
    url = URL("HTTP://Example.COM/Path")
    assert str(url) == "http://example.com/Path"
    
    url_no_scheme = URL("example.com/path")
    assert str(url_no_scheme) == "http://example.com/path"


def test_file_hash_normalization():
    """Test file hash normalization."""
    hash_upper = FileHash("ABCDEF1234567890")
    assert str(hash_upper) == "abcdef1234567890"
    
    hash_with_space = FileHash("  abc def  ")
    assert str(hash_with_space) == "abcdef"


def test_ioc_equality():
    """Test IoC equality comparison."""
    ip1 = IPAddress("192.168.1.1")
    ip2 = IPAddress("192.168.1.1")
    ip3 = IPAddress("10.0.0.1")
    
    assert ip1 == ip2
    assert ip1 != ip3


def test_ioc_hashing():
    """Test IoC hashing for use in sets."""
    ip1 = IPAddress("192.168.1.1")
    ip2 = IPAddress("192.168.1.1")
    
    ioc_set = {ip1, ip2}
    assert len(ioc_set) == 1  # Should be deduplicated


def test_create_ioc_with_type():
    """Test IoC factory function with explicit type."""
    ip = create_ioc("192.168.1.1", "ip")
    assert isinstance(ip, IPAddress)
    
    domain = create_ioc("example.com", "domain")
    assert isinstance(domain, Domain)
    
    url = create_ioc("http://example.com", "url")
    assert isinstance(url, URL)
    
    hash_ioc = create_ioc("abcdef1234567890", "hash")
    assert isinstance(hash_ioc, FileHash)


def test_create_ioc_auto_detect():
    """Test IoC factory function with auto-detection."""
    # Should detect as IP
    ip = create_ioc("192.168.1.1")
    assert isinstance(ip, IPAddress)
    
    # Should detect as hash (32 hex chars = MD5)
    hash_ioc = create_ioc("d41d8cd98f00b204e9800998ecf8427e")
    assert isinstance(hash_ioc, FileHash)
    
    # Should detect as URL
    url = create_ioc("http://example.com/path")
    assert isinstance(url, URL)
    
    # Should detect as domain
    domain = create_ioc("example.com")
    assert isinstance(domain, Domain)


def test_create_ioc_invalid_type():
    """Test IoC factory with invalid type."""
    with pytest.raises(ValueError):
        create_ioc("test", "invalid_type")


def test_ioc_repr():
    """Test IoC representation."""
    ip = IPAddress("192.168.1.1")
    repr_str = repr(ip)
    assert "IPAddress" in repr_str
    assert "192.168.1.1" in repr_str
