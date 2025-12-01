"""
IoC (Indicator of Compromise) data models.
"""

import re
import hashlib
from abc import ABC, abstractmethod
from typing import Union


class IoC(ABC):
    """Base class for Indicators of Compromise."""
    
    def __init__(self, value: str):
        """
        Initialize IoC.
        
        Args:
            value: Raw IoC value
        """
        self.raw_value = value
        self.normalized_value = self.normalize(value)
        
    @abstractmethod
    def normalize(self, value: str) -> str:
        """
        Normalize the IoC value for consistent encoding.
        
        Args:
            value: Raw value
            
        Returns:
            Normalized value
        """
        pass
    
    def __str__(self) -> str:
        """String representation."""
        return self.normalized_value
    
    def __repr__(self) -> str:
        """Detailed representation."""
        return f"{self.__class__.__name__}('{self.normalized_value}')"
    
    def __eq__(self, other) -> bool:
        """Equality comparison."""
        if not isinstance(other, IoC):
            return False
        return self.normalized_value == other.normalized_value
    
    def __hash__(self) -> int:
        """Hash for use in sets/dicts."""
        return hash(self.normalized_value)


class IPAddress(IoC):
    """IP Address IoC."""
    
    def normalize(self, value: str) -> str:
        """
        Normalize IP address (remove whitespace, validate format).
        
        Args:
            value: Raw IP address
            
        Returns:
            Normalized IP address
        """
        value = value.strip()
        
        # Basic IPv4 validation
        parts = value.split('.')
        if len(parts) == 4:
            try:
                if all(0 <= int(part) <= 255 for part in parts):
                    return value
            except ValueError:
                pass
        
        # If not valid IPv4, return as-is (could be IPv6)
        return value


class Domain(IoC):
    """Domain name IoC."""
    
    def normalize(self, value: str) -> str:
        """
        Normalize domain (lowercase, remove trailing dot).
        
        Args:
            value: Raw domain
            
        Returns:
            Normalized domain
        """
        value = value.strip().lower()
        
        # Remove trailing dot if present
        if value.endswith('.'):
            value = value[:-1]
        
        # Remove protocol if present
        value = re.sub(r'^https?://', '', value)
        
        # Remove path if present
        value = value.split('/')[0]
        
        return value


class URL(IoC):
    """URL IoC."""
    
    def normalize(self, value: str) -> str:
        """
        Normalize URL (lowercase scheme and domain, preserve path).
        
        Args:
            value: Raw URL
            
        Returns:
            Normalized URL
        """
        value = value.strip()
        
        # Add http:// if no scheme present
        if not re.match(r'^[a-zA-Z]+://', value):
            value = 'http://' + value
        
        # Parse and normalize
        match = re.match(r'^([a-zA-Z]+://)?([^/]+)(.*)', value)
        if match:
            scheme, domain, path = match.groups()
            scheme = (scheme or 'http://').lower()
            domain = domain.lower()
            return f"{scheme}{domain}{path}"
        
        return value.lower()


class FileHash(IoC):
    """File hash IoC (MD5, SHA1, SHA256, etc.)."""
    
    def normalize(self, value: str) -> str:
        """
        Normalize file hash (lowercase, remove whitespace).
        
        Args:
            value: Raw hash
            
        Returns:
            Normalized hash
        """
        value = value.strip().lower()
        
        # Remove any non-hexadecimal characters
        value = re.sub(r'[^a-f0-9]', '', value)
        
        return value


def create_ioc(value: str, ioc_type: str = None) -> IoC:
    """
    Factory function to create appropriate IoC object.
    
    Args:
        value: IoC value
        ioc_type: Type of IoC ('ip', 'domain', 'url', 'hash')
                 If None, will attempt to auto-detect
        
    Returns:
        Appropriate IoC subclass instance
    """
    if ioc_type:
        ioc_type = ioc_type.lower()
        if ioc_type in ['ip', 'ip_address']:
            return IPAddress(value)
        elif ioc_type == 'domain':
            return Domain(value)
        elif ioc_type == 'url':
            return URL(value)
        elif ioc_type in ['hash', 'file_hash']:
            return FileHash(value)
        else:
            raise ValueError(f"Unknown IoC type: {ioc_type}")
    
    # Auto-detect type
    value = value.strip()
    
    # Check if it's a hash (32, 40, or 64 hex characters)
    if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', value):
        return FileHash(value)
    
    # Check if it's an IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return IPAddress(value)
    
    # Check if it's a URL
    if re.match(r'^https?://', value) or '/' in value:
        return URL(value)
    
    # Default to domain
    return Domain(value)
