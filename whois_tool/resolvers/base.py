"""
Base resolver class for IP WHOIS lookups.

This module defines an abstract base class for WHOIS resolvers.
"""

import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, ClassVar

from ..util import validate_ip, normalize_whois_result, WhoisResult

# Get logger
logger = logging.getLogger('whois_tool.resolvers.base')


class BaseResolver(ABC):
    """
    Abstract base class for WHOIS resolvers.
    
    This class defines the interface that all WHOIS resolvers must implement.
    It provides common functionality for rate limiting and result normalization.
    """
    
    # Class variable for resolver registry
    resolver_registry: ClassVar[List[str]] = []
    
    def __init__(self, rate_limit: float = 1.0):
        """
        Initialize the resolver.
        
        Args:
            rate_limit: Minimum time between requests in seconds (default: 1.0)
        """
        self.rate_limit = rate_limit
        self.last_request_time = 0.0
        self.name = self.__class__.__name__
        logger.debug(f"Initialized {self.name} with rate limit {rate_limit}s")
    
    def _apply_rate_limit(self):
        """
        Apply rate limiting before making a request.
        
        This method ensures that requests are not made too frequently by
        sleeping if necessary.
        """
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if elapsed < self.rate_limit:
            # Sleep for the remaining time
            sleep_time = self.rate_limit - elapsed
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
            
        # Update the last request time
        self.last_request_time = time.time()
    
    @abstractmethod
    def _perform_lookup(self, ip: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Perform the actual WHOIS lookup.
        
        Args:
            ip: IP address to look up
            timeout: Timeout in seconds (None for default)
            
        Returns:
            Raw WHOIS data as a dictionary
            
        Raises:
            Exception: If the lookup fails
        """
        pass
    
    def lookup(self, ip: str, timeout: Optional[float] = None, max_retries: int = 2) -> WhoisResult:
        """
        Look up WHOIS information for an IP address.
        
        Args:
            ip: IP address to look up
            timeout: Timeout in seconds (None for default)
            max_retries: Maximum number of retry attempts
            
        Returns:
            Normalized WHOIS information
            
        Raises:
            ValueError: If the IP address is invalid
            Exception: If the lookup fails after retries
        """
        # Validate the IP address
        validate_ip(ip)
        
        # Initialize retry counter
        retry_count = 0
        last_error = None
        
        while retry_count <= max_retries:
            try:
                # Apply rate limiting
                self._apply_rate_limit()
                
                # Log lookup attempt
                if retry_count > 0:
                    logger.debug(f"Retry {retry_count}/{max_retries} for {ip} using {self.name}")
                else:
                    logger.debug(f"Looking up {ip} using {self.name}")
                
                # Perform the lookup
                raw_result = self._perform_lookup(ip, timeout)
                
                # Make sure the IP is included in the result
                if 'ip' not in raw_result:
                    raw_result['ip'] = ip
                    
                # Normalize the result
                result = normalize_whois_result(raw_result, self.name)
                
                logger.debug(f"Lookup successful for {ip} using {self.name}")
                return result
                
            except Exception as e:
                last_error = e
                retry_count += 1
                
                if retry_count <= max_retries:
                    logger.warning(f"Lookup failed for {ip} using {self.name}: {e}. Retrying ({retry_count}/{max_retries})...")
                    # Exponential backoff for retries
                    time.sleep(retry_count * 2)
                else:
                    logger.error(f"Lookup failed for {ip} using {self.name} after {max_retries} retries: {e}")
                    raise ValueError(f"Lookup failed: {e}")
    
    @classmethod
    def register(cls) -> None:
        """
        Register this resolver in the resolver registry.
        
        This method is called by resolver implementations to register
        themselves in the resolver registry.
        """
        if cls.__name__ not in cls.resolver_registry and cls != BaseResolver:
            logger.debug(f"Registering resolver: {cls.__name__}")
            cls.resolver_registry.append(cls.__name__)
    
    @classmethod
    def get_resolver_name(cls) -> str:
        """
        Get the name of the resolver.
        
        Returns:
            Name of the resolver
        """
        return cls.__name__
    
    @classmethod
    def get_all_resolvers(cls) -> List[str]:
        """
        Get a list of all available resolver names.
        
        Returns:
            List of resolver names
        """
        return cls.resolver_registry.copy()
