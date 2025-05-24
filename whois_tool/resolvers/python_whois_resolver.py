"""
Python-WHOIS resolver implementation.

This module provides a resolver implementation using the python-whois package.
"""

import logging
import socket
from typing import Dict, Any, Optional

import whois
from whois.parser import PywhoisError

from ..util import WhoisResult
from .base import BaseResolver

# Get logger
logger = logging.getLogger('whois_tool.resolvers.pythonwhois')


class PythonWhoisResolver(BaseResolver):
    """
    WHOIS resolver implementation using the python-whois package.
    
    This resolver uses the python-whois package to look up domain information,
    which can sometimes provide useful organization info for IP addresses.
    This is primarily used as a fallback.
    """
    
    def __init__(self, rate_limit: float = 1.5):
        """
        Initialize the Python-WHOIS resolver.
        
        Args:
            rate_limit: Minimum time between requests in seconds (default: 1.5)
        """
        super().__init__(rate_limit)
        self.name = "PythonWhoisResolver"
        logger.debug(f"Initialized {self.name}")
    
    def _ip_to_domain(self, ip: str) -> Optional[str]:
        """
        Attempt to convert an IP to a domain name using reverse DNS lookup.
        
        Args:
            ip: IP address to convert
            
        Returns:
            Domain name or None if conversion fails
        """
        try:
            domain_name = socket.gethostbyaddr(ip)[0]
            logger.debug(f"Resolved IP {ip} to domain {domain_name}")
            return domain_name
        except (socket.herror, socket.gaierror) as e:
            logger.debug(f"Failed to resolve IP {ip} to domain: {e}")
            return None
    
    def _perform_lookup(self, ip: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Perform the WHOIS lookup using python-whois.
        
        This method first attempts to convert the IP to a domain name,
        then looks up WHOIS information for the domain.
        
        Args:
            ip: IP address to look up
            timeout: Timeout in seconds (None for default)
            
        Returns:
            Raw WHOIS data as a dictionary
            
        Raises:
            ValueError: If lookup fails
        """
        try:
            # Try to convert IP to domain
            domain = self._ip_to_domain(ip)
            
            if not domain:
                logger.warning(f"Could not resolve IP {ip} to domain")
                raise ValueError(f"Could not resolve IP {ip} to domain")
            
            # Set timeout if provided
            if timeout is not None:
                socket.setdefaulttimeout(timeout)
            
            # Perform the lookup
            logger.debug(f"Performing WHOIS lookup for domain {domain}")
            result = whois.whois(domain)
            
            if not result or not result.domain_name:
                logger.warning(f"No WHOIS data found for domain {domain}")
                raise ValueError(f"No WHOIS data found for domain {domain}")
            
            # Convert result to dictionary if it isn't already
            if not isinstance(result, dict):
                result_dict = result.__dict__
            else:
                result_dict = result
                
            # Add IP to result
            result_dict['ip'] = ip
            
            logger.debug(f"Lookup successful for domain {domain}")
            return result_dict
            
        except PywhoisError as e:
            logger.error(f"Python WHOIS error for {ip}: {e}")
            raise ValueError(f"Python WHOIS error: {e}")
        except ValueError:
            # Re-raise ValueError
            raise
        except Exception as e:
            logger.error(f"Unexpected error during lookup for {ip}: {e}")
            raise ValueError(f"Unexpected error during lookup: {e}")


# Register the resolver
PythonWhoisResolver.register()
