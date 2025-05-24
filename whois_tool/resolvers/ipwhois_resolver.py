"""
RDAP/WHOIS resolver using the ipwhois package.

This is our primary resolver since it gives the most reliable results.
"""

import socket
import logging
from typing import Dict, Any, Optional

from ipwhois import IPWhois
from ipwhois.exceptions import (
    IPDefinedError, ASNRegistryError, HTTPLookupError, WhoisLookupError
)

from ..util import WhoisResult
from .base import BaseResolver

# Set up logging
logger = logging.getLogger('whois_tool.resolvers.ipwhois')


class IPWhoisResolver(BaseResolver):
    """Uses ipwhois package to get RDAP/WHOIS data"""
    
    def __init__(self, rate_limit=1.0, use_rdap=True):
        super().__init__(rate_limit)
        self.use_rdap = use_rdap
        self.name = "IPWhoisResolver"

    def _perform_lookup(self, ip: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Do the actual lookup via ipwhois"""
        try:
            # Initialize the IPWhois object
            obj = IPWhois(ip)
            
            # Set the timeout if provided
            if timeout is not None:
                socket.setdefaulttimeout(timeout)
            
            # Perform the lookup
            if self.use_rdap:
                logger.debug(f"Performing RDAP lookup for {ip}")
                result = obj.lookup_rdap(
                    asn_methods=['whois', 'http'],
                    inc_raw=False,
                    retry_count=2
                )
            else:
                logger.debug(f"Performing WHOIS lookup for {ip}")
                result = obj.lookup_whois(
                    inc_raw=False,
                    retry_count=2
                )
                
            logger.debug(f"Lookup successful for {ip}")
            return result
            
        except IPDefinedError as e:
            logger.error(f"IP defined error for {ip}: {e}")
            raise ValueError(f"IP defined error: {e}")
        except ASNRegistryError as e:
            logger.error(f"ASN registry error for {ip}: {e}")
            raise ValueError(f"ASN registry error: {e}")
        except HTTPLookupError as e:
            logger.error(f"HTTP lookup error for {ip}: {e}")
            raise ValueError(f"HTTP lookup error: {e}")
        except WhoisLookupError as e:
            logger.error(f"WHOIS lookup error for {ip}: {e}")
            raise ValueError(f"WHOIS lookup error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during lookup for {ip}: {e}")
            raise ValueError(f"Unexpected error during lookup: {e}")


# Register this resolver
IPWhoisResolver.register()
