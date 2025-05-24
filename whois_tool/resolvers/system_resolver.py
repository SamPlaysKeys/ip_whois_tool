"""
System WHOIS resolver implementation.

This module provides a resolver implementation using the system whois command.
"""

import logging
import re
import subprocess
import json
from typing import Dict, Any, Optional, List, Tuple

from ..util import WhoisResult
from .base import BaseResolver

# Get logger
logger = logging.getLogger('whois_tool.resolvers.system')


class SystemWhoisResolver(BaseResolver):
    """
    WHOIS resolver implementation using the system whois command.
    
    This resolver uses the system's whois command to look up information
    for IP addresses. It's used as a fallback when other methods fail.
    """
    
    def __init__(self, rate_limit: float = 2.0, whois_path: str = '/usr/bin/whois'):
        """
        Initialize the System WHOIS resolver.
        
        Args:
            rate_limit: Minimum time between requests in seconds (default: 2.0)
            whois_path: Path to the whois command (default: /usr/bin/whois)
        """
        super().__init__(rate_limit)
        self.whois_path = whois_path
        self.name = "SystemWhoisResolver"
        logger.debug(f"Initialized {self.name} with whois path: {whois_path}")
    
    def _parse_whois_output(self, output: str, ip: str) -> Dict[str, Any]:
        """
        Parse raw WHOIS output into a structured dictionary.
        
        Args:
            output: Raw WHOIS output
            ip: IP address
            
        Returns:
            Parsed WHOIS data as a dictionary
        """
        result: Dict[str, Any] = {'ip': ip}
        
        # Regular expressions for key information
        patterns = {
            'organization': [
                r'(?:Organization|Org(?:anization)? Name):\s*(.+)$',
                r'(?:descr|owner):\s*(.+)$'
            ],
            'country': [
                r'(?:Country|Country Code):\s*(.+)$',
                r'country:\s*(.+)$'
            ],
            'asn': [
                r'(?:OriginAS|Origin AS|ASNumber|ASN):\s*(.+)$',
                r'origin:\s*AS(\d+)$'
            ],
            'network': [
                r'(?:CIDR|NetRange|Network):\s*(.+)$',
                r'inetnum:\s*(.+)$'
            ],
            'registered': [
                r'(?:RegDate|Created|Registration Date):\s*(.+)$',
                r'created:\s*(.+)$'
            ]
        }
        
        # Process each line and extract information
        for line in output.splitlines():
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            
            # Process each pattern and extract data
            for key, pattern_list in patterns.items():
                for pattern in pattern_list:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        result[key] = match.group(1).strip()
                        break
        
        return result
    
    def _execute_whois_command(self, ip: str, timeout: Optional[float] = None) -> Tuple[str, int]:
        """
        Execute the system whois command.
        
        Args:
            ip: IP address to look up
            timeout: Timeout in seconds (None for default)
            
        Returns:
            Tuple of (output, return_code)
            
        Raises:
            subprocess.SubprocessError: If command execution fails
        """
        try:
            # Prepare command with timeout
            cmd = [self.whois_path, ip]
            timeout_val = timeout if timeout is not None else 30
            
            # Execute command
            logger.debug(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_val,
                check=False
            )
            
            return result.stdout, result.returncode
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout expired for whois {ip}")
            raise ValueError(f"Timeout expired for whois command")
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error for whois {ip}: {e}")
            raise ValueError(f"Error executing whois command: {e}")
    
    def _perform_lookup(self, ip: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Perform the WHOIS lookup using the system whois command.
        
        Args:
            ip: IP address to look up
            timeout: Timeout in seconds (None for default)
            
        Returns:
            Raw WHOIS data as a dictionary
            
        Raises:
            ValueError: If lookup fails
        """
        try:
            # Execute the whois command
            output, return_code = self._execute_whois_command(ip, timeout)
            
            # Check if command was successful
            if return_code != 0:
                logger.warning(f"whois command returned non-zero code {return_code} for {ip}")
                if not output:
                    raise ValueError(f"whois command failed with code {return_code}")
            
            # Check if we got any output
            if not output:
                logger.warning(f"No output from whois command for {ip}")
                raise ValueError("No output from whois command")
            
            # Parse the output
            result = self._parse_whois_output(output, ip)
            
            # Add raw output for debugging
            result['raw_output'] = output
            
            logger.debug(f"Lookup successful for {ip}")
            return result
            
        except ValueError:
            # Re-raise ValueError
            raise
        except Exception as e:
            logger.error(f"Unexpected error during lookup for {ip}: {e}")
            raise ValueError(f"Unexpected error during lookup: {e}")


# Register the resolver
SystemWhoisResolver.register()
