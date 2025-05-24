"""
Resolvers package for IP WHOIS lookups.

This package contains different resolver implementations for retrieving
WHOIS information from various sources.
"""

import logging
from typing import Dict, List, Optional, Union, Type

from .base import BaseResolver
from .ipwhois_resolver import IPWhoisResolver
from .python_whois_resolver import PythonWhoisResolver
from .system_resolver import SystemWhoisResolver

# Get logger
logger = logging.getLogger('whois_tool.resolvers')

# Map of resolver names to resolver classes
RESOLVER_MAP: Dict[str, Type[BaseResolver]] = {
    'IPWhoisResolver': IPWhoisResolver,
    'PythonWhoisResolver': PythonWhoisResolver,
    'SystemWhoisResolver': SystemWhoisResolver,
}


def get_available_resolvers() -> List[str]:
    """
    Get a list of available resolver names.
    
    Returns:
        List of resolver names
    """
    return BaseResolver.get_all_resolvers()


def get_resolver(name: str, **kwargs) -> BaseResolver:
    """
    Get a resolver by name.
    
    Args:
        name: Name of the resolver
        **kwargs: Additional arguments for the resolver
        
    Returns:
        Resolver instance
        
    Raises:
        ValueError: If the resolver is not found or cannot be instantiated
    """
    # Check if the resolver exists in our map
    if name not in RESOLVER_MAP:
        available = ', '.join(get_available_resolvers())
        raise ValueError(f"Resolver '{name}' not found. Available resolvers: {available}")
    
    try:
        # Create an instance of the resolver
        resolver_class = RESOLVER_MAP[name]
        return resolver_class(**kwargs)
    except Exception as e:
        # Handle instantiation errors
        logger.error(f"Error creating resolver '{name}': {e}")
        raise ValueError(f"Error creating resolver '{name}': {e}")


def get_resolver_by_method(method: str, **kwargs) -> Union[BaseResolver, List[BaseResolver]]:
    """
    Get a resolver based on the lookup method.
    
    Args:
        method: Lookup method (auto, ipwhois, pythonwhois, system)
        **kwargs: Additional arguments for the resolver
        
    Returns:
        Resolver instance or list of resolver instances
        
    Raises:
        ValueError: If the method is not valid
    """
    if method == 'auto':
        # Return all resolvers in preferred order
        return [
            IPWhoisResolver(**kwargs),
            PythonWhoisResolver(**kwargs),
            SystemWhoisResolver(**kwargs)
        ]
    elif method == 'ipwhois':
        return IPWhoisResolver(**kwargs)
    elif method == 'pythonwhois':
        return PythonWhoisResolver(**kwargs)
    elif method == 'system':
        return SystemWhoisResolver(**kwargs)
    else:
        available = 'auto, ipwhois, pythonwhois, system'
        raise ValueError(f"Invalid lookup method '{method}'. Available methods: {available}")


# Ensure all resolvers are registered
for resolver_class in RESOLVER_MAP.values():
    resolver_class.register()
