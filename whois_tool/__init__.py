"""
IP WHOIS Lookup Tool package.

This package provides tools for looking up WHOIS information for IP addresses
using multiple sources and methods. It supports various output formats and
provides caching to avoid unnecessary network requests.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

# Version
__version__ = '0.1.0'

# Setup logging
logger = logging.getLogger('whois_tool')

# Create logs directory if it doesn't exist
os.makedirs(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'logs'), exist_ok=True)

# Setup rotating file handler
log_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'logs', 'whois_tool.log')
file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Default log level
logger.setLevel(logging.INFO)

# Import main components for easier access
from .engine import WhoisEngine
from .util import WhoisResult, filter_valid_ips, merge_whois_results
from .output import render_console, write_output, write_csv, write_json, write_text
from .resolvers import get_resolver, get_resolver_by_method, get_available_resolvers

# Define public API
__all__ = [
    'WhoisEngine',
    'WhoisResult',
    'filter_valid_ips',
    'merge_whois_results',
    'render_console',
    'write_output',
    'write_csv',
    'write_json',
    'write_text',
    'get_resolver',
    'get_resolver_by_method',
    'get_available_resolvers',
    '__version__'
]
