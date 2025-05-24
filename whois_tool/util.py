"""
Utility functions for IP WHOIS lookup tool.

This module provides utility functions for IP validation and data normalization.
"""

import ipaddress
import re
import logging
from typing import Dict, Any, Union, Optional, TypeVar, cast, List
from datetime import datetime

# Get logger
logger = logging.getLogger('whois_tool.util')

# Type aliases
IPAddress = TypeVar('IPAddress', ipaddress.IPv4Address, ipaddress.IPv6Address)
IPNetwork = TypeVar('IPNetwork', ipaddress.IPv4Network, ipaddress.IPv6Network)
WhoisResult = Dict[str, Any]


def validate_ip(ip_str: str) -> IPAddress:
    """
    Validate and convert a string to an IP address object.
    
    Args:
        ip_str: A string representing an IP address (IPv4 or IPv6)
        
    Returns:
        An IPv4Address or IPv6Address object
        
    Raises:
        ValueError: If the string is not a valid IP address
    """
    try:
        # Try to create an IP address object
        ip_obj = ipaddress.ip_address(ip_str)
        return cast(IPAddress, ip_obj)
    except ValueError:
        logger.error(f"Invalid IP address: {ip_str}")
        raise ValueError(f"Invalid IP address: {ip_str}")


def is_valid_ip(ip_str: str) -> bool:
    """
    Check if a string is a valid IP address.
    
    Args:
        ip_str: A string to check
        
    Returns:
        True if the string is a valid IP address, False otherwise
    """
    try:
        validate_ip(ip_str)
        return True
    except ValueError:
        return False


def extract_asn(asn_str: Optional[str]) -> Optional[str]:
    """
    Extract the ASN number from an ASN string.
    
    Args:
        asn_str: A string that may contain an ASN number
        
    Returns:
        The extracted ASN number or None if not found
    """
    if not asn_str:
        return None
        
    # Pattern to match ASN number (AS followed by digits)
    pattern = r'AS(\d+)'
    match = re.search(pattern, str(asn_str))
    
    if match:
        return match.group(1)
    
    # If no match but there are digits, extract them
    digits = re.search(r'(\d+)', str(asn_str))
    if digits:
        return digits.group(1)
        
    return None


def extract_organization(org_data: Optional[Union[str, Dict[str, Any]]]) -> Optional[str]:
    """
    Extract organization name from various data formats.
    
    Args:
        org_data: Organization data that may be a string or dictionary
        
    Returns:
        Organization name as a string or None if not found
    """
    if not org_data:
        return None
        
    if isinstance(org_data, str):
        return org_data.strip()
    
    if isinstance(org_data, dict):
        # Try common keys for organization
        for key in ['name', 'org', 'organization', 'orgName']:
            if key in org_data and org_data[key]:
                return str(org_data[key]).strip()
    
    return None


def extract_country(location_data: Optional[Union[str, Dict[str, Any]]]) -> Optional[str]:
    """
    Extract country information from location data.
    
    Args:
        location_data: Location data that may be a string or dictionary
        
    Returns:
        Country code or name as a string, or None if not found
    """
    if not location_data:
        return None
        
    if isinstance(location_data, str):
        return location_data.strip()
    
    if isinstance(location_data, dict):
        # Try common keys for country
        for key in ['country', 'cc', 'countryCode', 'country_code']:
            if key in location_data and location_data[key]:
                return str(location_data[key]).strip()
    
    return None


def extract_city(location_data: Optional[Union[str, Dict[str, Any]]]) -> Optional[str]:
    """
    Extract city information from location data.
    
    Args:
        location_data: Location data that may be a string or dictionary
        
    Returns:
        City name as a string, or None if not found
    """
    if not location_data:
        return None
        
    if isinstance(location_data, str):
        # If it's just a string, assume it's not a city
        return None
    
    if isinstance(location_data, dict):
        # Try common keys for city
        for key in ['city', 'cityName', 'city_name']:
            if key in location_data and location_data[key]:
                return str(location_data[key]).strip()
    
    return None


def format_timestamp(timestamp: Optional[Union[str, int, float, datetime]]) -> Optional[str]:
    """
    Format a timestamp to a consistent string format.
    
    Args:
        timestamp: A timestamp in various formats
        
    Returns:
        Formatted timestamp string or None if input is None
    """
    if timestamp is None:
        return None
        
    try:
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(timestamp)
        elif isinstance(timestamp, str):
            # Try parsing as ISO format first
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                # If that fails, try a common format
                dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        elif isinstance(timestamp, datetime):
            dt = timestamp
        else:
            return str(timestamp)
            
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        logger.debug(f"Error formatting timestamp {timestamp}: {e}")
        # If we can't parse it, return as is
        return str(timestamp) if timestamp else None


def normalize_whois_result(raw_result: Dict[str, Any], source: str) -> WhoisResult:
    """
    Normalize raw WHOIS lookup results to a consistent format.
    
    Args:
        raw_result: Raw WHOIS lookup result
        source: Source of the WHOIS data
        
    Returns:
        Normalized WHOIS result dictionary
    """
    result = {
        'ip': None,
        'network': None,
        'asn': None,
        'organization': None,
        'country': None,
        'city': None,
        'registered': None,
        'source': source,
        'raw': raw_result
    }
    
    # Extract IP
    if 'ip' in raw_result:
        result['ip'] = raw_result['ip']
    elif 'query' in raw_result:
        result['ip'] = raw_result['query']
    
    # Extract network
    if 'network' in raw_result and isinstance(raw_result['network'], dict):
        if 'cidr' in raw_result['network']:
            result['network'] = raw_result['network']['cidr']
        elif 'start_address' in raw_result['network'] and 'end_address' in raw_result['network']:
            result['network'] = f"{raw_result['network']['start_address']}-{raw_result['network']['end_address']}"
    elif 'cidr' in raw_result:
        result['network'] = raw_result['cidr']
        
    # Extract ASN
    if 'asn' in raw_result:
        result['asn'] = extract_asn(str(raw_result['asn']))
    elif 'asn_registry' in raw_result and 'asn' in raw_result:
        result['asn'] = extract_asn(str(raw_result['asn']))
        
    # Extract organization
    if 'org' in raw_result:
        result['organization'] = extract_organization(raw_result['org'])
    elif 'organization' in raw_result:
        result['organization'] = extract_organization(raw_result['organization'])
    elif 'nets' in raw_result and raw_result['nets'] and isinstance(raw_result['nets'], list):
        for net in raw_result['nets']:
            if 'description' in net:
                result['organization'] = extract_organization(net['description'])
                break
                
    # Extract location
    if 'country' in raw_result:
        result['country'] = extract_country(raw_result['country'])
    elif 'asn_country_code' in raw_result:
        result['country'] = extract_country(raw_result['asn_country_code'])
    
    if 'city' in raw_result:
        result['city'] = extract_city(raw_result['city'])
        
    # Extract registration date
    if 'registered' in raw_result:
        result['registered'] = format_timestamp(raw_result['registered'])
    elif 'created' in raw_result:
        result['registered'] = format_timestamp(raw_result['created'])
    
    return result


def merge_whois_results(results: List[WhoisResult]) -> WhoisResult:
    """
    Merge multiple WHOIS results into a single result.
    
    This function takes multiple WHOIS results for the same IP address
    and merges them into a single result, preferring more complete information.
    
    Args:
        results: List of WHOIS results to merge
        
    Returns:
        Merged WHOIS result
    """
    if not results:
        return {}
    
    # Use the first result as the base
    merged = results[0].copy()
    
    # Track sources
    sources = [merged.get('source', 'unknown')]
    
    # Merge additional results
    for result in results[1:]:
        sources.append(result.get('source', 'unknown'))
        
        # Merge each field, preferring non-None values
        for key, value in result.items():
            # Skip source and raw fields
            if key in ('source', 'raw'):
                continue
                
            # Use the new value if the current value is None or empty
            if merged.get(key) is None or (merged.get(key) == '' and value):
                merged[key] = value
    
    # Update the source field
    merged['source'] = ', '.join(sources)
    
    return merged


def filter_valid_ips(ip_list: List[str]) -> List[str]:
    """
    Filter a list of IP addresses to only include valid ones.
    
    Args:
        ip_list: List of IP address strings
        
    Returns:
        List of valid IP addresses
    """
    valid_ips = []
    
    for ip in ip_list:
        if is_valid_ip(ip):
            valid_ips.append(ip)
        else:
            logger.warning(f"Skipping invalid IP address: {ip}")
    
    return valid_ips
