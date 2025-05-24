"""
Core engine for IP WHOIS lookups.

Handles the orchestration of lookups, caching, and fallback mechanisms.
"""

import logging
import time
import concurrent.futures
from typing import List, Dict, Any, Optional, Union

from .util import WhoisResult, filter_valid_ips, merge_whois_results
from .cache import CacheManager
from .resolvers import get_resolver_by_method, BaseResolver

# TODO: Add async support in the future

logger = logging.getLogger('whois_tool.engine')


class WhoisEngine:
    """Main engine that coordinates WHOIS lookups and caching"""
    
    def __init__(
        self,
        lookup_method='auto',
        use_cache=True,
        timeout=None,
        rate_limit=1.0,
        max_retries=2
    ):
        """Sets up the engine with the given configuration"""
        self.lookup_method = lookup_method
        self.use_cache = use_cache
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        
        # Cache manager - only initialize if caching is enabled
        # (saves memory and prevents unnecessary directory creation)
        self.cache = None
        if use_cache:
            self.cache = CacheManager()
        
        # Log config at startup - helps with debugging
        logger.debug(f"Engine started: {lookup_method=}, {use_cache=}, {timeout=}")
        
        # FIXME: Currently using a fixed rate limit for all resolvers
        # Should probably be configurable per resolver type
    
    def lookup_ip(self, ip):
        """Look up WHOIS info for a single IP address"""
        # First check if we've seen this IP before
        if self.use_cache and self.cache:
            cached = self.cache.get(ip, self.lookup_method)
            if cached:
                logger.debug(f"Found {ip} in cache 🎯")
                return cached
            
        # Didn't find it in cache, need to do the lookup
        logger.debug(f"Cache miss for {ip}, looking it up")
        
        # Get the right resolver(s)
        resolvers = get_resolver_by_method(self.lookup_method, rate_limit=self.rate_limit)
        if not isinstance(resolvers, list):
            resolvers = [resolvers]  # Make sure we have a list to iterate
            
        # Will store our successes and failures here
        results = []
        errors = []
        
        # Try resolvers until we get a hit
        for resolver in resolvers:
            try:
                # The actual lookup happens here
                logger.info(f"Trying {resolver.name} for {ip}")
                result = resolver.lookup(ip, self.timeout, self.max_retries)
                results.append(result)
                
                # In non-auto mode, we only try one resolver
                if self.lookup_method != 'auto':
                    break
                    
            except ValueError as e:
                # Something went wrong, log it and maybe try another resolver
                errors.append(str(e))
                logger.warning(f"{resolver.name} failed on {ip}: {e}")
                
                # In non-auto mode, show the error
                if self.lookup_method != 'auto':
                    # Add some context to the error
                    raise ValueError(f"Lookup with {resolver.name} failed: {e}")
        
        if not results:
            # We tried everything and nothing worked
            # AKA f.t.s.i.o.
            err = '; '.join(errors)
            logger.error(f"No joy for {ip} - all methods failed: {err}")
            raise ValueError(f"All lookup methods failed for {ip}")
        
        # We might have multiple results to combine
        if len(results) > 1:
            # This happens in auto mode when multiple resolvers work
            logger.debug(f"Got {len(results)} results for {ip}, merging them")
            final_result = merge_whois_results(results)
        else:
            # Just one result, use it directly
            final_result = results[0]
        
        # Save for next time
        if self.use_cache and self.cache:
            self.cache.set(ip, self.lookup_method, final_result)
        
        return final_result
    
    def process_ips(self, ips, parallel=True, max_workers=8):
        """Process multiple IP addresses, with optional parallelization"""
        # Make sure we only process valid IPs
        valid_ips = filter_valid_ips(ips)
        
        # Bail early if nothing to do
        if not valid_ips:
            logger.warning("Found no valid IPs to process!")
            return []
        
        # Let us know what we're doing
        mode = "parallel" if parallel and len(valid_ips) > 1 else "sequential"
        logger.info(f"Processing {len(valid_ips)} IPs in {mode} mode")
        
        results = []
        errors = []  # Keep track of failures
        
        # Process differently based on parallel flag
        if parallel and len(valid_ips) > 1:
            # Fancy concurrent processing for multiple IPs
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Map IPs to futures
                futures = {}
                for ip in valid_ips:
                    futures[executor.submit(self.lookup_ip, ip)] = ip
                
                # Collect results as they finish
                for future in concurrent.futures.as_completed(futures):
                    ip = futures[future]
                    try:
                        # Get the result or exception
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        # Something went wrong with this IP
                        errors.append((ip, str(e)))
                        logger.error(f"Couldn't look up {ip}: {e}")
        else:
            # Simple sequential processing - good for small batches
            # or when debugging threading issues
            for ip in valid_ips:
                try:
                    result = self.lookup_ip(ip)
                    results.append(result)
                except Exception as e:
                    errors.append((ip, str(e)))
                    logger.error(f"Failed to process {ip}: {e}")
        
        # Print a little summary
        if results:
            logger.info(f"Successfully processed {len(results)} IPs")
            
        if errors:
            # Build a nice error message
            err_ips = [ip for ip, _ in errors]
            err_count = len(errors)
            
            if err_count == 1:
                logger.warning(f"Failed to process {err_ips[0]}")
            elif err_count <= 3:
                logger.warning(f"Failed to process {err_count} IPs: {', '.join(err_ips)}")
            else:
                # Don't list them all if there are too many
                logger.warning(f"Failed to process {err_count} IPs")
        
        return results
    
    def clean_cache(self) -> int:
        """
        Clean expired cache entries.
        
        Returns:
            Number of cache entries cleaned
        """
        if not self.use_cache or not self.cache:
            logger.warning("Cache is disabled, cannot clean")
            return 0
        
        logger.debug("Cleaning expired cache entries")
        return self.cache.clean_expired()

