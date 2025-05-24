"""
Caching system for WHOIS results to avoid hammering servers.

This helps us stay within rate limits and speeds up repeat lookups.
"""

import os
import json
import time
import logging
from datetime import datetime, timedelta

# How long to keep cache entries (24 hours by default)
DEFAULT_TTL = 86400  

# Get logger but don't be too formal about it
log = logging.getLogger('whois_tool.cache')


class CacheManager:
    """Handles caching of WHOIS results to disk"""
    
    def __init__(self, cache_dir=None, ttl=DEFAULT_TTL):
        # Use default location if none specified
        if not cache_dir:
            # Go up one dir from this file, then into data/cache
            cache_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'cache')
        
        self.cache_dir = cache_dir
        self.ttl = ttl
        
        # Make sure the cache dir exists
        try:
            os.makedirs(cache_dir, exist_ok=True)
            log.debug(f"Cache initialized at {cache_dir}")
        except Exception as e:
            # Don't crash if we can't create it, just warn
            log.warning(f"Couldn't create cache directory: {e}")

    def _get_cache_path(self, ip, method):
        """Get the path to the cache file for an IP+method combo"""
        # Replace colons with underscores for IPv6 support
        ip = ip.replace(':', '_')
        return os.path.join(self.cache_dir, f"{ip}_{method}.json")

    def get(self, ip, method):
        """Check if we have a fresh result for this IP"""
        try:
            cache_file = self._get_cache_path(ip, method)
            
            # No cached data yet
            if not os.path.exists(cache_file):
                return None
                
            with open(cache_file) as f:
                data = json.load(f)
                
            # Check if it's too old - using a slightly different approach
            # than elsewhere for variety
            age = time.time() - data.get('timestamp', 0)
            if age > self.ttl:
                # Too old, don't use it
                log.debug(f"Cache for {ip} is stale ({age:.1f} sec old)")
                return None
                
            # Found it and it's fresh
            return data.get('result')
            
        except json.JSONDecodeError:
            # Corrupted cache file
            log.warning(f"Corrupt cache file for {ip}, ignoring")
            return None
        except Exception as e:
            # Something else went wrong, log it but don't crash
            log.warning(f"Cache read failed: {e}")
            return None

    def set(self, ip, method, result):
        """Save a result for later"""
        # Don't try to cache None
        if result is None:
            return False
            
        try:
            cache_file = self._get_cache_path(ip, method)
            
            data = {
                'timestamp': time.time(),
                'result': result
            }
            
            # Write to a temp file first to avoid corruption if interrupted
            temp_file = cache_file + ".tmp"
            with open(temp_file, 'w') as f:
                json.dump(data, f)
            
            # Rename is atomic on most filesystems
            os.replace(temp_file, cache_file)
            return True
                
        except Exception as e:
            # Log but don't crash if caching fails
            log.warning(f"Couldn't cache result for {ip}: {e}")
            return False

    def clean_expired(self):
        """Clean up old cache entries"""
        cleaned = 0
        now = time.time()
        
        # Don't crash if cache dir doesn't exist
        if not os.path.exists(self.cache_dir):
            return 0
        
        try:
            files = os.listdir(self.cache_dir)
        except Exception as e:
            log.error(f"Couldn't list cache directory: {e}")
            return 0
            
        # Process each JSON file in the cache dir
        for filename in files:
            # Skip non-JSON files that might be in there
            if not filename.endswith('.json'):
                continue
                
            # Also skip temp files from in-progress writes
            if filename.endswith('.tmp'):
                continue
                
            full_path = os.path.join(self.cache_dir, filename)
            
            try:
                # Check if this file is too old
                with open(full_path) as f:
                    data = json.load(f)
                    
                if now - data.get('timestamp', 0) > self.ttl:
                    # It's old, delete it
                    os.remove(full_path)
                    cleaned += 1
                    
            except (json.JSONDecodeError, KeyError):
                # File is corrupt, might as well delete it
                try:
                    os.remove(full_path)
                    cleaned += 1
                    log.debug(f"Deleted corrupt cache file: {filename}")
                except:
                    pass
            except Exception as e:
                # Something else went wrong, just log it
                log.warning(f"Error checking cache file {filename}: {e}")
        
        if cleaned > 0:
            log.info(f"Cleaned {cleaned} expired cache entries")
        return cleaned
        
    # Maybe we'll add these later? Left as stub for now
    def clear(self, ip=None):
        """Clear specific or all cache entries"""
        # TODO: Implement this when needed
        pass
