"""
Utility functions for IOC Enrichment Tool
"""

import re
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any, Optional
import json
import os
from pathlib import Path

from config import IOC_TYPES, CACHE, RATE_LIMITS, LOGGING

# Setup logging
logging.basicConfig(
    level=getattr(logging, LOGGING['level']),
    format=LOGGING['format'],
    filename=LOGGING['file']
)
logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter for API calls"""
    def __init__(self, calls_per_minute: int):
        self.calls_per_minute = calls_per_minute
        self.calls = []
    
    def wait_if_needed(self):
        now = time.time()
        # Remove calls older than 1 minute
        self.calls = [call for call in self.calls if now - call < 60]
        
        if len(self.calls) >= self.calls_per_minute:
            sleep_time = 60 - (now - self.calls[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.calls = self.calls[1:]
        
        self.calls.append(now)

class Cache:
    """Simple file-based cache implementation"""
    def __init__(self, cache_dir: str = ".cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if not CACHE['enabled']:
            return None
            
        cache_file = self.cache_dir / f"{key}.json"
        if not cache_file.exists():
            return None
            
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                if datetime.fromisoformat(data['timestamp']) + timedelta(seconds=CACHE['ttl']) < datetime.now():
                    cache_file.unlink()
                    return None
                return data['value']
        except Exception as e:
            logger.error(f"Cache read error: {e}")
            return None
    
    def set(self, key: str, value: Dict[str, Any]):
        if not CACHE['enabled']:
            return
            
        try:
            cache_file = self.cache_dir / f"{key}.json"
            with open(cache_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'value': value
                }, f)
        except Exception as e:
            logger.error(f"Cache write error: {e}")

def validate_ioc(ioc: str) -> Optional[str]:
    """Validate IOC and return its type"""
    for ioc_type, pattern in IOC_TYPES.items():
        if re.match(pattern, ioc, re.IGNORECASE):
            return ioc_type
    return None

def rate_limit(api_name: str):
    """Decorator for rate limiting API calls"""
    limiter = RateLimiter(RATE_LIMITS[api_name])
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter.wait_if_needed()
            return func(*args, **kwargs)
        return wrapper
    return decorator

def cache_result(func):
    """Decorator for caching function results"""
    cache = Cache()
    
    @wraps(func)
    def wrapper(ioc: str, *args, **kwargs):
        if not CACHE['enabled']:
            return func(ioc, *args, **kwargs)
            
        cached_result = cache.get(ioc)
        if cached_result is not None:
            logger.info(f"Cache hit for {ioc}")
            return cached_result
            
        result = func(ioc, *args, **kwargs)
        cache.set(ioc, result)
        return result
    return wrapper

def calculate_freshness_score(last_seen: datetime) -> float:
    """Calculate freshness score based on last seen timestamp"""
    age = datetime.now() - last_seen
    
    if age < timedelta(hours=24):
        return 10
    elif age < timedelta(days=7):
        return 5
    elif age > timedelta(days=30):
        return -5
    return 0

def format_stix_output(data: Dict[str, Any]) -> Dict[str, Any]:
    """Format data according to STIX 2.1 standard"""
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{data['IOC']}",
        "created": datetime.now().isoformat(),
        "modified": datetime.now().isoformat(),
        "name": f"IOC Analysis: {data['IOC']}",
        "description": f"Threat analysis for {data['IOC']}",
        "pattern": f"[{data['IOC']}]",
        "pattern_type": "stix",
        "valid_from": datetime.now().isoformat(),
        "confidence": data.get('confidence', 50),
        "severity": data.get('Risk Level', 'unknown').lower(),
        "labels": data.get('Tags', '').split(', '),
        "external_references": [
            {
                "source_name": source,
                "url": url
            } for source, url in data.get('references', {}).items()
        ]
    }

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to be safe for all operating systems"""
    return re.sub(r'[<>:"/\\|?*]', '_', filename) 