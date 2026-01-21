"""
Intelligent DNS Error Handling & Caching System

Features:
1. Distinguishes between different error types
2. User-friendly error messages with retry options
3. Smart caching with TTL respect
4. Cache invalidation on demand
5. Performance metrics
"""

import dns.resolver
import dns.exception
import time
from typing import Dict, Optional, Any
from datetime import datetime, timedelta

class DNSCache:
    """Smart DNS cache with TTL respect"""
    
    def __init__(self, default_ttl: int = 300):
        self.cache = {}
        self.default_ttl = default_ttl
        self.stats = {'hits': 0, 'misses': 0, 'refreshes': 0}
    
    def _make_key(self, domain: str, record_type: str) -> str:
        return f"{domain.lower()}:{record_type}"
    
    def get(self, domain: str, record_type: str) -> Optional[Dict]:
        key = self._make_key(domain, record_type)
        
        if key not in self.cache:
            self.stats['misses'] += 1
            return None
        
        cached = self.cache[key]
        
        # Check expiration
        if datetime.now() > cached['expires_at']:
            del self.cache[key]
            self.stats['misses'] += 1
            return None
        
        self.stats['hits'] += 1
        return cached
    
    def set(self, domain: str, record_type: str, result: Any, 
            ttl: Optional[int] = None, error: bool = False):
        key = self._make_key(domain, record_type)
        
        if ttl is None:
            ttl = self.default_ttl
        
        self.cache[key] = {
            'result': result,
            'cached_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(seconds=ttl),
            'ttl': ttl,
            'error': error
        }
    
    def invalidate(self, domain: str, record_type: Optional[str] = None):
        if record_type:
            key = self._make_key(domain, record_type)
            if key in self.cache:
                del self.cache[key]
                self.stats['refreshes'] += 1
        else:
            keys = [k for k in self.cache.keys() if k.startswith(f"{domain.lower()}:")]
            for key in keys:
                del self.cache[key]
                self.stats['refreshes'] += 1
    
    def get_stats(self) -> Dict:
        total = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0
        return {
            **self.stats,
            'total_queries': total,
            'hit_rate': round(hit_rate, 1),
            'cached_entries': len(self.cache)
        }


class DNSErrorHandler:
    """Intelligent DNS error classification"""
    
    ERROR_TYPES = {
        'NXDOMAIN': {
            'severity': 'info',
            'icon': 'ℹ️',
            'message': 'Record does not exist',
            'user_message': 'No {record_type} record found',
            'is_error': False,
            'retry_recommended': False
        },
        'TIMEOUT': {
            'severity': 'warning',
            'icon': '⚠️',
            'message': 'DNS query timed out',
            'user_message': 'DNS server took too long to respond',
            'is_error': True,
            'retry_recommended': True
        },
        'NO_NAMESERVER': {
            'severity': 'error',
            'icon': '❌',
            'message': 'No nameservers available',
            'user_message': 'Domain has no working nameservers',
            'is_error': True,
            'retry_recommended': False
        },
        'SERVFAIL': {
            'severity': 'error',
            'icon': '❌',
            'message': 'DNS server failure',
            'user_message': 'DNS server encountered an error',
            'is_error': True,
            'retry_recommended': True
        },
        'REFUSED': {
            'severity': 'error',
            'icon': '❌',
            'message': 'DNS server refused query',
            'user_message': 'DNS server refused to answer',
            'is_error': True,
            'retry_recommended': True
        },
        'NO_ANSWER': {
            'severity': 'info',
            'icon': 'ℹ️',
            'message': 'No answer in response',
            'user_message': 'DNS responded but provided no data',
            'is_error': False,
            'retry_recommended': False
        }
    }
    
    @staticmethod
    def classify_error(exception: Exception) -> str:
        if isinstance(exception, dns.resolver.NXDOMAIN):
            return 'NXDOMAIN'
        elif isinstance(exception, dns.resolver.Timeout):
            return 'TIMEOUT'
        elif isinstance(exception, dns.resolver.NoNameservers):
            return 'NO_NAMESERVER'
        elif isinstance(exception, dns.resolver.NoAnswer):
            return 'NO_ANSWER'
        elif 'SERVFAIL' in str(exception):
            return 'SERVFAIL'
        elif 'REFUSED' in str(exception):
            return 'REFUSED'
        else:
            return 'TIMEOUT'
    
    @classmethod
    def get_error_info(cls, error_type: str, record_type: str = '') -> Dict:
        error_info = cls.ERROR_TYPES.get(error_type, cls.ERROR_TYPES['TIMEOUT'])
        user_message = error_info['user_message'].format(record_type=record_type)
        return {**error_info, 'error_type': error_type, 'user_message': user_message}


class SmartDNSResolver:
    """DNS resolver with caching and error handling"""
    
    def __init__(self, cache_ttl: int = 300, timeout: int = 5):
        self.cache = DNSCache(default_ttl=cache_ttl)
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def query(self, domain: str, record_type: str, 
              use_cache: bool = True, retry: bool = False) -> Dict:
        start_time = time.time()
        
        # Check cache
        if use_cache and not retry:
            cached = self.cache.get(domain, record_type)
            if cached:
                return {
                    'success': not cached['error'],
                    'records': cached['result'] if not cached['error'] else None,
                    'error': cached['result'] if cached['error'] else None,
                    'cached': True,
                    'query_time': time.time() - start_time,
                    'ttl': cached['ttl'],
                    'cache_age': (datetime.now() - cached['cached_at']).seconds
                }
        
        # Perform query
        try:
            answers = self.resolver.resolve(domain, record_type)
            records = [str(rdata).strip('"') for rdata in answers]
            ttl = answers.rrset.ttl if answers.rrset else self.cache.default_ttl
            
            self.cache.set(domain, record_type, records, ttl=ttl, error=False)
            
            return {
                'success': True,
                'records': records,
                'error': None,
                'cached': False,
                'query_time': time.time() - start_time,
                'ttl': ttl
            }
            
        except Exception as e:
            error_type = DNSErrorHandler.classify_error(e)
            error_info = DNSErrorHandler.get_error_info(error_type, record_type)
            
            error_ttl = 60 if error_info['retry_recommended'] else 300
            self.cache.set(domain, record_type, error_info, ttl=error_ttl, error=True)
            
            return {
                'success': False,
                'records': None,
                'error': error_info,
                'cached': False,
                'query_time': time.time() - start_time,
                'ttl': error_ttl
            }
    
    def invalidate_cache(self, domain: str, record_type: Optional[str] = None):
        self.cache.invalidate(domain, record_type)
    
    def get_cache_stats(self) -> Dict:
        return self.cache.get_stats()


# Example
if __name__ == "__main__":
    resolver = SmartDNSResolver()
    
    result = resolver.query("google.com", "TXT")
    print(f"Success: {result['success']}")
    print(f"Cached: {result['cached']}")
    print(f"Query time: {result['query_time']*1000:.0f}ms")
    
    if result['success']:
        print(f"Records: {len(result['records'])}")
    else:
        print(f"Error: {result['error']['user_message']}")
