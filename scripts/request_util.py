#!/usr/bin/env python3
"""
HTTP Request Utility
Advanced HTTP request handling for security testing
"""

import requests
import json
import urllib.parse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RequestUtil:
    """HTTP Request utility class"""
    
    def __init__(self, proxy=None, timeout=10, retries=3, user_agent=None):
        self.session = requests.Session()
        self.timeout = timeout
        
        # Set User-Agent
        if user_agent:
            self.session.headers['User-Agent'] = user_agent
        else:
            self.session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Set proxy
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Configure retries
        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def get(self, url, params=None, headers=None, cookies=None):
        """Send GET request"""
        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                cookies=cookies,
                timeout=self.timeout
            )
            return self._parse_response(response)
        except Exception as e:
            return {'error': str(e)}
    
    def post(self, url, data=None, json_data=None, headers=None, cookies=None):
        """Send POST request"""
        try:
            if json_data:
                headers = headers or {}
                headers['Content-Type'] = 'application/json'
            
            response = self.session.post(
                url,
                data=data,
                json=json_data,
                headers=headers,
                cookies=cookies,
                timeout=self.timeout
            )
            return self._parse_response(response)
        except Exception as e:
            return {'error': str(e)}
    
    def put(self, url, data=None, headers=None, cookies=None):
        """Send PUT request"""
        try:
            response = self.session.put(
                url,
                data=data,
                headers=headers,
                cookies=cookies,
                timeout=self.timeout
            )
            return self._parse_response(response)
        except Exception as e:
            return {'error': str(e)}
    
    def delete(self, url, headers=None, cookies=None):
        """Send DELETE request"""
        try:
            response = self.session.delete(
                url,
                headers=headers,
                cookies=cookies,
                timeout=self.timeout
            )
            return self._parse_response(response)
        except Exception as e:
            return {'error': str(e)}
    
    def _parse_response(self, response):
        """Parse response into dictionary"""
        result = {
            'status_code': response.status_code,
            'url': response.url,
            'headers': dict(response.headers),
            'cookies': dict(response.cookies),
            'content_length': len(response.content),
            'text': response.text,
            'encoding': response.encoding,
        }
        
        # Try to parse JSON
        try:
            result['json'] = response.json()
        except:
            result['json'] = None
        
        return result
    
    def set_header(self, key, value):
        """Set custom header"""
        self.session.headers[key] = value
    
    def remove_header(self, key):
        """Remove header"""
        if key in self.session.headers:
            del self.session.headers[key]
    
    def set_cookie(self, name, value):
        """Set cookie"""
        self.session.cookies.set(name, value)
    
    def clear_cookies(self):
        """Clear all cookies"""
        self.session.cookies.clear()


def build_url(base_url, path=None, params=None):
    """Build URL with path and parameters"""
    url = base_url
    
    if path:
        url = urllib.parse.urljoin(url, path)
    
    if params:
        query = urllib.parse.urlencode(params)
        url = f"{url}?{query}"
    
    return url


def parse_url(url):
    """Parse URL into components"""
    parsed = urllib.parse.urlparse(url)
    return {
        'scheme': parsed.scheme,
        'netloc': parsed.netloc,
        'path': parsed.path,
        'params': parsed.params,
        'query': parsed.query,
        'fragment': parsed.fragment,
        'hostname': parsed.hostname,
        'port': parsed.port,
    }


def encode_params(params):
    """URL encode parameters"""
    return urllib.parse.urlencode(params)


def decode_params(query_string):
    """URL decode parameters"""
    return urllib.parse.parse_qs(query_string)


if __name__ == "__main__":
    # Example usage
    util = RequestUtil()
    
    # Test request
    result = util.get("https://httpbin.org/get")
    print(json.dumps(result['json'], indent=2))
