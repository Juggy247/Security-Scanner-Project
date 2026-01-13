import requests
from typing import Optional
from urllib.parse import urlparse

def session_get() -> requests.Session:
    """
        We try to create and configure a request session with headers
        and return request.Session object
    """
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'SecurityScanner/1.0 (Educational)'
    })
    return session

def fetch_url(session, url, timeout=10, allow_redirects=True):
    try: 
        response = session.get(url, timeout=timeout, allow_redirects = allow_redirects)
        return response
    except requests.RequestException as e: 
        print(f"Error fetching {url}: {e}")
        return None 