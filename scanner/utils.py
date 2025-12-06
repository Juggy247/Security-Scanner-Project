import requests
from urllib.parse import urlparse

def session_get():
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'SecurityScanner/1.0 (Educational)'
    })
    return session

def fetch_url(session, url, timeout=10, allow_redirects=True):
    return session.get(url, timeout=timeout, allow_redirects = allow_redirects)