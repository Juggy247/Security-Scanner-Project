import requests
from typing import Optional
from urllib.parse import urlparse


def session_get() -> requests.Session:
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'SecurityScanner/1.0 (Educational)'
    })
    return session


def fetch_url(session, url, timeout=10, allow_redirects=True, verify=False):
    """
    Fetch URL with error handling for malicious sites.
    Args:
        verify: Set False to allow invalid SSL certificates
    """
    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify  # Allow invalid SSL
        )
        return response

    except requests.exceptions.Timeout:
        print(f"  Timeout fetching {url}")
        return None

    except requests.exceptions.ConnectionError:
        print(f"  Connection error to {url}")
        return None

    except requests.exceptions.SSLError:
        print("  SSL error (retrying without verification)...")
        try:
            # Retry without SSL verification
            return session.get(
                url,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False
            )
        except Exception:
            return None

    except requests.RequestException as e:
        print(f"  Error fetching {url}: {e}")
        return None
