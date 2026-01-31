from urllib.robotparser import RobotFileParser
from urllib.parse import urljoin, urlparse
import requests
from .utils import fetch_url


def scan_check(url: str, session: requests.Session) -> bool:
    """
    Check if scanning is allowed according to robots.txt
    """
    parsed_url = urlparse(url)
    robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"

    try:
        rp = RobotFileParser()
        response = fetch_url(session, robots_url, timeout=5, allow_redirects=True)

        if response and response.status_code == 200:
            rp.parse(response.text.splitlines())
        else:
            print(f"robots.txt not found ({getattr(response, 'status_code', 'No response')}) → allowing scan")
            return True

    except Exception as e:
        print(f"robots.txt check failed ({e}) → allowing scan")
        return True

    allowed = rp.can_fetch('*', url)
    print(f"robots.txt: {'ALLOW' if allowed else 'DISALLOW'}")
    return allowed
