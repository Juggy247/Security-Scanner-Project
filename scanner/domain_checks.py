import whois
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import re
from bs4 import BeautifulSoup

from .config import MongoDbConfig

#start conncection
_db_config = None

def get_db_config() -> MongoDbConfig:
    
    global _db_config
    if _db_config is None:
        _db_config = MongoDbConfig()
    return _db_config

def check_domain_age(domain: str) -> Dict[str, Any]:
    
    try:
        # Remove 'www.' prefix 
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        
        print(f"    📅 Looking up WHOIS for: {domain}")
        
        # Perform WHOIS lookup
        w = whois.whois(domain)
        
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        
        if not creation_date:
            print(f"No creation date found in WHOIS data")
            return {
                "available": False,
                "error": "Creation date not available in WHOIS data",
                "note": "Domain may use WHOIS privacy protection"
            }
        
        # Calculate age
        age = datetime.now() - creation_date
        days_old = age.days
        
        is_new = days_old < 180
        is_very_new = days_old < 30
        
        print(f"Domain age: {days_old} days")
        
        return {
            "available": True,
            "creation_date": str(creation_date),
            "days_old": days_old,
            "years_old": round(days_old / 365.25, 1),
            "is_new": is_new,
            "is_very_new": is_very_new,
            "age_category": (
                "Very New (High Risk)" if is_very_new
                else "New (Medium Risk)" if is_new
                else "Established (Low Risk)"
            )
        }
    
    except whois.parser.PywhoisError as e:
        print(f"WHOIS parsing error: {str(e)[:50]}")
        return {
            "available": False,
            "error": f"WHOIS parsing error: {str(e)[:100]}",
            "note": "Unable to parse WHOIS data for this domain"
        }
    
    except Exception as e:
        error_msg = str(e)
        print(f"WHOIS lookup failed: {error_msg[:50]}")
        
        if "timed out" in error_msg.lower():
            return {
                "available": False,
                "error": "WHOIS server timeout",
                "note": "Try again or WHOIS server may be temporarily unavailable"
            }
        elif "no match" in error_msg.lower():
            return {
                "available": False,
                "error": "Domain not found in WHOIS",
                "note": "Domain may not be registered or uses non-standard WHOIS"
            }
        else:
            return {
                "available": False,
                "error": f"WHOIS lookup failed: {error_msg[:100]}",
                "note": "Check network connection or domain validity"
            }

def check_blacklist(domain: str) -> Dict[str, Any]:
    
    try:
        db = get_db_config()
        is_blacklisted = db.is_blacklisted(domain)
        
        return {
            "is_blacklisted": is_blacklisted,
            "blacklist_sources": ["mongodb_database"] if is_blacklisted else [],
        }
    except Exception as e:
        print(f"Blacklist check failed: {e}")
       
        return {
            "is_blacklisted": False,
            "blacklist_sources": [],
            "error": str(e)
        }

def check_homograph_attack(domain: str) -> Dict[str, Any]:
   
    suspicious_patterns = []
    
    lookalike_pairs = {
        'rn': 'm', 
        'vv': 'w',  
        'cl': 'd',  
        '0': 'o',   
        '1': 'l',   
    }
    
    for fake, real in lookalike_pairs.items():
        if fake in domain.lower():
            suspicious_patterns.append(f"Contains '{fake}' (looks like '{real}')")
    
    # Check for mixed scripts
    has_cyrillic = bool(re.search(r'[а-яА-Я]', domain))
    has_latin = bool(re.search(r'[a-zA-Z]', domain))
    
    if has_cyrillic and has_latin:
        suspicious_patterns.append("Mixed Latin and Cyrillic characters")
    
    # Check for excessive hyphens
    hyphen_count = domain.count('-')
    if hyphen_count > 3:
        suspicious_patterns.append(f"Excessive hyphens ({hyphen_count})")
    
    # Check for non-ASCII characters
    if not domain.isascii():
        suspicious_patterns.append("Contains non-ASCII characters ")
    
    return {
        "is_suspicious": len(suspicious_patterns) > 0,
        "patterns_found": suspicious_patterns,
        "domain": domain
    }

def check_domain_in_title(domain: str, title: str) -> Dict[str, Any]:
    
    if not title:
        return {
            "domain_in_title": False,
            "reason": "No title found"
        }
    
    # Extract main domain without TLD
    domain_parts = domain.split('.')
    main_domain = domain_parts[0] if len(domain_parts) > 1 else domain
    
    # Remove common subdomains
    if main_domain in ['www', 'www2', 'mail', 'ftp', 'webmail']:
        main_domain = domain_parts[1] if len(domain_parts) > 2 else main_domain
    
    # Check if domain appears in title (case insensitive)
    domain_in_title = main_domain.lower() in title.lower()
    
    return {
        "domain_in_title": domain_in_title,
        "domain_checked": main_domain,
        "title": title
    }


def check_form_redirects(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    
    from urllib.parse import urljoin
    
    base_domain = urlparse(base_url).netloc
    forms = soup.find_all('form')
    suspicious_forms = []
    
    for i, form in enumerate(forms):
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        
        # Resolve relative URLs
        action_url = urljoin(base_url, action)
        action_domain = urlparse(action_url).netloc
        
        # Check if form redirects to external domain
        if action_domain and action_domain != base_domain:
            suspicious_forms.append({
                "form_index": i,
                "method": method,
                "action": action_url,
                "redirects_external": True,
                "external_domain": action_domain,
                "base_domain": base_domain
            })
    
    return suspicious_forms


def check_domain_length(domain: str) -> Dict[str, Any]:
    
    # Remove TLD for length check
    domain_without_tld = '.'.join(domain.split('.')[:-1])
    length = len(domain_without_tld)
    
    if length > 30:
        risk_level = "very_high"
        is_suspicious = True
    elif length > 20:
        risk_level = "high"
        is_suspicious = True
    elif length > 15:
        risk_level = "medium"
        is_suspicious = False
    else:
        risk_level = "low"
        is_suspicious = False
    
    return {
        "length": length,
        "full_domain_length": len(domain),
        "is_suspicious": is_suspicious,
        "risk_level": risk_level
    }


def check_suspicious_tld(domain: str) -> Dict[str, Any]:
   
    try:
        tld = domain.split('.')[-1].lower()
        
        db = get_db_config()
        suspicious_tlds = db.get_suspicious_tlds()
        
        is_suspicious = tld in suspicious_tlds
        
        # Get details if suspicious
        details = None
        if is_suspicious:
            details = db.get_tld_details(tld)
        
        return {
            "tld": tld,
            "is_suspicious": is_suspicious,
            "reason": details.get('reason') if details else None,
            "risk_level": details.get('risk_level') if details else None
        }
    except Exception as e:
        print(f"TLD check failed: {e}")
        
        tld = domain.split('.')[-1].lower()
        return {
            "tld": tld,
            "is_suspicious": False,
            "error": str(e)
        }

def check_subdomain_depth(domain: str) -> Dict[str, Any]:

    parts = domain.split('.')
    
    depth = len(parts) - 2 
    is_suspicious = depth > 2
    
    return {
        "depth": depth,
        "parts": parts,
        "is_suspicious": is_suspicious,
        "full_domain": domain
    }

def check_brand_impersonation(domain: str) -> Dict[str, Any]:

    try:
        domain_lower = domain.lower()
        
        db = get_db_config()
        
        # Get brands from MongoDB
        brands = db.get_brands()
        found_brands = [brand for brand in brands if brand in domain_lower]
        
        if not found_brands:
            return {
                "potential_impersonation": False
            }
        
        keywords = db.get_suspicious_keywords()
        found_suspicious = [kw for kw in keywords if kw in domain_lower]
        
        potential_impersonation = len(found_brands) > 0 and len(found_suspicious) > 0
        

        return {
            "potential_impersonation": potential_impersonation,
            "suspected_brand": found_brands[0] if found_brands else None,
            "suspicious_keywords": found_suspicious,
            "domain": domain
        }
    except Exception as e:
        print(f"Brand impersonation check failed: {e}")
        
        return {
            "potential_impersonation": False,
            "error": str(e)
        }


def close_db_connection():
    
    global _db_config
    if _db_config is not None:
        _db_config.close()
        _db_config = None
        print("MongoDB connection closed")


