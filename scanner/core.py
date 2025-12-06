from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from bs4 import BeautifulSoup
from .robots import scan_check
from .security import (
    check_https_final, check_ssl, check_headers, check_forms
)
from .domain_checks import (
    check_domain_age, check_blacklist, check_homograph_attack,
    check_domain_in_title, check_form_redirects, check_domain_length,
    check_suspicious_tld, check_subdomain_depth, check_brand_impersonation
)
from .utils import session_get, fetch_url

def create_issue(issue_type: str, description: str, risk: str, severity: str) -> Dict[str, str]:
    """Create an issue dictionary"""
    return {
        'type': issue_type,
        'description': description,
        'risk': risk,
        'severity': severity
    }


@dataclass
class ScanReport:
    url: str
    success: bool
    error: Optional[str] = None
    robots_allowed: bool = False
    robots_bypassed: bool = False
    https: dict = None
    ssl: dict = None
    headers: dict = None
    forms: list = field(default_factory=list)
    title: str = None

    # Domain security checks
    domain_age: dict = None
    blacklist: dict = None 
    homograph: dict = None 
    domain_in_title: dict = None
    form_redirects: list = field(default_factory=list)
    domain_length: dict = None 
    suspicious_tld: dict = None 
    subdomain_depth: dict = None
    brand_impersonation: dict = None
    
    def _check_https_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.https and not self.https.get('https_enforced'):
            issues.append(create_issue(
                issue_type="No HTTPS",
                description="Website does not use HTTPS encryption",
                risk="Data transmitted in plain text can be intercepted",
                severity="critical"
            ))
        
        return issues
    
    def _check_ssl_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.ssl and not self.ssl.get('valid'):
            issues.append(create_issue(
                issue_type="Invalid SSL Certificate",
                description=f"SSL certificate is not valid: {self.ssl.get('error', 'Unknown error')}",
                risk="Cannot verify website identity",
                severity="critical"
            ))
        
        return issues
    
    def _check_blacklist_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.blacklist and self.blacklist.get('is_blacklisted'):
            issues.append(create_issue(
                issue_type="Blacklisted Domain",
                description="Domain appears in malicious site databases",
                risk="Known malicious or phishing site",
                severity="critical"
            ))
        
        return issues
    
    def _check_homograph_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.homograph and self.homograph.get('is_suspicious'):
            patterns = ", ".join(self.homograph.get('patterns_found', []))
            issues.append(create_issue(
                issue_type="Homograph Attack",
                description=f"Suspicious characters detected: {patterns}",
                risk="Domain may be impersonating legitimate site",
                severity="critical"
            ))
        
        return issues
    
    def _check_form_redirect_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.form_redirects:
            for form in self.form_redirects:
                if form.get('redirects_external'):
                    issues.append(create_issue(
                        issue_type="External Form Redirect",
                        description=f"Form submits to external domain: {form.get('external_domain')}",
                        risk="Your data may be sent to malicious third party",
                        severity="critical"
                    ))
                    break  # Only report once
        
        return issues
    
    def _check_brand_impersonation_issues(self) -> List[Dict[str, str]]:
       
        issues = []
        
        if self.brand_impersonation and self.brand_impersonation.get('potential_impersonation'):
            brand = self.brand_impersonation.get('suspected_brand')
            keywords = ", ".join(self.brand_impersonation.get('suspicious_keywords', []))
            issues.append(create_issue(
                issue_type="Potential Brand Impersonation",
                description=f"Domain contains '{brand}' with suspicious keywords: {keywords}",
                risk="May be fake site impersonating legitimate brand",
                severity="high"
            ))
        
        return issues
    
    def _check_tld_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.suspicious_tld and self.suspicious_tld.get('is_suspicious'):
            tld = self.suspicious_tld.get('tld')
            issues.append(create_issue(
                issue_type="Suspicious TLD",
                description=f"Domain uses high-risk TLD: .{tld}",
                risk="TLD commonly used in phishing attacks",
                severity="high"
            ))
        
        return issues
    
    def _check_domain_length_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.domain_length and self.domain_length.get('is_suspicious'):
            length = self.domain_length.get('length')
            issues.append(create_issue(
                issue_type="Suspicious Domain Length",
                description=f"Domain is unusually long ({length} characters)",
                risk="Phishing sites often use long domains to hide real intent",
                severity="high"
            ))
        
        return issues
    
    def _check_domain_age_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.domain_age and self.domain_age.get('is_new'):
            days = self.domain_age.get('days_old')
            issues.append(create_issue(
                issue_type="Recently Registered Domain",
                description=f"Domain registered only {days} days ago",
                risk="New domains are higher risk for scams",
                severity="medium"
            ))
        elif self.domain_age and not self.domain_age.get('available'):
            issues.append(create_issue(
                issue_type="Domain Age Unknown",
                description="Cannot verify when domain was registered",
                risk="Unable to assess domain history",
                severity="medium"
            ))
        
        return issues
    
    def _check_domain_title_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.domain_in_title and not self.domain_in_title.get('domain_in_title'):
            issues.append(create_issue(
                issue_type="Domain Not in Page Title",
                description="Website's domain name doesn't appear in page title",
                risk="Legitimate sites usually include their name in the title",
                severity="medium"
            ))
        
        return issues
    
    def _check_subdomain_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.subdomain_depth and self.subdomain_depth.get('is_suspicious'):
            depth = self.subdomain_depth.get('depth')
            issues.append(create_issue(
                issue_type="Deep Subdomain Nesting",
                description=f"Domain has {depth} levels of subdomains",
                risk="Phishing sites often use subdomains to appear legitimate",
                severity="medium"
            ))
        
        return issues
    
    def _check_form_security_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.forms:
            form_count = len(self.forms)
            issues.append(create_issue(
                issue_type="Insecure Forms",
                description=f"Found {form_count} form(s) with security issues",
                risk="Forms may transmit data insecurely",
                severity="medium"
            ))
        
        return issues
    
    def _check_security_header_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if self.headers:
            missing = self.headers.get('missing', [])
            if missing:
                issues.append(create_issue(
                    issue_type="Missing Security Headers",
                    description=f"Missing {len(missing)} security header(s): {', '.join(missing[:3])}",
                    risk="Reduced protection against attacks",
                    severity="low"
                ))
        
        return issues
    
    def _check_robots_issues(self) -> List[Dict[str, str]]:
        
        issues = []
        
        if not self.robots_allowed and self.robots_bypassed:
            issues.append(create_issue(
                issue_type="Robots.txt Restriction",
                description="Site blocks automated scanning",
                risk="May be hiding from search engines",
                severity="low"
            ))
        
        return issues
    
    def _collect_all_issues(self) -> Dict[str, List[Dict[str, str]]]:
        
        all_issues = []
        
        # Run all check methods
        check_methods = [
            self._check_https_issues,
            self._check_ssl_issues,
            self._check_blacklist_issues,
            self._check_homograph_issues,
            self._check_form_redirect_issues,
            self._check_brand_impersonation_issues,
            self._check_tld_issues,
            self._check_domain_length_issues,
            self._check_domain_age_issues,
            self._check_domain_title_issues,
            self._check_subdomain_issues,
            self._check_form_security_issues,
            self._check_security_header_issues,
            self._check_robots_issues,
        ]
        
        for check_method in check_methods:
            all_issues.extend(check_method())
        
        # Categorize by severity
        categorized = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for issue in all_issues:
            severity = issue['severity']
            categorized[severity].append({
                'type': issue['type'],
                'description': issue['description'],
                'risk': issue['risk']
            })
        
        return categorized
    
    def _calculate_verdict(self, issue_counts: Dict[str, int]) -> Dict[str, str]:
        """Determine overall verdict based on issue counts"""
        critical = issue_counts['critical']
        high = issue_counts['high']
        medium = issue_counts['medium']
        low = issue_counts['low']
        
        if critical > 0:
            return {
                'verdict': 'SUSPICIOUS',
                'emoji': '🚨',
                'message': 'This website shows critical security issues and should NOT be trusted'
            }
        elif high >= 2:
            return {
                'verdict': 'SUSPICIOUS',
                'emoji': '⚠️',
                'message': 'This website shows multiple high-risk indicators'
            }
        elif high == 1 and medium >= 2:
            return {
                'verdict': 'SUSPICIOUS',
                'emoji': '⚠️',
                'message': 'This website shows concerning security issues'
            }
        elif high == 1 or medium >= 3:
            return {
                'verdict': 'POTENTIALLY SUSPICIOUS',
                'emoji': '⚠️',
                'message': 'This website shows some warning signs - proceed with caution'
            }
        elif medium > 0 or low > 0:
            return {
                'verdict': 'SAFE (with minor issues)',
                'emoji': '✅',
                'message': 'This website appears safe but has minor security improvements needed'
            }
        else:
            return {
                'verdict': 'SAFE',
                'emoji': '✅',
                'message': 'This website appears to be legitimate and secure'
            }
    
    def get_verdict(self) -> Dict:
        """
        Analyze scan results and return verdict with categorized issues.
        Returns whether site is suspicious or safe.
        """
        # Collect all issues
        issues = self._collect_all_issues()
        
        # Count issues by severity
        issue_counts = {
            'critical': len(issues['critical']),
            'high': len(issues['high']),
            'medium': len(issues['medium']),
            'low': len(issues['low'])
        }
        
        total_issues = sum(issue_counts.values())
        
        # Calculate verdict
        verdict_info = self._calculate_verdict(issue_counts)
        
        return {
            'verdict': verdict_info['verdict'],
            'verdict_emoji': verdict_info['emoji'],
            'verdict_message': verdict_info['message'],
            'total_issues': total_issues,
            'issues': issues,
            'issue_counts': issue_counts
        }



class SecurityScanner:
    def __init__(self, bypass_robots: bool = True):
        self.session = session_get()
        self.bypass_robots = bypass_robots
    
    def scan(self, url: str) -> ScanReport:
        """
        Perform comprehensive security scan on the given URL.
        
        Args:
            url: The URL to scan (must include scheme)
            
        Returns:
            ScanReport object with all scan results
        """
        report = ScanReport(url=url, success=False)
        
        # Check robots.txt
        report.robots_allowed = scan_check(url, self.session)
        
        if not report.robots_allowed and not self.bypass_robots:
            report.error = "Scanning not allowed by robots.txt (use bypass_robots=True to override)"
            return report
        elif not report.robots_allowed and self.bypass_robots:
            report.robots_bypassed = True
            print("BYPASSING robots.txt restrictions")
        
        try:
            # Fetch page ONCE
            response = fetch_url(self.session, url, timeout=10, allow_redirects=True)
            response.raise_for_status()
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            title = soup.find('title')
            report.title = title.string.strip() if title and title.string else None
            
            # Get domain 
            parsed_url = urlparse(response.url)
            domain = parsed_url.netloc
            
            print(f"🔍 Scanning: {domain}")
            
            # Run all security checks
            print("  ├─ Checking HTTPS...")
            report.https = check_https_final(url, response)
            
            print("  ├─ Checking SSL certificate...")
            report.ssl = check_ssl(domain)
            
            print("  ├─ Checking security headers...")
            report.headers = check_headers(response)
            
            print("  ├─ Checking forms...")
            report.forms = check_forms(soup, response.url)
            
            # Run domain checks
            print("  ├─ Checking domain age...")
            report.domain_age = check_domain_age(domain)
            
            print("  ├─ Checking blacklists...")
            report.blacklist = check_blacklist(domain)
            
            print("  ├─ Checking for homograph attacks...")
            report.homograph = check_homograph_attack(domain)
            
            print("  ├─ Checking domain in title...")
            report.domain_in_title = check_domain_in_title(domain, report.title)
            
            print("  ├─ Checking form redirects...")
            report.form_redirects = check_form_redirects(soup, response.url)
            
            print("  ├─ Checking domain length...")
            report.domain_length = check_domain_length(domain)
            
            print("  ├─ Checking TLD...")
            report.suspicious_tld = check_suspicious_tld(domain)
            
            print("  ├─ Checking subdomain depth...")
            report.subdomain_depth = check_subdomain_depth(domain)
            
            print("  └─ Checking brand impersonation...")
            report.brand_impersonation = check_brand_impersonation(domain)
            
            report.success = True
            print("✅ Scan completed successfully!")
            
        except Exception as e:
            report.error = str(e)
            print(f" Scan failed: {e}")
        
        return report