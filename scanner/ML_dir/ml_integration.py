"""
Integration helper for adding ML to existing SecurityScanner
Drop-in enhancement without modifying core.py
"""

from scanner.core import SecurityScanner, ScanReport
from scanner.ml_detector import MLPhishingDetector
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class EnhancedSecurityScanner(SecurityScanner):
    """
    Enhanced scanner with ML capabilities
    Drop-in replacement for SecurityScanner
    """
    
    def __init__(self, bypass_robots: bool = True, enable_ml: bool = True, 
                 model_path: str = "models/phishing_model.pkl"):
        """
        Initialize enhanced scanner
        
        Args:
            bypass_robots: Whether to bypass robots.txt
            enable_ml: Whether to use ML predictions
            model_path: Path to trained ML model
        """
        super().__init__(bypass_robots=bypass_robots)
        
        self.enable_ml = enable_ml
        self.ml_detector = None
        
        if enable_ml:
            try:
                self.ml_detector = MLPhishingDetector(model_path=model_path)
                if self.ml_detector.is_trained:
                    logger.info("✅ ML detector loaded successfully")
                else:
                    logger.warning("⚠️  ML model not trained, ML predictions disabled")
                    self.enable_ml = False
            except Exception as e:
                logger.warning(f"⚠️  Failed to load ML detector: {e}")
                self.enable_ml = False
    
    def scan(self, url: str) -> ScanReport:
        """
        Perform scan with optional ML enhancement
        
        Returns ScanReport with additional ml_prediction field
        """
        # Run traditional scan
        report = super().scan(url)
        
        # Add ML prediction if enabled
        if self.enable_ml and self.ml_detector:
            try:
                ml_result = self.ml_detector.predict(url, report)
                report.ml_prediction = ml_result
                logger.debug(f"ML Prediction: {ml_result['ml_verdict']} "
                           f"({ml_result['confidence']*100:.1f}% confidence)")
            except Exception as e:
                logger.warning(f"ML prediction failed: {e}")
                report.ml_prediction = None
        else:
            report.ml_prediction = None
        
        return report


def add_ml_to_verdict(scan_report: ScanReport, ml_weight: float = 0.3) -> Dict[str, Any]:
    """
    Enhanced verdict that combines traditional scanning + ML prediction
    
    Args:
        scan_report: ScanReport object (must have ml_prediction)
        ml_weight: Weight to give ML prediction (0.0 to 1.0)
        
    Returns:
        Enhanced verdict dictionary
    """
    # Get traditional verdict
    traditional = scan_report.get_verdict()
    
    # If no ML prediction, return traditional
    if not hasattr(scan_report, 'ml_prediction') or not scan_report.ml_prediction:
        return traditional
    
    ml = scan_report.ml_prediction
    
    # Calculate combined score
    # Traditional: SAFE=0, POTENTIALLY SUSPICIOUS=0.5, SUSPICIOUS=1.0
    trad_score = 0.0
    if "SUSPICIOUS" in traditional['verdict']:
        if "POTENTIALLY" in traditional['verdict']:
            trad_score = 0.5
        else:
            trad_score = 1.0
    
    # ML: phishing_probability (0.0 to 1.0)
    ml_score = ml['phishing_probability']
    
    # Weighted combination
    combined_score = (1 - ml_weight) * trad_score + ml_weight * ml_score
    
    # Determine enhanced verdict
    if combined_score >= 0.7:
        enhanced_verdict = "SUSPICIOUS"
        emoji = "🚨"
        message = "This website shows critical security issues"
    elif combined_score >= 0.4:
        enhanced_verdict = "POTENTIALLY SUSPICIOUS"
        emoji = "⚠️"
        message = "This website shows warning signs - proceed with caution"
    else:
        enhanced_verdict = "SAFE"
        emoji = "✅"
        message = "This website appears legitimate and secure"
    
    # Build enhanced result
    enhanced = {
        'verdict': enhanced_verdict,
        'verdict_emoji': emoji,
        'verdict_message': message,
        'combined_score': combined_score,
        
        # Traditional components
        'traditional_verdict': traditional['verdict'],
        'traditional_score': trad_score,
        'total_issues': traditional['total_issues'],
        'issues': traditional['issues'],
        'issue_counts': traditional['issue_counts'],
        
        # ML components
        'ml_verdict': ml['ml_verdict'],
        'ml_score': ml_score,
        'ml_confidence': ml['confidence'],
        'ml_phishing_probability': ml['phishing_probability'],
        
        # Analysis
        'methods_agree': (trad_score > 0.5) == (ml_score > 0.5),
        'confidence_level': 'high' if abs(trad_score - ml_score) < 0.3 else 'medium' if abs(trad_score - ml_score) < 0.5 else 'low'
    }
    
    return enhanced


# Example usage functions

def quick_ml_scan(url: str) -> Dict[str, Any]:
    """
    Quick ML-only scan (fast, no full security scan)
    
    Args:
        url: URL to check
        
    Returns:
        ML prediction results
    """
    detector = MLPhishingDetector()
    if not detector.is_trained:
        return {'error': 'ML model not trained'}
    
    return detector.predict(url)


def full_enhanced_scan(url: str) -> tuple[ScanReport, Dict[str, Any]]:
    """
    Complete scan with ML enhancement
    
    Args:
        url: URL to check
        
    Returns:
        Tuple of (ScanReport, enhanced_verdict)
    """
    scanner = EnhancedSecurityScanner(bypass_robots=True, enable_ml=True)
    report = scanner.scan(url)
    
    if hasattr(report, 'ml_prediction') and report.ml_prediction:
        verdict = add_ml_to_verdict(report, ml_weight=0.3)
    else:
        verdict = report.get_verdict()
    
    return report, verdict