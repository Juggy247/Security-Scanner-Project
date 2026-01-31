"""
Demo script to test ML Phishing Detector
Shows how to integrate with existing scanner
"""

import sys
import os

# Add scanner directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.ml_detector import MLPhishingDetector
from scanner.core import SecurityScanner


def demo_ml_only(detector: MLPhishingDetector, test_urls: list):
    """Demo ML detector with URL features only (no full scan)"""
    
    print("=" * 70)
    print("ML DETECTOR - URL FEATURES ONLY")
    print("=" * 70)
    print()
    
    for url in test_urls:
        print(f"Testing: {url}")
        result = detector.predict(url)
        
        if 'error' in result:
            print(f"  ❌ Error: {result['error']}")
        else:
            verdict = result['ml_verdict']
            confidence = result['confidence'] * 100
            phishing_prob = result['phishing_probability'] * 100
            
            emoji = "🚨" if result['is_phishing'] else "✅"
            print(f"  {emoji} Verdict: {verdict}")
            print(f"  📊 Confidence: {confidence:.1f}%")
            print(f"  🎯 Phishing Probability: {phishing_prob:.1f}%")
        
        print()


def demo_ml_with_scan(detector: MLPhishingDetector, scanner: SecurityScanner, test_urls: list):
    """Demo ML detector integrated with full security scan"""
    
    print("=" * 70)
    print("ML DETECTOR + FULL SECURITY SCAN")
    print("=" * 70)
    print()
    
    for url in test_urls:
        print(f"Testing: {url}")
        print(f"  🔍 Running full security scan...")
        
        # Run full scan
        scan_report = scanner.scan(url)
        
        # Get ML prediction with scan data
        ml_result = detector.predict(url, scan_report)
        
        # Get traditional verdict
        traditional_verdict = scan_report.get_verdict()
        
        print(f"\n  📋 TRADITIONAL SCANNER:")
        print(f"     Verdict: {traditional_verdict['verdict']}")
        print(f"     Total Issues: {traditional_verdict['total_issues']}")
        print(f"     Critical: {traditional_verdict['issue_counts']['critical']}, "
              f"High: {traditional_verdict['issue_counts']['high']}, "
              f"Medium: {traditional_verdict['issue_counts']['medium']}")
        
        if 'error' not in ml_result:
            print(f"\n  🤖 ML DETECTOR:")
            verdict = ml_result['ml_verdict']
            confidence = ml_result['confidence'] * 100
            phishing_prob = ml_result['phishing_probability'] * 100
            
            emoji = "🚨" if ml_result['is_phishing'] else "✅"
            print(f"     {emoji} ML Verdict: {verdict}")
            print(f"     📊 ML Confidence: {confidence:.1f}%")
            print(f"     🎯 Phishing Probability: {phishing_prob:.1f}%")
            
            # Compare verdicts
            trad_suspicious = "SUSPICIOUS" in traditional_verdict['verdict']
            ml_suspicious = ml_result['is_phishing']
            
            if trad_suspicious == ml_suspicious:
                print(f"\n  ✅ Both methods AGREE")
            else:
                print(f"\n  ⚠️  Methods DISAGREE - Review needed")
        
        print("\n" + "-" * 70 + "\n")


def main():
    """Main demo"""
    
    print("\n" + "=" * 70)
    print("ML PHISHING DETECTOR - DEMO")
    print("=" * 70)
    print()
    
    # Load model
    model_path = "models/phishing_model.pkl"
    
    if not os.path.exists(model_path):
        print(f"❌ Model not found: {model_path}")
        print(f"Please train the model first using: python train_ml_model.py")
        return
    
    detector = MLPhishingDetector(model_path=model_path)
    
    if not detector.is_trained:
        print("❌ Failed to load model")
        return
    
    print(f"✅ Model loaded successfully!")
    print(f"📊 Features: {len(detector.feature_names)}")
    print()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://www.amazon.com",
        "https://paypal-verify-account-now.tk",  # Suspicious (fake example)
        "http://192.168.1.1/login",  # Suspicious (IP address)
        "https://www.facebook.com",
    ]
    
    # Demo 1: ML only (fast, URL features)
    demo_ml_only(detector, test_urls[:3])
    
    # Demo 2: ML + Full scan (slower, comprehensive)
    print("\n" + "=" * 70)
    print("Now testing with FULL SCANNER integration...")
    print("This may take a minute as it performs complete security scans.")
    print("=" * 70)
    print()
    
    scanner = SecurityScanner(bypass_robots=True)
    demo_ml_with_scan(detector, scanner, test_urls[:2])  # Just test first 2
    
    # Show feature importance
    print("\n" + "=" * 70)
    print("TOP 15 MOST IMPORTANT FEATURES")
    print("=" * 70)
    print()
    
    top_features = detector.get_feature_importance(top_n=15)
    for i, feat in enumerate(top_features, 1):
        bar_length = int(feat['importance'] * 50)
        bar = "█" * bar_length
        print(f"{i:2d}. {feat['feature']:30s} {bar} {feat['importance']:.4f}")
    
    print("\n" + "=" * 70)
    print("DEMO COMPLETE!")
    print("=" * 70)


if __name__ == "__main__":
    main()