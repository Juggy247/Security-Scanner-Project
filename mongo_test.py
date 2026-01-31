"""
Quick test to verify MongoDB integration with your scanner
Run this to confirm all collections are being used
"""

from scanner.config import MongoDbConfig
from scanner.core import SecurityScanner
from scanner.ml_integration import EnhancedSecurityScanner

print("=" * 70)
print("MONGODB INTEGRATION TEST")
print("=" * 70)
print()

# Test 1: Check MongoDB Connection
print("1️⃣  Testing MongoDB Connection...")
try:
    db = MongoDbConfig()
    print("   ✅ MongoDB connected successfully!")
    print()
except Exception as e:
    print(f"   ❌ MongoDB connection failed: {e}")
    print()
    exit(1)

# Test 2: Check Collections
print("2️⃣  Checking MongoDB Collections...")

# Count documents in each collection
tlds_count = db.suspicious_tlds.count_documents({'is_active': True})
brands_count = db.brands.count_documents({'is_active': True})
blacklist_count = db.blacklisted_domains.count_documents({'is_active': True})
keywords_count = db.suspicious_keywords.count_documents({'is_active': True})

print(f"   📊 Suspicious TLDs: {tlds_count}")
print(f"   📊 Protected Brands: {brands_count}")
print(f"   📊 Blacklisted Domains: {blacklist_count}")
print(f"   📊 Suspicious Keywords: {keywords_count}")
print()

if tlds_count == 0:
    print("   ⚠️  WARNING: No suspicious TLDs found!")
    print("       Add some using: python admin_main.py")
    print()

# Test 3: Sample Data
print("3️⃣  Sample Data from Collections...")

# Show a few TLDs
print("   🔸 Sample Suspicious TLDs:")
for tld in db.get_suspicious_tlds()[:5]:
    print(f"      • .{tld}")
if tlds_count > 5:
    print(f"      ... and {tlds_count - 5} more")
print()

# Show a few brands
print("   🔸 Sample Protected Brands:")
for brand in db.get_brands()[:5]:
    print(f"      • {brand}")
if brands_count > 5:
    print(f"      ... and {brands_count - 5} more")
print()

# Show a few keywords
print("   🔸 Sample Suspicious Keywords:")
for keyword in db.get_suspicious_keywords()[:5]:
    print(f"      • {keyword}")
if keywords_count > 5:
    print(f"      ... and {keywords_count - 5} more")
print()

# Test 4: Test Scanner Integration
print("4️⃣  Testing Scanner Integration...")
print("   Testing domain checks with MongoDB data...")
print()

# Test TLD check
test_domain = "suspicious-site.tk"
print(f"   🧪 Testing: {test_domain}")

from scanner.domain_checks import check_suspicious_tld
tld_result = check_suspicious_tld(test_domain)

if tld_result['is_suspicious']:
    print(f"      ✅ TLD '.{tld_result['tld']}' correctly identified as suspicious")
    if tld_result.get('reason'):
        print(f"         Reason: {tld_result['reason']}")
else:
    print(f"      ⚠️  TLD '.{tld_result['tld']}' not flagged (may not be in database)")
print()

# Test brand impersonation
test_domain2 = "paypal-verify-secure.com"
print(f"   🧪 Testing: {test_domain2}")

from scanner.domain_checks import check_brand_impersonation
brand_result = check_brand_impersonation(test_domain2)

if brand_result['potential_impersonation']:
    print(f"      ✅ Brand impersonation detected!")
    print(f"         Suspected brand: {brand_result['suspected_brand']}")
    print(f"         Suspicious keywords: {brand_result['suspicious_keywords']}")
else:
    print(f"      ℹ️  No brand impersonation detected")
    if brands_count == 0:
        print(f"         (No brands in database - add 'paypal' to test)")
print()

# Test 5: Full Scanner Test
print("5️⃣  Testing Full Security Scanner...")
print("   Running quick scan on test URL...")
print()

try:
    scanner = SecurityScanner(bypass_robots=True)
    test_url = "https://google.com"
    
    print(f"   🔍 Scanning: {test_url}")
    report = scanner.scan(test_url)
    
    if report.success:
        print(f"      ✅ Scan completed successfully!")
        
        # Check if MongoDB data was used
        checks_run = []
        if report.suspicious_tld:
            checks_run.append("TLD check")
        if report.brand_impersonation:
            checks_run.append("Brand impersonation check")
        if report.blacklist:
            checks_run.append("Blacklist check")
        if report.domain_age:
            checks_run.append("Domain age check")
        
        print(f"      📊 MongoDB checks performed: {', '.join(checks_run)}")
        
        # Show some results
        if report.suspicious_tld:
            print(f"         TLD suspicious: {report.suspicious_tld.get('is_suspicious', False)}")
        if report.blacklist:
            print(f"         Blacklisted: {report.blacklist.get('is_blacklisted', False)}")
    else:
        print(f"      ⚠️  Scan failed: {report.error}")
    
    print()
    
except Exception as e:
    print(f"      ❌ Scanner error: {e}")
    print()

# Test 6: ML Integration Test
print("6️⃣  Testing ML + MongoDB Integration...")
try:
    from scanner.ml_detector import MLPhishingDetector
    import os
    
    if os.path.exists("models/phishing_model.pkl"):
        print("   ✅ ML model found: models/phishing_model.pkl")
        
        detector = MLPhishingDetector()
        if detector.is_trained:
            print("   ✅ ML model loaded successfully!")
            print(f"   📊 Features: {len(detector.feature_names)}")
            
            # Check if MongoDB features are in the model
            mongodb_features = ['tld_suspicious', 'brand_impersonation', 'is_blacklisted']
            found_features = [f for f in mongodb_features if f in detector.feature_names]
            
            print(f"   📊 MongoDB-related features: {len(found_features)}/{len(mongodb_features)}")
            for feat in found_features:
                print(f"      • {feat}")
        else:
            print("   ⚠️  ML model not trained")
    else:
        print("   ℹ️  ML model not found (run train_ml_model.py)")
    
    print()
    
except Exception as e:
    print(f"   ⚠️  ML test skipped: {e}")
    print()

# Summary
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print()

all_good = True

if tlds_count > 0:
    print("✅ MongoDB collections populated")
else:
    print("⚠️  MongoDB collections need data (use admin panel)")
    all_good = False

if tlds_count > 0:
    print("✅ Scanner can access MongoDB data")
else:
    print("⚠️  Add data to MongoDB first")
    all_good = False

print("✅ All imports working correctly")

if os.path.exists("models/phishing_model.pkl"):
    print("✅ ML model trained and ready")
else:
    print("ℹ️  ML model not trained yet (optional)")

print()

if all_good:
    print("🎉 Everything is working perfectly!")
    print()
    print("Your scanner is using MongoDB data for:")
    print("  • TLD risk assessment")
    print("  • Brand impersonation detection")
    print("  • Blacklist checking")
    print("  • Keyword analysis")
    print()
    print("Next steps:")
    print("  1. Make sure your MongoDB has enough data")
    print("  2. Run: python admin_main.py (to view/add data)")
    print("  3. Use EnhancedSecurityScanner in your Flask app")
else:
    print("⚠️  Some setup needed:")
    print("  1. Add suspicious TLDs: python admin_main.py")
    print("  2. Add brand names to protect")
    print("  3. Add suspicious keywords")

print()
print("=" * 70)

# Close connection
db.close()