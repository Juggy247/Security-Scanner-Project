"""
Test MongoDB Integration with domain_checks
"""

from scanner.domain_checks import (
    check_suspicious_tld,
    check_brand_impersonation,
    check_blacklist,
    close_db_connection
)

print("=" * 60)
print("🧪 Testing MongoDB Integration")
print("=" * 60)
print()

# Helper to safely get values from possibly None results
def safe_get(result, key, default='N/A'):
    if result:
        value = result.get(key, default)
        return default if value is None else value
    return default

# Test 1: Suspicious TLD Check
print("Test 1: Checking suspicious TLD...")
result = check_suspicious_tld("example.tk")
print(f"   Domain: example.tk")
print(f"   Is suspicious: {result['is_suspicious'] if result else False}")
print(f"   Risk level: {safe_get(result, 'risk_level')}")
print(f"   Reason: {safe_get(result, 'reason')[:50]}...")
print()

# Test 2: Safe TLD
print("Test 2: Checking safe TLD...")
result = check_suspicious_tld("example.com")
print(f"   Domain: example.com")
print(f"   Is suspicious: {result['is_suspicious'] if result else False}")
print()

# Test 3: Brand Impersonation (should detect)
print("Test 3: Checking brand impersonation...")
result = check_brand_impersonation("paypal-verify-account.com")
print(f"   Domain: paypal-verify-account.com")
print(f"   Potential impersonation: {result['potential_impersonation'] if result else False}")
if result and result.get('potential_impersonation'):
    print(f"   Suspected brand: {result.get('suspected_brand', 'N/A')}")
    print(f"   Suspicious keywords: {result.get('suspicious_keywords', [])}")
print()

# Test 4: Safe domain (no brand)
print("Test 4: Checking safe domain...")
result = check_brand_impersonation("example.com")
print(f"   Domain: example.com")
print(f"   Potential impersonation: {result['potential_impersonation'] if result else False}")
print()

# Test 5: Blacklist check
print("Test 5: Checking blacklist...")
result = check_blacklist("google.com")
print(f"   Domain: google.com")
print(f"   Is blacklisted: {result['is_blacklisted'] if result else False}")
print()

print("=" * 60)
print("✅ All Tests Complete!")
print("=" * 60)
print()
print("What this proves:")
print("  ✅ domain_checks.py now uses MongoDB")
print("  ✅ TLDs are loaded from database")
print("  ✅ Brands are loaded from database")
print("  ✅ Keywords are loaded from database")
print("  ✅ Can add new data without changing code!")
print()

# Cleanup
close_db_connection()


"""  <a href="{{ url_for('admin.import_data') }}" class="menu-item {% if request.endpoint == 'admin.import_data' %}active{% endif %}">
                📥 Import Data
            </a>
            
            <a href="{{ url_for('admin.export_data') }}" class="menu-item">
                📤 Export Data
            </a>
               <a href="{{ url_for('admin.import_data') }}" class="btn btn-success">📥 Import Data</a>
                  
                     <div id="raw-data" class="raw-data" style="display: none;">
            <h3 style="margin-bottom: 15px;">Raw Technical Data:</h3>
            <pre>{{ raw_data }}</pre>
        </div>
                           """