from scanner.core import SecurityScanner
import json


def print_verdict(verdict):
    """Pretty print the verdict with colored output"""
    print("\n" + "="*70)
    print(f"{verdict['verdict_emoji']} VERDICT: {verdict['verdict']}")
    print("="*70)
    print(f"\n{verdict['verdict_message']}\n")
    
    # Print issue summary
    counts = verdict['issue_counts']
    total = verdict['total_issues']
    
    if total == 0:
        print("✅ No security issues detected!\n")
        return
    
    print(f"📊 Found {total} issue(s):\n")
    
    if counts['critical'] > 0:
        print(f"   🚨 {counts['critical']} CRITICAL")
    if counts['high'] > 0:
        print(f"   🔴 {counts['high']} HIGH")
    if counts['medium'] > 0:
        print(f"   🟡 {counts['medium']} MEDIUM")
    if counts['low'] > 0:
        print(f"   🔵 {counts['low']} LOW")
    
    print("\n" + "-"*70 + "\n")
    
    # Print critical issues
    if verdict['issues']['critical']:
        print("🚨 CRITICAL ISSUES:")
        for i, issue in enumerate(verdict['issues']['critical'], 1):
            print(f"\n  {i}. {issue['type']}")
            print(f"     ⚠️  {issue['description']}")
            print(f"     💀 Risk: {issue['risk']}")
    
    # Print high severity issues
    if verdict['issues']['high']:
        print("\n🔴 HIGH SEVERITY ISSUES:")
        for i, issue in enumerate(verdict['issues']['high'], 1):
            print(f"\n  {i}. {issue['type']}")
            print(f"     ⚠️  {issue['description']}")
            print(f"     ⚠️  Risk: {issue['risk']}")
    
    # Print medium severity issues
    if verdict['issues']['medium']:
        print("\n🟡 MEDIUM SEVERITY ISSUES:")
        for i, issue in enumerate(verdict['issues']['medium'], 1):
            print(f"\n  {i}. {issue['type']}")
            print(f"     ℹ️  {issue['description']}")
            print(f"     ℹ️  Risk: {issue['risk']}")
    
    # Print low severity issues (collapsed)
    if verdict['issues']['low']:
        print(f"\n🔵 LOW SEVERITY: {counts['low']} minor issue(s)")
        for issue in verdict['issues']['low']:
            print(f"   • {issue['type']}")
    
    print("\n" + "="*70 + "\n")


def print_full_report(report):
    """Print the complete raw JSON report"""
    print("\n📄 FULL TECHNICAL REPORT:")
    print("="*70)
    print(json.dumps(report.__dict__, indent=2, default=str))
    print("="*70 + "\n")


if __name__ == "__main__":
    print("Website Security Scanner")
    print("="*70 + "\n")
    
    # Get user input
    url = input("Enter URL to scan: ").strip()
    
    if not url:
        print("❌ Error: URL is required!")
        exit(1)
    
    # Add https:// if no scheme provided
    if not url.startswith("http"):
        url = "https://" + url
    
    print(f"\n🔍 Scanning {url}...")
    print("-"*70 + "\n")
    
    # Create scanner and scan
    scanner = SecurityScanner(bypass_robots=True)
    report = scanner.scan(url)
    
    # Check if scan was successful
    if not report.success:
        print(f"\n❌ Scan failed: {report.error}")
        exit(1)
    
    # Get and print verdict
    verdict = report.get_verdict()
    print_verdict(verdict)
    
    # Ask if user wants full technical report
    show_full = input("Show full technical report? (y/n): ").strip().lower()
    if show_full == 'y':
        print_full_report(report)
    
    print("✅ Done!")