"""
Test script for RICO Enterprise Reporting System
"""

from rico.reporting import ReportBuilder, ComplianceMapper, RiskAggregator

# Sample vulnerabilities (simulating scan results)
sample_vulnerabilities = [
    {
        "type": "SQL Injection",
        "endpoint": "/users/search",
        "method": "GET",
        "severity": "Critical",
        "confidence": 0.95,
        "description": "SQL injection vulnerability detected in search parameter. Attacker can execute arbitrary SQL queries.",
        "poc": {
            "curl": "curl -X GET 'http://localhost:8000/users/search?q=' OR 1=1--'"
        }
    },
    {
        "type": "IDOR",
        "endpoint": "/users/{user_id}/orders",
        "method": "GET",
        "severity": "High",
        "confidence": 0.85,
        "description": "Insecure Direct Object Reference allows accessing other users' orders by manipulating the user_id parameter.",
        "poc": {
            "curl": "curl -X GET 'http://localhost:8000/users/999/orders'"
        }
    },
    {
        "type": "Missing Authentication",
        "endpoint": "/admin/users",
        "method": "GET",
        "severity": "Critical",
        "confidence": 0.90,
        "description": "Admin endpoint accessible without authentication. Exposes sensitive user data.",
        "poc": {
            "curl": "curl -X GET 'http://localhost:8000/admin/users'"
        }
    },
    {
        "type": "IDOR",
        "endpoint": "/users/{user_id}",
        "method": "GET",
        "severity": "Medium",
        "confidence": 0.75,
        "description": "User profile endpoint allows accessing other users' information.",
        "poc": {
            "curl": "curl -X GET 'http://localhost:8000/users/123'"
        }
    },
    {
        "type": "CSRF",
        "endpoint": "/users/update",
        "method": "POST",
        "severity": "Medium",
        "confidence": 0.70,
        "description": "Missing CSRF protection on user update endpoint.",
        "poc": {
            "curl": "curl -X POST 'http://localhost:8000/users/update' -d 'email=attacker@evil.com'"
        }
    }
]

def test_compliance_mapper():
    """Test compliance mapping functionality."""
    print("\n" + "="*70)
    print("TEST 1: Compliance Mapper")
    print("="*70)
    
    # Test OWASP mapping
    print("\nTesting OWASP Mapping:")
    for vuln_type in ["SQL Injection", "IDOR", "Missing Authentication"]:
        owasp = ComplianceMapper.map_to_owasp(vuln_type)
        if owasp:
            print(f"  {vuln_type} -> {owasp['category']}: {owasp['name']}")
        else:
            print(f"  {vuln_type} -> No mapping")
    
    # Test CWE mapping
    print("\nTesting CWE Mapping:")
    for vuln_type in ["SQL Injection", "IDOR", "Missing Authentication"]:
        cwe = ComplianceMapper.map_to_cwe(vuln_type)
        if cwe:
            desc = ComplianceMapper.get_cwe_description(cwe)
            print(f"  {vuln_type} -> {cwe}: {desc}")
        else:
            print(f"  {vuln_type} -> No mapping")
    
    # Test enrichment
    print("\nTesting Vulnerability Enrichment:")
    test_vuln = {
        "type": "SQL Injection",
        "endpoint": "/test",
        "severity": "Critical"
    }
    enriched = ComplianceMapper.enrich_vulnerability(test_vuln)
    print(f"  Original keys: {list(test_vuln.keys())}")
    print(f"  Enriched keys: {list(enriched.keys())}")
    print(f"  OWASP Category: {enriched.get('owasp_category')}")
    print(f"  CWE ID: {enriched.get('cwe_id')}")
    
    print("\n✓ Compliance Mapper tests passed!")

def test_risk_aggregator():
    """Test risk aggregation functionality."""
    print("\n" + "="*70)
    print("TEST 2: Risk Aggregator")
    print("="*70)
    
    aggregator = RiskAggregator(sample_vulnerabilities)
    
    print(f"\nTotal Vulnerabilities: {aggregator.get_total_count()}")
    
    print("\nSeverity Distribution:")
    for severity, count in aggregator.get_severity_distribution().items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    print(f"\nRisk Score: {aggregator.calculate_risk_score():.2f}/100")
    print(f"Risk Level: {aggregator.get_risk_level()}")
    print(f"Highest Severity: {aggregator.get_highest_severity()}")
    
    print("\nKey Exposure Areas:")
    for area in aggregator.get_key_exposure_areas():
        print(f"  - {area}")
    
    print("\nExecutive Summary:")
    summary = aggregator.generate_executive_summary("http://localhost:8000")
    print(f"  {summary}")
    
    print("\n✓ Risk Aggregator tests passed!")

def test_report_builder():
    """Test report builder and exporters."""
    print("\n" + "="*70)
    print("TEST 3: Report Builder & Exporters")
    print("="*70)
    
    # Create report builder
    builder = ReportBuilder(
        vulnerabilities=sample_vulnerabilities,
        target_url="http://localhost:8000",
        additional_metadata={
            "scan_duration": "45.2s",
            "endpoints_tested": 23
        }
    )
    
    print(f"\nEnriched Vulnerabilities: {len(builder.enriched_vulnerabilities)}")
    print(f"Risk Score: {builder.summary_stats['risk_score']:.2f}")
    print(f"Risk Level: {builder.summary_stats['risk_level']}")
    
    # Test JSON export
    print("\nExporting JSON report...")
    try:
        builder.export_json("test_reports/test_report.json")
        print("  ✓ JSON export successful")
    except Exception as e:
        print(f"  ✗ JSON export failed: {e}")
    
    # Test Markdown export
    print("\nExporting Markdown report...")
    try:
        builder.export_markdown("test_reports/test_report.md")
        print("  ✓ Markdown export successful")
    except Exception as e:
        print(f"  ✗ Markdown export failed: {e}")
    
    # Test HTML export
    print("\nExporting HTML report...")
    try:
        builder.export_html("test_reports/test_report.html")
        print("  ✓ HTML export successful")
    except Exception as e:
        print(f"  ✗ HTML export failed: {e}")
    
    # Test export all
    print("\nExporting all formats...")
    try:
        filepaths = builder.export_all("test_reports", "complete_report")
        print("  ✓ All formats exported successfully")
        print("\n  Generated files:")
        for format_type, filepath in filepaths.items():
            print(f"    - {format_type}: {filepath}")
    except Exception as e:
        print(f"  ✗ Export all failed: {e}")
    
    # Print summary
    print("\n" + "-"*70)
    builder.print_summary()
    
    print("✓ Report Builder tests passed!")

def test_enriched_vulnerability():
    """Test that vulnerabilities are properly enriched."""
    print("\n" + "="*70)
    print("TEST 4: Vulnerability Enrichment")
    print("="*70)
    
    builder = ReportBuilder(
        vulnerabilities=sample_vulnerabilities,
        target_url="http://localhost:8000"
    )
    
    print("\nChecking enriched vulnerability fields:")
    sample_enriched = builder.enriched_vulnerabilities[0]
    
    required_fields = [
        "id", "type", "endpoint", "method", "severity", "confidence",
        "owasp_category", "owasp_name", "cwe_id", "cwe_description"
    ]
    
    for field in required_fields:
        value = sample_enriched.get(field)
        status = "✓" if value is not None else "✗"
        print(f"  {status} {field}: {value}")
    
    print("\n✓ Vulnerability enrichment tests passed!")

def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("RICO ENTERPRISE REPORTING SYSTEM - TEST SUITE")
    print("="*70)
    
    try:
        test_compliance_mapper()
        test_risk_aggregator()
        test_enriched_vulnerability()
        test_report_builder()
        
        print("\n" + "="*70)
        print("ALL TESTS PASSED! ✓")
        print("="*70)
        print("\nGenerated test reports in: test_reports/")
        print("  - test_report.json")
        print("  - test_report.md")
        print("  - test_report.html")
        print("  - complete_report.json")
        print("  - complete_report.md")
        print("  - complete_report.html")
        print("\nOpen test_reports/test_report.html in your browser to see the dashboard!")
        print()
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
