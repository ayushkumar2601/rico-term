"""
Test CI/CD Integration Features

Tests pipeline enforcer and SARIF exporter functionality.
"""

import json
import sys
from pathlib import Path

# Test data
sample_vulnerabilities = [
    {
        "id": "RICO-001",
        "type": "SQL Injection",
        "endpoint": "/users/search",
        "method": "GET",
        "severity": "Critical",
        "confidence": 0.95,
        "description": "SQL injection vulnerability detected in search parameter",
        "poc": {"curl": "curl -X GET 'http://localhost:8000/users/search?q=' OR 1=1--'"},
        "cwe_id": "CWE-89",
        "owasp_category": "API8:2023"
    },
    {
        "id": "RICO-002",
        "type": "IDOR",
        "endpoint": "/users/{user_id}",
        "method": "GET",
        "severity": "High",
        "confidence": 0.85,
        "description": "Insecure Direct Object Reference vulnerability",
        "poc": {"curl": "curl -X GET 'http://localhost:8000/users/999'"},
        "cwe_id": "CWE-639",
        "owasp_category": "API1:2023"
    },
    {
        "id": "RICO-003",
        "type": "Missing Authentication",
        "endpoint": "/admin/users",
        "method": "GET",
        "severity": "Medium",
        "confidence": 0.90,
        "description": "Admin endpoint accessible without authentication",
        "poc": {"curl": "curl -X GET 'http://localhost:8000/admin/users'"},
        "cwe_id": "CWE-306",
        "owasp_category": "API2:2023"
    }
]


def test_pipeline_enforcer():
    """Test pipeline enforcer functionality."""
    print("=" * 70)
    print("TEST 1: Pipeline Enforcer")
    print("=" * 70)
    
    from rico.cicd.pipeline_enforcer import PipelineEnforcer, should_fail_build
    
    # Test 1: Critical threshold
    print("\n1. Testing critical threshold...")
    enforcer = PipelineEnforcer("critical")
    result = enforcer.check_vulnerabilities(sample_vulnerabilities)
    print(f"   Should fail on critical: {result}")
    assert result == True, "Should fail with critical vulnerability present"
    
    failing = enforcer.get_failing_vulnerabilities(sample_vulnerabilities)
    print(f"   Failing vulnerabilities: {len(failing)}")
    assert len(failing) == 1, "Should have 1 critical vulnerability"
    print("   [OK] Critical threshold test passed")
    
    # Test 2: High threshold
    print("\n2. Testing high threshold...")
    enforcer = PipelineEnforcer("high")
    result = enforcer.check_vulnerabilities(sample_vulnerabilities)
    print(f"   Should fail on high: {result}")
    assert result == True, "Should fail with high+ vulnerabilities present"
    
    failing = enforcer.get_failing_vulnerabilities(sample_vulnerabilities)
    print(f"   Failing vulnerabilities: {len(failing)}")
    assert len(failing) == 2, "Should have 2 high+ vulnerabilities"
    print("   [OK] High threshold test passed")
    
    # Test 3: Medium threshold
    print("\n3. Testing medium threshold...")
    enforcer = PipelineEnforcer("medium")
    result = enforcer.check_vulnerabilities(sample_vulnerabilities)
    print(f"   Should fail on medium: {result}")
    assert result == True, "Should fail with medium+ vulnerabilities present"
    
    failing = enforcer.get_failing_vulnerabilities(sample_vulnerabilities)
    print(f"   Failing vulnerabilities: {len(failing)}")
    assert len(failing) == 3, "Should have 3 medium+ vulnerabilities"
    print("   [OK] Medium threshold test passed")
    
    # Test 4: No vulnerabilities above threshold
    print("\n4. Testing with no critical vulnerabilities...")
    safe_vulns = [v for v in sample_vulnerabilities if v["severity"] != "Critical"]
    enforcer = PipelineEnforcer("critical")
    result = enforcer.check_vulnerabilities(safe_vulns)
    print(f"   Should pass (no critical): {not result}")
    assert result == False, "Should pass with no critical vulnerabilities"
    print("   [OK] Safe threshold test passed")
    
    # Test 5: Convenience function
    print("\n5. Testing convenience function...")
    result = should_fail_build(sample_vulnerabilities, "high")
    print(f"   should_fail_build result: {result}")
    assert result == True, "Convenience function should work"
    print("   [OK] Convenience function test passed")
    
    print("\n[OK] All pipeline enforcer tests passed!")


def test_sarif_exporter():
    """Test SARIF exporter functionality."""
    print("\n" + "=" * 70)
    print("TEST 2: SARIF Exporter")
    print("=" * 70)
    
    from rico.cicd.sarif_exporter import SARIFExporter, convert_to_sarif_format
    
    # Test 1: Create SARIF report
    print("\n1. Creating SARIF report...")
    exporter = SARIFExporter(tool_name="RICO", tool_version="1.0.0")
    sarif_report = exporter.create_sarif_report(
        vulnerabilities=sample_vulnerabilities,
        target_url="http://localhost:8000",
        scan_timestamp="2026-02-28T12:00:00Z"
    )
    
    print(f"   SARIF version: {sarif_report['version']}")
    assert sarif_report["version"] == "2.1.0", "Should be SARIF 2.1.0"
    
    print(f"   Tool name: {sarif_report['runs'][0]['tool']['driver']['name']}")
    assert sarif_report['runs'][0]['tool']['driver']['name'] == "RICO"
    
    print(f"   Number of rules: {len(sarif_report['runs'][0]['tool']['driver']['rules'])}")
    assert len(sarif_report['runs'][0]['tool']['driver']['rules']) == 3
    
    print(f"   Number of results: {len(sarif_report['runs'][0]['results'])}")
    assert len(sarif_report['runs'][0]['results']) == 3
    
    print("   [OK] SARIF report structure valid")
    
    # Test 2: Verify severity mapping
    print("\n2. Verifying severity mapping...")
    results = sarif_report['runs'][0]['results']
    
    critical_result = next(r for r in results if r['properties']['severity'] == 'CRITICAL')
    print(f"   Critical mapped to: {critical_result['level']}")
    assert critical_result['level'] == 'error', "Critical should map to error"
    
    high_result = next(r for r in results if r['properties']['severity'] == 'HIGH')
    print(f"   High mapped to: {high_result['level']}")
    assert high_result['level'] == 'error', "High should map to error"
    
    medium_result = next(r for r in results if r['properties']['severity'] == 'MEDIUM')
    print(f"   Medium mapped to: {medium_result['level']}")
    assert medium_result['level'] == 'warning', "Medium should map to warning"
    
    print("   [OK] Severity mapping correct")
    
    # Test 3: Verify CWE and OWASP mapping
    print("\n3. Verifying compliance mapping...")
    rules = sarif_report['runs'][0]['tool']['driver']['rules']
    
    sqli_rule = next(r for r in rules if r['name'] == 'SQL Injection')
    print(f"   SQL Injection CWE: {sqli_rule['properties'].get('cwe')}")
    assert sqli_rule['properties'].get('cwe') == 'CWE-89'
    
    print(f"   SQL Injection OWASP: {sqli_rule['properties'].get('owasp')}")
    assert sqli_rule['properties'].get('owasp') == 'API8:2023'
    
    print("   [OK] Compliance mapping correct")
    
    # Test 4: Export to file
    print("\n4. Testing file export...")
    output_path = Path("test_reports/test_rico.sarif")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    exporter.export_to_file(
        filepath=str(output_path),
        vulnerabilities=sample_vulnerabilities,
        target_url="http://localhost:8000"
    )
    
    print(f"   SARIF file created: {output_path}")
    assert output_path.exists(), "SARIF file should be created"
    
    # Verify file is valid JSON
    with open(output_path, 'r') as f:
        loaded_sarif = json.load(f)
    
    print(f"   File is valid JSON: {loaded_sarif['version']}")
    assert loaded_sarif['version'] == '2.1.0'
    
    print("   [OK] File export successful")
    
    # Test 5: Convert to SARIF format
    print("\n5. Testing format conversion...")
    incomplete_vulns = [
        {"type": "XSS", "endpoint": "/search"},
        {"type": "CSRF", "endpoint": "/update", "severity": "low"}
    ]
    
    converted = convert_to_sarif_format(incomplete_vulns)
    print(f"   Converted {len(converted)} vulnerabilities")
    
    # Check that missing fields were added
    assert all('id' in v for v in converted), "All should have IDs"
    assert all('severity' in v for v in converted), "All should have severity"
    assert all('description' in v for v in converted), "All should have description"
    
    print("   [OK] Format conversion successful")
    
    print("\n[OK] All SARIF exporter tests passed!")


def test_integration():
    """Test full integration scenario."""
    print("\n" + "=" * 70)
    print("TEST 3: Full Integration Scenario")
    print("=" * 70)
    
    from rico.cicd import PipelineEnforcer, SARIFExporter
    
    print("\n1. Simulating CI/CD pipeline...")
    
    # Step 1: Generate SARIF report
    print("   Step 1: Generating SARIF report...")
    exporter = SARIFExporter()
    sarif_path = Path("test_reports/integration_test.sarif")
    exporter.export_to_file(
        filepath=str(sarif_path),
        vulnerabilities=sample_vulnerabilities,
        target_url="http://localhost:8000"
    )
    print(f"   [OK] SARIF report generated: {sarif_path}")
    
    # Step 2: Check pipeline policy
    print("   Step 2: Checking pipeline policy (fail-on high)...")
    enforcer = PipelineEnforcer("high")
    should_fail = enforcer.check_vulnerabilities(sample_vulnerabilities)
    
    if should_fail:
        failing = enforcer.get_failing_vulnerabilities(sample_vulnerabilities)
        print(f"   [FAIL] Build would fail: {len(failing)} high+ vulnerabilities")
        print(f"   Exit code would be: 1")
    else:
        print(f"   [PASS] Build would pass")
        print(f"   Exit code would be: 0")
    
    print("\n2. Testing different thresholds...")
    
    thresholds = ["critical", "high", "medium", "low"]
    for threshold in thresholds:
        enforcer = PipelineEnforcer(threshold)
        should_fail = enforcer.check_vulnerabilities(sample_vulnerabilities)
        failing = enforcer.get_failing_vulnerabilities(sample_vulnerabilities)
        
        status = "FAIL" if should_fail else "PASS"
        print(f"   --fail-on {threshold:8s}: {status} ({len(failing)} vulnerabilities)")
    
    print("\n[OK] Integration test completed!")


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("RICO CI/CD INTEGRATION TEST SUITE")
    print("=" * 70)
    
    try:
        # Run tests
        test_pipeline_enforcer()
        test_sarif_exporter()
        test_integration()
        
        # Summary
        print("\n" + "=" * 70)
        print("ALL TESTS PASSED! ✓")
        print("=" * 70)
        print("\nCI/CD integration is working correctly:")
        print("  ✓ Pipeline enforcer blocks builds correctly")
        print("  ✓ SARIF exporter generates valid reports")
        print("  ✓ GitHub integration ready")
        print("\nGenerated test files:")
        print("  - test_reports/test_rico.sarif")
        print("  - test_reports/integration_test.sarif")
        print("\nNext steps:")
        print("  1. Review .github/workflows/rico-security-scan.yml")
        print("  2. Test with: rico scan --spec demo-api/openapi.yaml --url http://localhost:8000 --fail-on high")
        print("  3. Generate SARIF: rico scan --spec demo-api/openapi.yaml --url http://localhost:8000 --report-sarif rico.sarif")
        
        return 0
        
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {str(e)}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
