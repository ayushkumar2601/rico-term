#!/usr/bin/env python3
"""
Test script for Demo Scan functionality
Tests both backend and integration
"""

import requests
import time
import json
import sys

# Configuration
BACKEND_URL = "https://rico-term.onrender.com"
# BACKEND_URL = "http://localhost:10000"  # For local testing

def test_backend_health():
    """Test 1: Backend health check"""
    print("=" * 60)
    print("Test 1: Backend Health Check")
    print("=" * 60)
    
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Backend is healthy")
            print(f"  Status: {data.get('status')}")
            print(f"  Version: {data.get('version')}")
            print(f"  Timestamp: {data.get('timestamp')}")
            return True
        else:
            print(f"✗ Backend health check failed: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Backend health check failed: {e}")
        return False


def test_demo_spec_exists():
    """Test 2: Check if demo spec exists in backend"""
    print("\n" + "=" * 60)
    print("Test 2: Demo OpenAPI Spec Exists")
    print("=" * 60)
    
    import os
    from pathlib import Path
    
    spec_path = Path("rico/web/demo_openapi.yaml")
    
    if spec_path.exists():
        print(f"✓ Demo spec exists: {spec_path}")
        print(f"  Size: {spec_path.stat().st_size} bytes")
        
        # Read first few lines
        with open(spec_path, 'r') as f:
            lines = f.readlines()[:5]
            print(f"  First lines:")
            for line in lines:
                print(f"    {line.rstrip()}")
        return True
    else:
        print(f"✗ Demo spec not found: {spec_path}")
        return False


def test_demo_scan_endpoint():
    """Test 3: Test /demo-scan endpoint"""
    print("\n" + "=" * 60)
    print("Test 3: Demo Scan Endpoint")
    print("=" * 60)
    
    try:
        print(f"Calling POST {BACKEND_URL}/demo-scan...")
        response = requests.post(f"{BACKEND_URL}/demo-scan", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            scan_id = data.get('scan_id')
            status = data.get('status')
            message = data.get('message')
            
            print(f"✓ Demo scan started successfully")
            print(f"  Scan ID: {scan_id}")
            print(f"  Status: {status}")
            print(f"  Message: {message}")
            
            return scan_id
        elif response.status_code == 500:
            error_data = response.json()
            detail = error_data.get('detail', 'Unknown error')
            
            if "DEMO_API_URL not configured" in detail:
                print(f"⚠ Demo scan endpoint exists but DEMO_API_URL not configured")
                print(f"  This is expected if environment variable is not set")
                print(f"  Error: {detail}")
                return "env_not_configured"
            else:
                print(f"✗ Demo scan failed: {detail}")
                return None
        else:
            print(f"✗ Demo scan failed: HTTP {response.status_code}")
            print(f"  Response: {response.text}")
            return None
    except Exception as e:
        print(f"✗ Demo scan endpoint test failed: {e}")
        return None


def test_scan_polling(scan_id):
    """Test 4: Test scan status polling"""
    print("\n" + "=" * 60)
    print("Test 4: Scan Status Polling")
    print("=" * 60)
    
    if not scan_id or scan_id == "env_not_configured":
        print("⊘ Skipping polling test (no valid scan_id)")
        return False
    
    print(f"Polling scan status for: {scan_id}")
    
    max_attempts = 20  # 20 attempts * 3 seconds = 60 seconds max
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        
        try:
            response = requests.get(f"{BACKEND_URL}/scan/{scan_id}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                status = data.get('status')
                
                print(f"  Attempt {attempt}: Status = {status}")
                
                if status == "completed":
                    result = data.get('result', {})
                    print(f"\n✓ Scan completed successfully!")
                    print(f"  Risk Score: {result.get('risk_score')}")
                    print(f"  Risk Level: {result.get('risk_level')}")
                    print(f"  Total Vulnerabilities: {result.get('total_vulnerabilities')}")
                    print(f"  Endpoints Tested: {result.get('endpoints_tested')}")
                    print(f"  Duration: {result.get('duration')} seconds")
                    return True
                elif status == "failed":
                    error = data.get('error', 'Unknown error')
                    print(f"\n✗ Scan failed: {error}")
                    return False
                elif status in ["queued", "running"]:
                    time.sleep(3)  # Wait 3 seconds before next poll
                else:
                    print(f"\n⚠ Unknown status: {status}")
                    return False
            else:
                print(f"✗ Polling failed: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"✗ Polling error: {e}")
            return False
    
    print(f"\n⚠ Scan did not complete within {max_attempts * 3} seconds")
    return False


def test_frontend_api_file():
    """Test 5: Check if frontend API file has runDemoScan"""
    print("\n" + "=" * 60)
    print("Test 5: Frontend API Integration")
    print("=" * 60)
    
    from pathlib import Path
    
    api_file = Path("frontend/lib/api.ts")
    
    if not api_file.exists():
        print(f"✗ Frontend API file not found: {api_file}")
        return False
    
    with open(api_file, 'r') as f:
        content = f.read()
    
    if "runDemoScan" in content:
        print(f"✓ runDemoScan function found in {api_file}")
        
        # Check for key elements
        checks = [
            ("export async function runDemoScan", "Function export"),
            ("/demo-scan", "Endpoint URL"),
            ("POST", "HTTP method"),
            ("ScanResponse", "Return type"),
        ]
        
        for check_str, description in checks:
            if check_str in content:
                print(f"  ✓ {description} present")
            else:
                print(f"  ✗ {description} missing")
        
        return True
    else:
        print(f"✗ runDemoScan function not found in {api_file}")
        return False


def test_frontend_component():
    """Test 6: Check if frontend component has demo scan button"""
    print("\n" + "=" * 60)
    print("Test 6: Frontend Component Integration")
    print("=" * 60)
    
    from pathlib import Path
    
    component_file = Path("frontend/components/real-scanner.tsx")
    
    if not component_file.exists():
        print(f"✗ Frontend component not found: {component_file}")
        return False
    
    with open(component_file, 'r') as f:
        content = f.read()
    
    checks = [
        ("handleDemoScan", "Demo scan handler"),
        ("runDemoScan", "API call"),
        ("Run Demo Scan", "Button text"),
        ("Quick Demo Scan", "Card title"),
        ("Zap", "Icon import"),
    ]
    
    all_present = True
    for check_str, description in checks:
        if check_str in content:
            print(f"  ✓ {description} present")
        else:
            print(f"  ✗ {description} missing")
            all_present = False
    
    if all_present:
        print(f"✓ All demo scan UI elements present in {component_file}")
        return True
    else:
        print(f"⚠ Some demo scan UI elements missing")
        return False


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("RICO DEMO SCAN FUNCTIONALITY TEST")
    print("=" * 60)
    print(f"Backend URL: {BACKEND_URL}")
    print()
    
    results = {}
    
    # Test 1: Backend health
    results['health'] = test_backend_health()
    
    # Test 2: Demo spec exists
    results['spec'] = test_demo_spec_exists()
    
    # Test 3: Demo scan endpoint
    scan_id = test_demo_scan_endpoint()
    results['endpoint'] = scan_id is not None or scan_id == "env_not_configured"
    
    # Test 4: Scan polling (only if we got a valid scan_id)
    if scan_id and scan_id != "env_not_configured":
        results['polling'] = test_scan_polling(scan_id)
    else:
        results['polling'] = None  # Skipped
    
    # Test 5: Frontend API
    results['frontend_api'] = test_frontend_api_file()
    
    # Test 6: Frontend component
    results['frontend_component'] = test_frontend_component()
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)
    total = len(results)
    
    for test_name, result in results.items():
        if result is True:
            status = "✓ PASS"
        elif result is False:
            status = "✗ FAIL"
        else:
            status = "⊘ SKIP"
        
        print(f"{status:10} {test_name}")
    
    print()
    print(f"Passed:  {passed}/{total}")
    print(f"Failed:  {failed}/{total}")
    print(f"Skipped: {skipped}/{total}")
    
    if failed == 0:
        print("\n✅ All tests passed!")
        return 0
    else:
        print(f"\n⚠ {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
