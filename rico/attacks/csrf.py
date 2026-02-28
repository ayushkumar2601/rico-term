"""CSRF (Cross-Site Request Forgery) vulnerability testing."""

from typing import Dict, Any
from rico.executor.http_runner import run_request
from rico.attacks.detector import detect_vulnerability


async def test_csrf(
    endpoint: str,
    base_url: str,
    method: str = "POST",
    session_headers: Dict[str, str] = None,
    csrf_token: str = None
) -> Dict[str, Any]:
    """
    Test for CSRF vulnerabilities.
    
    Logic:
    1. Make request WITH session but WITHOUT CSRF token
    2. Make request WITH session and FAKE CSRF token
    3. If both succeed → possible CSRF vulnerability
    
    Args:
        endpoint: API endpoint path
        base_url: Base URL of API
        method: HTTP method (POST, PUT, DELETE)
        session_headers: Headers with session cookies/tokens
        csrf_token: Valid CSRF token (if available)
        
    Returns:
        Dict with vulnerability details
    """
    # Only test state-changing methods
    if method.upper() not in ["POST", "PUT", "DELETE", "PATCH"]:
        return {
            "vulnerable": False,
            "confidence": 0,
            "attack_type": "CSRF",
            "endpoint": endpoint,
            "details": f"{method} method not vulnerable to CSRF (read-only operation)"
        }
    
    try:
        # Build full URL
        url = base_url.rstrip("/") + endpoint
        
        # Test 1: Request without CSRF token
        headers_no_csrf = session_headers.copy() if session_headers else {}
        
        try:
            response_no_csrf = await run_request(
                method=method,
                url=url,
                headers=headers_no_csrf,
                timeout=5.0
            )
            no_csrf_status = response_no_csrf.status_code
            no_csrf_success = 200 <= no_csrf_status < 300
        except Exception:
            no_csrf_status = 0
            no_csrf_success = False
        
        # Test 2: Request with fake CSRF token
        headers_fake_csrf = session_headers.copy() if session_headers else {}
        headers_fake_csrf["X-CSRF-Token"] = "fake_token_12345"
        headers_fake_csrf["X-XSRF-Token"] = "fake_token_12345"
        
        try:
            response_fake_csrf = await run_request(
                method=method,
                url=url,
                headers=headers_fake_csrf,
                timeout=5.0
            )
            fake_csrf_status = response_fake_csrf.status_code
            fake_csrf_success = 200 <= fake_csrf_status < 300
        except Exception:
            fake_csrf_status = 0
            fake_csrf_success = False
        
        # Analyze results
        if no_csrf_success or fake_csrf_success:
            # Vulnerability detected
            confidence = 0
            details = []
            
            if no_csrf_success:
                confidence += 50
                details.append(f"Request without CSRF token succeeded (status {no_csrf_status})")
            
            if fake_csrf_success:
                confidence += 40
                details.append(f"Request with fake CSRF token succeeded (status {fake_csrf_status})")
            
            # Only flag if confidence > 60%
            if confidence > 60:
                return {
                    "vulnerable": True,
                    "confidence": confidence,
                    "attack_type": "CSRF",
                    "endpoint": endpoint,
                    "details": "; ".join(details)
                }
        
        # No vulnerability detected
        return {
            "vulnerable": False,
            "confidence": 10,
            "attack_type": "CSRF",
            "endpoint": endpoint,
            "details": f"CSRF protection appears to be in place. Status without token: {no_csrf_status}, with fake token: {fake_csrf_status}"
        }
        
    except Exception as e:
        return {
            "vulnerable": False,
            "confidence": 0,
            "attack_type": "CSRF",
            "endpoint": endpoint,
            "details": f"Error during CSRF test: {str(e)}"
        }
