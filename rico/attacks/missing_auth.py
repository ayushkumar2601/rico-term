"""Missing Authentication attack testing."""
from typing import Dict, Any, Optional
import json
import re
from rico.executor.http_runner import run_request
from rico.attacks.detector import detect_vulnerability
import httpx


def is_sensitive_endpoint(endpoint: str, response_data: Optional[str] = None) -> bool:
    """
    Determine if an endpoint appears sensitive based on path and response.
    
    Args:
        endpoint: Endpoint path
        response_data: Optional response text to analyze
        
    Returns:
        True if endpoint appears sensitive
    """
    # Check for path parameters (e.g., /users/{id}, /orders/{order_id})
    has_path_params = bool(re.search(r'\{[^}]+\}', endpoint))
    
    # Check for sensitive path patterns
    sensitive_patterns = [
        r'/users?/',
        r'/accounts?/',
        r'/orders?/',
        r'/admin',
        r'/profile',
        r'/settings',
        r'/payment',
        r'/billing',
        r'/transactions?/',
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, endpoint, re.IGNORECASE):
            return True
    
    # If response data provided, check for sensitive fields
    if response_data:
        try:
            data = json.loads(response_data)
            
            # Check for sensitive field names
            sensitive_fields = [
                'email', 'password', 'token', 'balance', 'credit_card',
                'ssn', 'phone', 'address', 'role', 'permissions',
                'api_key', 'secret', 'private'
            ]
            
            def has_sensitive_fields(obj, depth=0):
                """Recursively check for sensitive fields."""
                if depth > 3:  # Limit recursion depth
                    return False
                
                if isinstance(obj, dict):
                    for key in obj.keys():
                        key_lower = str(key).lower()
                        if any(field in key_lower for field in sensitive_fields):
                            return True
                        # Recurse into nested objects
                        if has_sensitive_fields(obj[key], depth + 1):
                            return True
                elif isinstance(obj, list) and obj:
                    # Check first item in list
                    return has_sensitive_fields(obj[0], depth + 1)
                
                return False
            
            if has_sensitive_fields(data):
                return True
        except (json.JSONDecodeError, TypeError):
            pass
    
    # Check if endpoint has path parameters
    if has_path_params:
        return True
    
    return False


def is_public_endpoint(endpoint: str) -> bool:
    """
    Determine if an endpoint is likely public/informational.
    
    Args:
        endpoint: Endpoint path
        
    Returns:
        True if endpoint appears to be public
    """
    public_patterns = [
        r'^/$',  # Root
        r'/health$',
        r'/status$',
        r'/version$',
        r'/ping$',
        r'/docs?$',
        r'/swagger',
        r'/openapi',
        r'/api-docs',
        r'/public/',
        r'/static/',
        r'/assets/',
    ]
    
    for pattern in public_patterns:
        if re.search(pattern, endpoint, re.IGNORECASE):
            return True
    
    return False


async def test_missing_auth(
    endpoint: str,
    base_url: str,
    method: str = "GET",
    token: Optional[str] = None,
    auth_required: bool = False
) -> Dict[str, Any]:
    """
    Test for missing authentication vulnerability.
    
    Enhanced logic:
    - Only flags Missing Auth on sensitive endpoints
    - Considers OpenAPI security requirements
    - Compares responses with/without token
    - Provides structured reasoning
    
    Args:
        endpoint: Endpoint path
        base_url: Base URL of the API
        method: HTTP method to use
        token: Optional authentication token to test with
        auth_required: Whether OpenAPI spec indicates auth is required
        
    Returns:
        Dictionary with test results
    """
    result = {
        "attack_type": "Missing Auth",
        "endpoint": endpoint,
        "vulnerable": False,
        "confidence": 0,
        "details": "Authentication properly enforced"
    }
    
    # Build full URL
    url = base_url.rstrip('/') + endpoint
    
    # Check if endpoint is public
    if is_public_endpoint(endpoint):
        result["confidence"] = 0
        result["details"] = "Public endpoint - authentication not expected"
        return result
    
    try:
        # Test 1: Request WITHOUT authentication
        try:
            response_no_auth = await run_request(
                method=method,
                url=url,
                timeout=5.0
            )
            no_auth_status = response_no_auth.status_code
            no_auth_text = response_no_auth.response_text
            no_auth_time = response_no_auth.response_time
            no_auth_success = 200 <= no_auth_status < 300
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            result["details"] = f"Connection failed: {str(e)}"
            result["confidence"] = 0
            return result
        except Exception as e:
            result["details"] = f"Error testing without auth: {str(e)}"
            result["confidence"] = 0
            return result
        
        # If request fails with auth error, authentication is properly enforced
        if no_auth_status in [401, 403]:
            result["vulnerable"] = False
            result["confidence"] = 5
            result["details"] = f"Authentication properly enforced (Status: {no_auth_status})"
            return result
        
        # Test 2: Request WITH authentication (if token provided)
        if token:
            try:
                response_with_auth = await run_request(
                    method=method,
                    url=url,
                    token=token,
                    timeout=5.0
                )
                with_auth_status = response_with_auth.status_code
                with_auth_text = response_with_auth.response_text
                with_auth_time = response_with_auth.response_time
                with_auth_success = 200 <= with_auth_status < 300
            except Exception:
                with_auth_success = False
                with_auth_status = 0
                with_auth_text = ""
                with_auth_time = 0.0
        else:
            # No token provided
            with_auth_success = None
            with_auth_status = None
            with_auth_text = ""
            with_auth_time = 0.0
        
        # Analysis based on OpenAPI security requirements and response
        if with_auth_success is not None:
            # We have both responses to compare
            detection = detect_vulnerability(
                attack_type="Missing Auth",
                endpoint=endpoint,
                baseline_response={
                    "status": no_auth_status,
                    "text": no_auth_text,
                    "time": no_auth_time
                },
                test_response={
                    "status": with_auth_status,
                    "text": with_auth_text,
                    "time": with_auth_time
                },
                additional_data={
                    "auth_required": auth_required,
                    "has_token": True
                }
            )
            
            result["vulnerable"] = detection.vulnerable
            result["confidence"] = detection.confidence
            result["details"] = detection.reason
        else:
            # No token to compare - analyze based on response alone
            if no_auth_success:
                # Check if endpoint appears sensitive
                is_sensitive = is_sensitive_endpoint(endpoint, no_auth_text)
                
                if auth_required:
                    # OpenAPI says auth required, but endpoint accessible
                    result["vulnerable"] = True
                    result["confidence"] = 85
                    result["details"] = (
                        f"Protected endpoint accessible without authentication "
                        f"(Status: {no_auth_status}). OpenAPI spec requires authentication."
                    )
                elif is_sensitive:
                    # Endpoint appears sensitive based on path/response
                    result["vulnerable"] = True
                    result["confidence"] = 70
                    result["details"] = (
                        f"Sensitive endpoint accessible without authentication "
                        f"(Status: {no_auth_status}). Contains sensitive data or path parameters."
                    )
                else:
                    # Endpoint accessible but doesn't appear sensitive
                    result["vulnerable"] = False
                    result["confidence"] = 20
                    result["details"] = (
                        f"Endpoint accessible without authentication (Status: {no_auth_status}). "
                        f"Does not appear to contain sensitive data. Provide --token to verify."
                    )
            else:
                # Request failed
                result["confidence"] = 10
                result["details"] = (
                    f"Request failed with status {no_auth_status}. "
                    f"May indicate proper auth or other issue."
                )
    
    except Exception as e:
        result["details"] = f"Error during missing auth test: {str(e)}"
        result["confidence"] = 0
    
    return result
