"""IDOR (Insecure Direct Object Reference) attack testing."""
import re
from typing import Dict, Any
from rico.executor.http_runner import run_request
from rico.attacks.detector import detect_vulnerability
import httpx


async def test_idor(
    endpoint: str, base_url: str, method: str = "GET"
) -> Dict[str, Any]:
    """
    Test for IDOR vulnerability by accessing different resource IDs.

    IDOR occurs when an application exposes a reference to an internal object
    (like a database key) without proper authorization checks.

    Args:
        endpoint: Endpoint path (e.g., /users/{id})
        base_url: Base URL of the API
        method: HTTP method to use

    Returns:
        Dictionary with test results
    """
    result = {
        "attack_type": "IDOR",
        "endpoint": endpoint,
        "vulnerable": False,
        "confidence": 0,
        "details": "No IDOR vulnerability detected",
    }

    # Check if endpoint has path parameters
    path_params = re.findall(r"\{(\w+)\}", endpoint)

    if not path_params:
        result["details"] = "No path parameters found - IDOR test not applicable"
        return result

    # Test with different ID values
    test_ids = ["1", "2", "999", "100"]
    responses = []

    try:
        for test_id in test_ids[:3]:  # Limit to 3 requests
            # Replace path parameter with test ID
            test_endpoint = endpoint
            for param in path_params:
                test_endpoint = test_endpoint.replace(f"{{{param}}}", test_id)

            # Build full URL
            url = base_url.rstrip("/") + test_endpoint

            try:
                # Make request without authentication
                response = await run_request(method=method, url=url, timeout=5.0)

                responses.append(
                    {
                        "id": test_id,
                        "status": response.status_code,
                        "body": response.response_text,
                        "length": len(response.response_text),
                    }
                )

            except (httpx.TimeoutException, httpx.ConnectError):
                # Skip this ID if request fails
                continue
            except Exception:
                continue

        # Analyze responses using detector
        if len(responses) >= 2:
            # Check if we got successful responses with different data
            successful_responses = [r for r in responses if 200 <= r["status"] < 300]

            if len(successful_responses) >= 2:
                # Use detector to analyze first two responses
                baseline = successful_responses[0]
                test = successful_responses[1]

                detection = detect_vulnerability(
                    attack_type="IDOR",
                    endpoint=endpoint,
                    baseline_response={
                        "status": baseline["status"],
                        "text": baseline["body"],
                        "time": 0.0,
                    },
                    test_response={
                        "status": test["status"],
                        "text": test["body"],
                        "time": 0.0,
                    },
                )

                result["vulnerable"] = detection.vulnerable
                result["confidence"] = detection.confidence
                result["details"] = detection.reason

                if not detection.vulnerable and detection.confidence < 30:
                    result["details"] = (
                        f"Endpoint accessible but responses similar (Confidence: {detection.confidence}%). "
                        f"Manual verification recommended."
                    )
            else:
                result["details"] = (
                    f"Only {len(successful_responses)} successful response(s). Insufficient data."
                )
                result["confidence"] = 0
        else:
            result["details"] = "Insufficient responses to determine IDOR vulnerability"
            result["confidence"] = 0

    except Exception as e:
        result["details"] = f"Error during IDOR test: {str(e)}"

    return result
