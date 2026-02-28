"""HTTP request runner for RICO using async httpx."""

import httpx
import time
import asyncio
from typing import Optional, Dict, Any, Tuple
from rico.executor.logger import log_request


# Global rate limiter
_rate_limiter = None
_request_count = 0
_rate_limit_window_start = 0


def init_rate_limiter(max_requests_per_second: int = 5):
    """Initialize global rate limiter."""
    global _rate_limiter
    _rate_limiter = max_requests_per_second


async def apply_rate_limit():
    """Apply rate limiting to prevent DDoS."""
    global _request_count, _rate_limit_window_start
    
    if _rate_limiter is None:
        return
    
    current_time = time.time()
    
    # Reset counter every second
    if current_time - _rate_limit_window_start >= 1.0:
        _request_count = 0
        _rate_limit_window_start = current_time
    
    # Check if we've hit the limit
    if _request_count >= _rate_limiter:
        sleep_time = 1.0 - (current_time - _rate_limit_window_start)
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
        _request_count = 0
        _rate_limit_window_start = time.time()
    
    _request_count += 1


class RequestResult:
    """Container for HTTP request results."""

    def __init__(
        self,
        status_code: int,
        response_text: str,
        response_time: float,
        error: Optional[str] = None,
    ):
        self.status_code = status_code
        self.response_text = response_text
        self.response_time = response_time
        self.error = error


async def run_request(
    method: str,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    token: Optional[str] = None,
    timeout: float = 30.0,
) -> RequestResult:
    """
    Execute an HTTP request using async httpx.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        url: Target URL
        params: Query parameters
        headers: HTTP headers
        token: Authorization token (will be added to headers)
        timeout: Request timeout in seconds

    Returns:
        RequestResult containing status_code, response_text, and response_time

    Raises:
        ValueError: If method or URL is invalid
        httpx.TimeoutException: If request times out
        httpx.ConnectError: If connection fails
    """
    # Apply rate limiting
    await apply_rate_limit()
    
    # Validate method
    method = method.upper()
    valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    if method not in valid_methods:
        raise ValueError(
            f"Invalid HTTP method: {method}. Must be one of {valid_methods}"
        )

    # Validate URL
    if not url or not url.startswith(("http://", "https://")):
        raise ValueError(f"Invalid URL: {url}. Must start with http:// or https://")

    # Prepare headers
    if headers is None:
        headers = {}

    # Add authorization token if provided
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Start timing
    start_time = time.time()

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Make the request
            response = await client.request(
                method=method, url=url, params=params, headers=headers
            )

            # Calculate response time
            response_time = time.time() - start_time

            # Get response text
            try:
                response_text = response.text
            except Exception:
                response_text = "<Unable to decode response>"

            # Log the request
            log_request(method, url, response.status_code, response_time)

            return RequestResult(
                status_code=response.status_code,
                response_text=response_text,
                response_time=response_time,
            )

    except httpx.TimeoutException as e:
        response_time = time.time() - start_time
        error_msg = f"Request timed out after {timeout}s"
        log_request(method, url, 0, response_time)
        raise httpx.TimeoutException(error_msg)

    except httpx.ConnectError as e:
        response_time = time.time() - start_time
        error_msg = f"Connection failed: {str(e)}"
        log_request(method, url, 0, response_time)
        raise httpx.ConnectError(error_msg)

    except httpx.InvalidURL as e:
        raise ValueError(f"Invalid URL format: {str(e)}")

    except Exception as e:
        response_time = time.time() - start_time
        error_msg = f"Unexpected error: {str(e)}"
        log_request(method, url, 0, response_time)
        raise Exception(error_msg)
