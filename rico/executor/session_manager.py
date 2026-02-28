"""Session management for authenticated API testing."""

from typing import Dict, Any, Optional
import json
from pathlib import Path


SESSION_FILE = ".rico_session.json"


def save_session(session_data: Dict[str, Any], file_path: str = SESSION_FILE) -> None:
    """
    Save session data to file.
    
    Args:
        session_data: Session data from playwright_runner
        file_path: Path to save session file
    """
    try:
        with open(file_path, 'w') as f:
            json.dump(session_data, f, indent=2)
    except Exception as e:
        raise ValueError(f"Failed to save session: {str(e)}")


def load_session(file_path: str = SESSION_FILE) -> Optional[Dict[str, Any]]:
    """
    Load session data from file.
    
    Args:
        file_path: Path to session file
        
    Returns:
        Session data dict or None if file doesn't exist
    """
    try:
        if not Path(file_path).exists():
            return None
        
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def attach_session_to_headers(
    session_data: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """
    Extract session tokens and attach to HTTP headers.
    
    Args:
        session_data: Session data from playwright_runner
        headers: Existing headers dict (optional)
        
    Returns:
        Headers dict with session tokens attached
    """
    if headers is None:
        headers = {}
    
    # Extract cookies and convert to Cookie header
    if session_data.get("cookies"):
        cookie_str = "; ".join([
            f"{cookie['name']}={cookie['value']}"
            for cookie in session_data["cookies"]
        ])
        headers["Cookie"] = cookie_str
    
    # Check localStorage for common token keys
    local_storage = session_data.get("local_storage", {})
    for key in ["token", "authToken", "auth_token", "accessToken", "access_token"]:
        if key in local_storage:
            headers["Authorization"] = f"Bearer {local_storage[key]}"
            break
    
    # Check sessionStorage for tokens
    session_storage = session_data.get("session_storage", {})
    for key in ["token", "authToken", "auth_token", "accessToken", "access_token"]:
        if key in session_storage:
            if "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {session_storage[key]}"
            break
    
    return headers


def get_csrf_token(session_data: Dict[str, Any]) -> Optional[str]:
    """
    Extract CSRF token from session data.
    
    Args:
        session_data: Session data from playwright_runner
        
    Returns:
        CSRF token string or None
    """
    # Check cookies for CSRF token
    if session_data.get("cookies"):
        for cookie in session_data["cookies"]:
            if "csrf" in cookie["name"].lower() or "xsrf" in cookie["name"].lower():
                return cookie["value"]
    
    # Check localStorage
    local_storage = session_data.get("local_storage", {})
    for key in ["csrfToken", "csrf_token", "xsrfToken", "xsrf_token"]:
        if key in local_storage:
            return local_storage[key]
    
    # Check sessionStorage
    session_storage = session_data.get("session_storage", {})
    for key in ["csrfToken", "csrf_token", "xsrfToken", "xsrf_token"]:
        if key in session_storage:
            return session_storage[key]
    
    return None
