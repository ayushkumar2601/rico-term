"""Utility functions for the API."""

import uuid
from datetime import datetime
from typing import Dict, Any


def add_response_metadata(data: Dict[str, Any], request_id: str = None) -> Dict[str, Any]:
    """Add standard metadata to response."""
    if request_id is None:
        request_id = str(uuid.uuid4())
    
    return {
        **data,
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request_id
    }

def generate_request_id() -> str:
    """Generate unique request ID."""
    return str(uuid.uuid4())

def is_internal_ip(url: str) -> bool:
    """Check if URL points to internal/private IP."""
    internal_patterns = [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.168.",
        "169.254.169.254",  # AWS metadata
        "metadata.google.internal",  # GCP metadata
    ]
    
    url_lower = url.lower()
    for pattern in internal_patterns:
        if pattern in url_lower:
            return True
    
    return False

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal (SECURE version).
    """
    # Remove path traversal attempts
    filename = filename.replace("..", "")
    filename = filename.replace("/", "")
    filename = filename.replace("\\", "")
    
    # Remove leading dots
    while filename.startswith("."):
        filename = filename[1:]
    
    return filename

def validate_json_structure(data: Dict[str, Any], required_fields: list) -> bool:
    """Validate JSON structure has required fields."""
    for field in required_fields:
        if field not in data:
            return False
    return True
