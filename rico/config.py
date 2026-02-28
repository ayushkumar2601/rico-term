"""Configuration management for RICO."""

import os
import yaml
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse


def load_config(config_path: str = "rico.yaml") -> Dict[str, Any]:
    """
    Load RICO configuration from YAML file.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Configuration dict
    """
    if not Path(config_path).exists():
        return {}
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def get_allowed_domains(config: Dict[str, Any] = None) -> List[str]:
    """
    Get list of allowed domains from config.
    
    Args:
        config: Configuration dict (optional, will load if not provided)
        
    Returns:
        List of allowed domain strings
    """
    if config is None:
        config = load_config()
    
    return config.get("allowed_domains", [])


def validate_target_url(url: str, config: Dict[str, Any] = None) -> bool:
    """
    Validate that target URL is in allowed domains list.
    
    Args:
        url: Target URL to validate
        config: Configuration dict (optional)
        
    Returns:
        True if URL is allowed, False otherwise
    """
    allowed_domains = get_allowed_domains(config)
    
    # If no allowlist configured, allow all
    if not allowed_domains:
        return True
    
    # Parse target URL
    parsed = urlparse(url)
    target_domain = parsed.netloc
    
    # Check if domain is in allowlist
    for allowed in allowed_domains:
        if target_domain == allowed or target_domain.endswith(f".{allowed}"):
            return True
    
    return False


def get_rate_limit(config: Dict[str, Any] = None) -> int:
    """
    Get rate limit from config.
    
    Args:
        config: Configuration dict (optional)
        
    Returns:
        Max requests per second
    """
    if config is None:
        config = load_config()
    
    return config.get("rate_limit", {}).get("max_requests_per_second", 5)
