"""Utility functions for security attack testing."""

import re
import json
from typing import Dict, Any, Optional, Tuple
from rich.console import Console
from rich.table import Table

console = Console()


def normalize_response(response_text: str) -> Dict[str, Any]:
    """
    Normalize response for comparison by removing dynamic fields.
    
    Args:
        response_text: Raw response text
        
    Returns:
        Normalized response dict with metadata
    """
    result = {
        "normalized": None,
        "is_json": False,
        "size": len(response_text),
        "text": response_text
    }
    
    try:
        data = json.loads(response_text)
        result["is_json"] = True
        
        # Remove dynamic fields recursively
        normalized = _remove_dynamic_fields(data)
        
        # Sort keys recursively for consistent comparison
        result["normalized"] = _sort_json_keys(normalized)
        
    except (json.JSONDecodeError, TypeError):
        # Not JSON, use text as-is
        result["normalized"] = response_text
        result["is_json"] = False
    
    return result


def _remove_dynamic_fields(obj: Any, depth: int = 0) -> Any:
    """
    Recursively remove dynamic fields from JSON object.
    
    Dynamic fields include:
    - timestamp, created_at, updated_at, date, time
    - request_id, id (when UUID format), uuid, guid
    - token, session_id
    - Any field with ISO 8601 date format
    - Any field with UUID format
    
    Args:
        obj: JSON object (dict, list, or primitive)
        depth: Current recursion depth
        
    Returns:
        Object with dynamic fields removed
    """
    if depth > 10:  # Prevent infinite recursion
        return obj
    
    # Dynamic field patterns
    dynamic_fields = [
        'timestamp', 'created_at', 'updated_at', 'modified_at',
        'date', 'time', 'datetime', 'request_id', 'session_id',
        'token', 'access_token', 'refresh_token', 'csrf_token',
        'nonce', 'state', 'uuid', 'guid', 'etag', 'x-request-id'
    ]
    
    # UUID pattern
    uuid_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    
    # ISO 8601 date pattern
    iso_date_pattern = re.compile(
        r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'
    )
    
    if isinstance(obj, dict):
        normalized = {}
        for key, value in obj.items():
            key_lower = str(key).lower()
            
            # Skip dynamic fields
            if any(field in key_lower for field in dynamic_fields):
                continue
            
            # Check if value is UUID or ISO date
            if isinstance(value, str):
                if uuid_pattern.match(value) or iso_date_pattern.match(value):
                    continue
            
            # Recurse into nested objects
            normalized[key] = _remove_dynamic_fields(value, depth + 1)
        
        return normalized
    
    elif isinstance(obj, list):
        return [_remove_dynamic_fields(item, depth + 1) for item in obj]
    
    else:
        return obj


def _sort_json_keys(obj: Any) -> Any:
    """
    Recursively sort JSON keys for consistent comparison.
    
    Args:
        obj: JSON object
        
    Returns:
        Object with sorted keys
    """
    if isinstance(obj, dict):
        return {k: _sort_json_keys(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [_sort_json_keys(item) for item in obj]
    else:
        return obj


def compare_json_deep(obj1: Any, obj2: Any) -> Tuple[int, float, Dict[str, Any]]:
    """
    Deep comparison of JSON objects.
    
    Args:
        obj1: First JSON object
        obj2: Second JSON object
        
    Returns:
        Tuple of (structural_changes, value_diff_percentage, details)
    """
    details = {
        "structural_changes": 0,
        "value_changes": 0,
        "total_fields": 0,
        "missing_keys": [],
        "extra_keys": [],
        "different_values": []
    }
    
    def compare_recursive(o1: Any, o2: Any, path: str = ""):
        """Recursively compare objects."""
        if type(o1) != type(o2):
            details["structural_changes"] += 1
            details["different_values"].append(f"{path}: type mismatch")
            return
        
        if isinstance(o1, dict):
            keys1 = set(o1.keys())
            keys2 = set(o2.keys())
            
            # Track structural changes
            missing = keys1 - keys2
            extra = keys2 - keys1
            
            if missing:
                details["structural_changes"] += len(missing)
                details["missing_keys"].extend([f"{path}.{k}" for k in missing])
            
            if extra:
                details["structural_changes"] += len(extra)
                details["extra_keys"].extend([f"{path}.{k}" for k in extra])
            
            # Compare common keys
            for key in keys1 & keys2:
                new_path = f"{path}.{key}" if path else str(key)
                details["total_fields"] += 1
                compare_recursive(o1[key], o2[key], new_path)
        
        elif isinstance(o1, list):
            if len(o1) != len(o2):
                details["structural_changes"] += 1
                details["different_values"].append(
                    f"{path}: list length {len(o1)} vs {len(o2)}"
                )
            else:
                for i, (item1, item2) in enumerate(zip(o1, o2)):
                    compare_recursive(item1, item2, f"{path}[{i}]")
        
        else:
            # Primitive value comparison
            details["total_fields"] += 1
            if o1 != o2:
                details["value_changes"] += 1
                details["different_values"].append(f"{path}: {o1} vs {o2}")
    
    compare_recursive(obj1, obj2)
    
    # Calculate percentage difference
    if details["total_fields"] > 0:
        value_diff_pct = (details["value_changes"] / details["total_fields"]) * 100
    else:
        value_diff_pct = 0.0
    
    return details["structural_changes"], value_diff_pct, details


def build_url(base_url: str, path: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Build a complete URL from base URL and path.

    Args:
        base_url: Base URL (e.g., http://localhost:3000)
        path: Endpoint path (e.g., /users/{id})
        params: Optional query parameters

    Returns:
        Complete URL
    """
    # Remove trailing slash from base_url
    base_url = base_url.rstrip("/")

    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path

    url = base_url + path

    # Add query parameters if provided
    if params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        url += f"?{param_str}"

    return url


def compare_responses(response1: str, response2: str, threshold: float = 0.1) -> bool:
    """
    Compare two responses to detect significant differences.

    Args:
        response1: First response text
        response2: Second response text
        threshold: Difference threshold (0.0 to 1.0)

    Returns:
        True if responses are significantly different
    """
    if not response1 or not response2:
        return True

    # Simple length-based comparison
    len1, len2 = len(response1), len(response2)
    if len1 == 0 or len2 == 0:
        return True

    # Calculate difference ratio
    max_len = max(len1, len2)
    diff_ratio = abs(len1 - len2) / max_len

    return diff_ratio > threshold


def sql_error_regex() -> list[str]:
    """
    Return list of SQL error patterns to detect.

    Returns:
        List of regex patterns for SQL errors
    """
    return [
        r"sql syntax",
        r"mysql",
        r"postgresql",
        r"sqlite",
        r"ora-\d{5}",
        r"syntax error",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"sql command not properly ended",
        r"database error",
        r"warning: mysql",
        r"valid mysql result",
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"sqlite_query",
        r"sqlite_fetch",
        r"microsoft sql native client error",
        r"odbc sql server driver",
        r"sqlstate",
    ]


def detect_sql_error(response_text: str) -> bool:
    """
    Detect SQL errors in response text.

    Args:
        response_text: Response text to check

    Returns:
        True if SQL error detected
    """
    if not response_text:
        return False

    response_lower = response_text.lower()

    for pattern in sql_error_regex():
        if re.search(pattern, response_lower, re.IGNORECASE):
            return True

    return False


def print_attack_result(result: Dict[str, Any]):
    """
    Print attack test result in a formatted way.

    Args:
        result: Attack result dictionary
    """
    vulnerable = result.get("vulnerable", False)
    attack_type = result.get("attack_type", "Unknown")
    endpoint = result.get("endpoint", "Unknown")
    details = result.get("details", "No details")

    status_color = "red" if vulnerable else "green"
    status_text = "VULNERABLE" if vulnerable else "SAFE"

    console.print(f"\n[bold cyan]{attack_type} Test[/bold cyan]")
    console.print(f"Endpoint: [yellow]{endpoint}[/yellow]")
    console.print(f"Status: [{status_color}]{status_text}[/{status_color}]")
    console.print(f"Details: {details}")


def create_results_table(results: list[Dict[str, Any]], show_reasoning: bool = False) -> Table:
    """
    Create a Rich table from attack results.

    Args:
        results: List of attack result dictionaries
        show_reasoning: Whether to show AI reasoning column

    Returns:
        Rich Table object
    """
    table = Table(
        title="[bold cyan]Security Attack Test Results[/bold cyan]", show_lines=True
    )
    table.add_column("Endpoint", style="cyan", no_wrap=False)
    table.add_column("Attack Type", style="magenta")
    table.add_column("Status", style="bold", justify="center")
    table.add_column("Confidence", style="bold", justify="center")
    
    if show_reasoning:
        table.add_column("AI Reasoning", style="blue", no_wrap=False)
    
    table.add_column("Details", style="yellow")

    for result in results:
        endpoint = result.get("endpoint", "Unknown")
        attack_type = result.get("attack_type", "Unknown")
        vulnerable = result.get("vulnerable", False)
        confidence = result.get("confidence", 0)
        details = result.get("details", "No details")
        reasoning = result.get("reasoning", "")

        # Truncate details if too long
        if len(details) > 80:
            details = details[:77] + "..."
        
        # Truncate reasoning if too long
        if reasoning and len(reasoning) > 60:
            reasoning = reasoning[:57] + "..."

        # Determine status color based on confidence
        if vulnerable and confidence > 80:
            status_color = "red"
            status_text = "⚠ VULNERABLE"
        elif vulnerable and confidence > 60:
            status_color = "yellow"
            status_text = "⚠ SUSPICIOUS"
        elif confidence > 40:
            status_color = "yellow"
            status_text = "⚠ SUSPICIOUS"
        else:
            status_color = "green"
            status_text = "✓ SAFE"

        # Confidence color
        if confidence > 80:
            conf_color = "red"
        elif confidence > 60:
            conf_color = "yellow"
        elif confidence > 40:
            conf_color = "yellow"
        else:
            conf_color = "green"

        if show_reasoning:
            table.add_row(
                endpoint,
                attack_type,
                f"[{status_color}]{status_text}[/{status_color}]",
                f"[{conf_color}]{confidence}%[/{conf_color}]",
                reasoning if reasoning else "-",
                details,
            )
        else:
            table.add_row(
                endpoint,
                attack_type,
                f"[{status_color}]{status_text}[/{status_color}]",
                f"[{conf_color}]{confidence}%[/{conf_color}]",
                details,
            )

    return table
