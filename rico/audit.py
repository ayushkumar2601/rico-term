"""Audit logging for RICO security scans."""

import json
import os
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path


AUDIT_LOG_FILE = "rico_audit.log"


def log_scan(
    user: str,
    target_url: str,
    spec_file: str,
    attacks_run: List[str],
    results_summary: Dict[str, Any],
    duration: float
) -> None:
    """
    Log security scan to audit file.
    
    Args:
        user: Username or system user
        target_url: Target API URL
        spec_file: OpenAPI spec file path
        attacks_run: List of attack types executed
        results_summary: Summary of results (vulnerable, safe, etc.)
        duration: Scan duration in seconds
    """
    audit_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "user": user,
        "target_url": target_url,
        "spec_file": spec_file,
        "attacks_run": attacks_run,
        "results_summary": results_summary,
        "duration_seconds": round(duration, 2),
        "environment": {
            "hostname": os.getenv("HOSTNAME", "unknown"),
            "ci": os.getenv("CI", "false"),
            "github_actor": os.getenv("GITHUB_ACTOR", None),
            "github_repository": os.getenv("GITHUB_REPOSITORY", None),
            "github_ref": os.getenv("GITHUB_REF", None),
        }
    }
    
    # Append to audit log
    try:
        with open(AUDIT_LOG_FILE, 'a') as f:
            f.write(json.dumps(audit_entry) + "\n")
    except Exception as e:
        # Don't fail scan if audit logging fails
        print(f"Warning: Failed to write audit log: {str(e)}")


def get_current_user() -> str:
    """Get current system user."""
    return os.getenv("USER") or os.getenv("USERNAME") or "unknown"


def read_audit_log(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Read recent audit log entries.
    
    Args:
        limit: Maximum number of entries to return
        
    Returns:
        List of audit log entries (most recent first)
    """
    if not Path(AUDIT_LOG_FILE).exists():
        return []
    
    try:
        entries = []
        with open(AUDIT_LOG_FILE, 'r') as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except:
                    continue
        
        # Return most recent first
        return entries[-limit:][::-1]
    except Exception:
        return []
