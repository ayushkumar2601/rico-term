"""
Pipeline Enforcer - CI/CD Build Blocking Logic

Implements severity-based build failure for DevSecOps pipelines.

⚠️ WARNING: This module contains sys.exit() calls and is designed for CLI usage only.
DO NOT import or use this module in web server contexts (FastAPI, Flask, etc.)
as it will terminate the entire process.

This module is safe for:
- CLI applications (rico scan --fail-on critical)
- CI/CD pipeline scripts
- Standalone Python scripts

This module is NOT safe for:
- Web servers (FastAPI, Flask, Django)
- Background workers
- Long-running services
"""

import sys
from typing import List, Dict, Any
from enum import IntEnum


class SeverityLevel(IntEnum):
    """Severity levels with numeric ranking for comparison."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class PipelineEnforcer:
    """Enforces security policies in CI/CD pipelines."""
    
    # Severity string to enum mapping
    SEVERITY_MAP = {
        "info": SeverityLevel.INFO,
        "low": SeverityLevel.LOW,
        "medium": SeverityLevel.MEDIUM,
        "high": SeverityLevel.HIGH,
        "critical": SeverityLevel.CRITICAL,
    }
    
    def __init__(self, threshold: str):
        """
        Initialize pipeline enforcer.
        
        Args:
            threshold: Severity threshold (critical/high/medium/low)
        
        Raises:
            ValueError: If threshold is invalid
        """
        threshold_lower = threshold.lower()
        if threshold_lower not in self.SEVERITY_MAP:
            raise ValueError(
                f"Invalid threshold: {threshold}. "
                f"Must be one of: {', '.join(self.SEVERITY_MAP.keys())}"
            )
        
        self.threshold = self.SEVERITY_MAP[threshold_lower]
        self.threshold_name = threshold_lower.upper()
    
    def check_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> bool:
        """
        Check if any vulnerabilities meet or exceed threshold.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries with 'severity' field
            
        Returns:
            True if build should fail, False otherwise
        """
        for vuln in vulnerabilities:
            severity_str = vuln.get("severity", "").lower()
            
            # Map severity string to enum
            severity_level = self.SEVERITY_MAP.get(severity_str, SeverityLevel.INFO)
            
            # Check if severity meets or exceeds threshold
            if severity_level >= self.threshold:
                return True
        
        return False
    
    def get_failing_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Get list of vulnerabilities that meet or exceed threshold.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of vulnerabilities that triggered failure
        """
        failing = []
        
        for vuln in vulnerabilities:
            severity_str = vuln.get("severity", "").lower()
            severity_level = self.SEVERITY_MAP.get(severity_str, SeverityLevel.INFO)
            
            if severity_level >= self.threshold:
                failing.append(vuln)
        
        return failing
    
    def enforce(self, vulnerabilities: List[Dict[str, Any]], console=None) -> None:
        """
        Enforce pipeline policy and exit if threshold exceeded.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            console: Optional Rich console for formatted output
        """
        should_fail = self.check_vulnerabilities(vulnerabilities)
        
        if should_fail:
            failing_vulns = self.get_failing_vulnerabilities(vulnerabilities)
            
            # Print failure message
            if console:
                console.print(
                    f"\n[bold red]❌ Build failed: {len(failing_vulns)} {self.threshold_name} "
                    f"or higher severity vulnerabilities detected![/bold red]"
                )
                console.print(f"\n[red]Failing vulnerabilities:[/red]")
                for vuln in failing_vulns:
                    severity = vuln.get("severity", "Unknown").upper()
                    vuln_type = vuln.get("type", "Unknown")
                    endpoint = vuln.get("endpoint", "Unknown")
                    console.print(f"  • [{severity}] {vuln_type} in {endpoint}")
            else:
                print(
                    f"\n❌ Build failed: {len(failing_vulns)} {self.threshold_name} "
                    f"or higher severity vulnerabilities detected!"
                )
                print("\nFailing vulnerabilities:")
                for vuln in failing_vulns:
                    severity = vuln.get("severity", "Unknown").upper()
                    vuln_type = vuln.get("type", "Unknown")
                    endpoint = vuln.get("endpoint", "Unknown")
                    print(f"  • [{severity}] {vuln_type} in {endpoint}")
            
            # Exit with failure code
            sys.exit(1)
        else:
            # Build passes
            if console:
                console.print(
                    f"\n[green]✓ Build passed: No {self.threshold_name} or higher "
                    f"severity vulnerabilities detected.[/green]"
                )
            else:
                print(
                    f"\n✓ Build passed: No {self.threshold_name} or higher "
                    f"severity vulnerabilities detected."
                )


def should_fail_build(vulnerabilities: List[Dict[str, Any]], threshold: str) -> bool:
    """
    Convenience function to check if build should fail.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        threshold: Severity threshold (critical/high/medium/low)
        
    Returns:
        True if build should fail, False otherwise
    """
    try:
        enforcer = PipelineEnforcer(threshold)
        return enforcer.check_vulnerabilities(vulnerabilities)
    except ValueError:
        # Invalid threshold, don't fail build
        return False
